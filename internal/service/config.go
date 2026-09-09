package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/storage"
)

// EnvConfig reads the service's configuration ENTIRELY from the environment
// (twelve-factor, spec Q4): the same binary runs unchanged on docker-compose,
// Cloud Run, or a box. It returns the pieces main needs to build a Service; the
// Store is opened separately (it owns a connection lifecycle).
type EnvConfig struct {
	HTTPAddr    string
	DatabaseURL string
	Verifier    *auth.Verifier
	URLs        URLBuilder

	// DeliverySigningKey signs granted-mode A/V delivery (spec Q3.B). Empty on a
	// deployment that never serves granted A/V; when empty, a granted A/V request
	// is refused (503) rather than served unsigned.
	DeliverySigningKey string
	// ImgproxyKey / ImgproxySalt sign non-public image URLs (IMGPROXY_KEY/SALT).
	ImgproxyKey  string
	ImgproxySalt string
	// GrantURLTTL / GrantCacheTTL tune granted delivery (spec Q3.B). Zero uses
	// service defaults.
	GrantURLTTL   time.Duration
	GrantCacheTTL time.Duration
}

// LoadEnv builds an EnvConfig from environment variables (see .env.example). It
// fails fast on anything missing that the read path genuinely needs, so a
// misconfigured deploy dies at boot rather than serving wrong (spec §6's bug
// class, applied to config).
func LoadEnv() (EnvConfig, error) {
	cfg := EnvConfig{
		HTTPAddr:    envOr("PLATE_HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		URLs: URLBuilder{
			ImageCDNBase: os.Getenv("IMGPROXY_BASE_URL"),
			R2PublicBase: os.Getenv("R2_PUBLIC_BASE"),
			DownloadBase: envOr("PLATE_DOWNLOAD_BASE", "https://plate.example"),
		},
		DeliverySigningKey: os.Getenv("PLATE_DELIVERY_SIGNING_KEY"),
		ImgproxyKey:        os.Getenv("IMGPROXY_KEY"),
		ImgproxySalt:       os.Getenv("IMGPROXY_SALT"),
		GrantURLTTL:        parseDurationOr("PLATE_GRANTED_URL_TTL", 0),
		GrantCacheTTL:      parseDurationOr("PLATE_GRANT_CACHE_TTL", 0),
	}

	// Fail fast on a granted-image window wider than the hard cap (spec Q3.B): a
	// granted/signed image is enforced by imgproxy, which cannot check grant
	// liveness, so its expiry bounds how long a revoked image stays loadable. A
	// too-long PLATE_GRANTED_URL_TTL would silently create an un-revocable window;
	// refuse to boot instead (same discipline as the storage-partial-config check).
	if cfg.GrantURLTTL > GrantedImageMaxTTL {
		return EnvConfig{}, fmt.Errorf(
			"service: PLATE_GRANTED_URL_TTL (%s) exceeds the %s cap on granted-image expiry — a granted image is enforced by imgproxy, which cannot check revocation, so a longer window is silently un-revocable (spec Q3.B)",
			cfg.GrantURLTTL, GrantedImageMaxTTL)
	}
	if cfg.DatabaseURL == "" {
		return EnvConfig{}, errors.New("service: DATABASE_URL is required")
	}

	// The validation key is optional at boot: with no key, the process still
	// starts and the unauthenticated health/readiness probes work (spec: those
	// opt out with security: []), but EVERY token-bearing request is rejected
	// 401 by a deny-all verifier — the quickstart boots, yet nothing leaks. Set
	// PLATE_JWT_PUBLIC_KEY to actually accept tokens. This is fail-safe: absence
	// of the key denies, never allows.
	keyStr := os.Getenv("PLATE_JWT_PUBLIC_KEY")
	if keyStr == "" {
		cfg.Verifier = auth.DenyAllVerifier()
		return cfg, nil
	}
	pub, err := loadEd25519Public(keyStr)
	if err != nil {
		return EnvConfig{}, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEY: %w", err)
	}
	cfg.Verifier = auth.NewVerifier(pub, os.Getenv("PLATE_JWT_ISSUER"), os.Getenv("PLATE_JWT_AUDIENCE"))
	return cfg, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// LoadStorage builds the write-path dependencies (storage + prober + upload
// bounds) from the environment. Two legitimate states, and one misconfiguration
// that FAILS FAST (review ruling 7 — a broken deployment must die at boot with
// instructions, not accept traffic and error per request):
//
//   - NONE of the R2_* vars set → read-path-only deployment (intentional). Returns
//     Storage=nil; write endpoints answer 503 "storage not configured".
//   - the required R2 vars set → write path enabled.
//   - SOME but not all required R2 vars set → a misconfiguration; return an error
//     so `serve`/`work` refuse to start rather than half-work.
func LoadStorage(ctx context.Context) (StorageConfig, error) {
	bucket := os.Getenv("R2_DEFAULT_BUCKET")
	endpoint := os.Getenv("R2_ENDPOINT")
	access := os.Getenv("R2_ACCESS_KEY_ID")
	secret := os.Getenv("R2_SECRET_ACCESS_KEY")

	set := 0
	for _, v := range []string{bucket, endpoint, access, secret} {
		if v != "" {
			set++
		}
	}
	switch set {
	case 0:
		// Nothing configured: read-path-only. Not an error.
		return StorageConfig{}, nil
	case 4:
		// Fully configured: proceed.
	default:
		return StorageConfig{}, fmt.Errorf(
			"service: storage is partially configured (%d/4 of R2_DEFAULT_BUCKET, R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY set) — set all four to enable the write path, or none for a read-path-only deployment", set)
	}

	stor, err := storage.New(ctx, storage.Config{
		Endpoint:     endpoint,
		Region:       os.Getenv("R2_REGION"),
		AccessKey:    access,
		SecretKey:    secret,
		Bucket:       bucket,
		UsePathStyle: os.Getenv("PLATE_S3_PATH_STYLE") == "true",
	})
	if err != nil {
		return StorageConfig{}, fmt.Errorf("service: storage: %w", err)
	}
	return StorageConfig{
		Storage:        stor,
		Prober:         probe.New(os.Getenv("PLATE_FFPROBE_PATH")),
		UploadTTL:      parseDurationOr("PLATE_UPLOAD_URL_TTL", time.Hour),
		UploadMaxBytes: parseInt64Or("PLATE_UPLOAD_MAX_BYTES", 0),
	}, nil
}

// StorageConfig is the write-path slice of the service config, built by
// LoadStorage and merged into service.Config by main.
type StorageConfig struct {
	Storage        storage.Storage
	Prober         *probe.Prober
	UploadTTL      time.Duration
	UploadMaxBytes int64
}

func parseDurationOr(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// DetailMaxDurationSeconds is the detail-tier duration ceiling in seconds from
// PLATE_DETAIL_MAX_DURATION (a Go duration like "720s"), default 720 (12 min,
// spec §5.4). Read here so the worker and any delivery-side check share one source.
func DetailMaxDurationSeconds() float64 {
	return parseDurationOr("PLATE_DETAIL_MAX_DURATION", 720*time.Second).Seconds()
}

func parseInt64Or(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// loadEd25519Public accepts either a PEM-encoded public key or a base64 raw
// 32-byte Ed25519 key (the two shapes .env.example documents).
func loadEd25519Public(s string) (ed25519.PublicKey, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	if block, _ := pem.Decode([]byte(s)); block != nil {
		// A PKIX PEM public key. Kept simple: expect the raw key in the PEM bytes
		// is out of scope here; most deployments will use the base64 raw form.
		return nil, errors.New("PEM public keys not yet supported; supply a base64 raw Ed25519 key")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong key size %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
