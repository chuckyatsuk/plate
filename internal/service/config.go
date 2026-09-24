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
	"strings"
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

	// Health: /readyz tunables (PLATE_WORKER_STALE_AFTER,
	// PLATE_WORKER_PROGRESS_WINDOW, PLATE_READYZ_TIMEOUT, PLATE_READYZ_CHECKS) + the
	// reported version (PLATE_VERSION, else Fly's FLY_IMAGE_REF).
	Health HealthConfig
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
			// Granted (expiring) images are served by a SEPARATE imgproxy in
			// options mode (pr+exp only); the presets-only public host cannot
			// parse exp. Unset ⇒ granted images refuse (503), fail closed.
			GrantedImageBase: os.Getenv("IMGPROXY_GRANTED_BASE_URL"),
			// imgproxy reads originals as a PRIVATE S3 source from this bucket
			// (s3://{bucket}/vault/...), so the vault original is never publicly
			// reachable. Same bucket as storage; imgproxy holds its own R2 creds.
			ImageSourceBucket: os.Getenv("R2_DEFAULT_BUCKET"),
			R2PublicBase:      os.Getenv("R2_PUBLIC_BASE"),
			DownloadBase:      envOr("PLATE_DOWNLOAD_BASE", "https://plate.example"),
		},
		DeliverySigningKey: os.Getenv("PLATE_DELIVERY_SIGNING_KEY"),
		ImgproxyKey:        os.Getenv("IMGPROXY_KEY"),
		ImgproxySalt:       os.Getenv("IMGPROXY_SALT"),
		GrantURLTTL:        parseDurationOr("PLATE_GRANTED_URL_TTL", 0),
		GrantCacheTTL:      parseDurationOr("PLATE_GRANT_CACHE_TTL", 0),
		Health: HealthConfig{
			WorkerStaleAfter:     parseDurationOr("PLATE_WORKER_STALE_AFTER", 0),
			WorkerProgressWindow: parseDurationOr("PLATE_WORKER_PROGRESS_WINDOW", 0),
			CheckTimeout:         parseDurationOr("PLATE_READYZ_TIMEOUT", 0),
			Checks:               splitCSV(os.Getenv("PLATE_READYZ_CHECKS")),
			Version:              firstNonEmpty(os.Getenv("PLATE_VERSION"), os.Getenv("FLY_IMAGE_REF")),
		},
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
	// Fail fast if the granted-image host is the PUBLIC presets-only host: that
	// imgproxy cannot parse the granted URL's exp option and answers every
	// granted image 404 "Invalid URL" (the 2026-09-24 bug). Unset is fine (granted
	// images then refuse 503); the SAME host is always a misconfiguration.
	if g := strings.TrimRight(cfg.URLs.GrantedImageBase, "/"); g != "" && g == strings.TrimRight(cfg.URLs.ImageCDNBase, "/") {
		return EnvConfig{}, errors.New(
			"service: IMGPROXY_GRANTED_BASE_URL must not equal IMGPROXY_BASE_URL — the public imgproxy runs presets-only and rejects granted (exp) URLs; point it at the granted imgproxy (deploy/fly.imgproxy-granted.plate.toml) or leave it unset")
	}
	if cfg.DatabaseURL == "" {
		return EnvConfig{}, errors.New("service: DATABASE_URL is required")
	}
	// Fail fast on the Supabase TRANSACTION pooler (port 6543). Plate's worker
	// queue uses SELECT ... FOR UPDATE SKIP LOCKED and goose runs DDL — both need
	// SESSION semantics, which the transaction pooler (6543) does not provide;
	// they break in subtle, runtime-only ways there. The IPv4 SESSION pooler
	// (5432) is correct (the direct host is IPv6-only). Refuse to boot on 6543
	// rather than half-work (spec Q4; the connection lesson, 2026-09-09).
	if strings.Contains(cfg.DatabaseURL, ":6543") {
		return EnvConfig{}, errors.New(
			"service: DATABASE_URL points at the Supabase TRANSACTION pooler (port 6543), which lacks the session semantics SKIP LOCKED + goose DDL require — use the SESSION pooler (port 5432) instead (the direct db.<ref> host is IPv6-only)")
	}

	// Validation keys are optional at boot: with none, the process still starts
	// and the unauthenticated health/readiness probes work (spec: those opt out
	// with security: []), but EVERY token-bearing request is rejected 401 by a
	// deny-all verifier — the quickstart boots, yet nothing leaks. This is
	// fail-safe: absence of keys denies, never allows.
	//
	// Two sources, combinable (Tier 1 credential rotation):
	//   - PLATE_JWT_PUBLIC_KEY: the legacy single key — verifies tokens with NO
	//     kid header (every pre-keyset token).
	//   - PLATE_JWT_PUBLIC_KEYS: a NAMED set, "kid=base64,kid2=base64" — a token's
	//     kid header selects exactly its key. Rotation is add → switch → retire;
	//     retiring a kid revokes that consumer's tokens without touching others.
	legacyStr := os.Getenv("PLATE_JWT_PUBLIC_KEY")
	keyset, err := parseKeyset(os.Getenv("PLATE_JWT_PUBLIC_KEYS"))
	if err != nil {
		return EnvConfig{}, err
	}
	if legacyStr == "" && keyset == nil {
		cfg.Verifier = auth.DenyAllVerifier()
		return cfg, nil
	}
	var legacy ed25519.PublicKey
	if legacyStr != "" {
		// Refuse to boot on a KNOWN-THROWAWAY key (the demo/smoke keypair) unless
		// the operator explicitly opts in with PLATE_ALLOW_THROWAWAY_KEYS=true.
		// This keeps a demo key from silently reaching a real deployment: the demo
		// sets the flag deliberately; prod never does, so a copied .env fails loud
		// at boot instead of accepting tokens signed by a key whose private half is
		// in a scratch file.
		if isThrowawayKey(legacyStr) && os.Getenv("PLATE_ALLOW_THROWAWAY_KEYS") != "true" {
			return EnvConfig{}, errors.New(
				"service: PLATE_JWT_PUBLIC_KEY is a KNOWN-THROWAWAY demo key — generate a real Ed25519 keypair for this deployment, or set PLATE_ALLOW_THROWAWAY_KEYS=true if this is intentionally the demo")
		}
		legacy, err = loadEd25519Public(legacyStr)
		if err != nil {
			return EnvConfig{}, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEY: %w", err)
		}
	}
	cfg.Verifier = auth.NewKeysetVerifier(legacy, keyset, os.Getenv("PLATE_JWT_ISSUER"), os.Getenv("PLATE_JWT_AUDIENCE"))
	return cfg, nil
}

// parseKeyset parses PLATE_JWT_PUBLIC_KEYS: comma-separated `kid=base64` pairs,
// e.g. "files=SEy/Ys...,ops=9SRBsq...". Returns nil for an empty/unset value.
// Every entry is validated hard — a malformed pair, empty half, duplicate kid,
// or throwaway-class key refuses BOOT, never a silently-untrusted key (the
// looks-configured-but-isn't trap this project keeps meeting: the empty Fly
// secret that read as "Deployed" while the server fail-closed at first use).
func parseKeyset(s string) (map[string]ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue // tolerate a trailing comma
		}
		kid, val, found := strings.Cut(entry, "=")
		// A base64 value may itself end in '='; Cut on the FIRST '=' keeps the
		// padding with the value. The kid half must not be empty and must be a
		// plain name (it travels in a JWT header and in ops runbooks).
		kid = strings.TrimSpace(kid)
		val = strings.TrimSpace(val)
		if !found || kid == "" || val == "" {
			return nil, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEYS entry %q is not kid=base64key", entry)
		}
		if !validKid(kid) {
			return nil, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEYS kid %q must be [A-Za-z0-9_-]{1,64}", kid)
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEYS names kid %q twice — one of them is not the key you think it is", kid)
		}
		if isThrowawayKey(val) && os.Getenv("PLATE_ALLOW_THROWAWAY_KEYS") != "true" {
			return nil, fmt.Errorf(
				"service: PLATE_JWT_PUBLIC_KEYS kid %q is a KNOWN-THROWAWAY demo key — generate a real Ed25519 keypair, or set PLATE_ALLOW_THROWAWAY_KEYS=true if this is intentionally the demo", kid)
		}
		pub, err := loadEd25519Public(val)
		if err != nil {
			return nil, fmt.Errorf("service: PLATE_JWT_PUBLIC_KEYS kid %q: %w", kid, err)
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("service: PLATE_JWT_PUBLIC_KEYS is set but contains no kid=key entries")
	}
	return keys, nil
}

// validKid bounds key ids to plain names: they travel in JWT headers, env vars,
// and runbook prose, so no separators/whitespace that could corrupt parsing.
func validKid(kid string) bool {
	if len(kid) == 0 || len(kid) > 64 {
		return false
	}
	for _, r := range kid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// knownThrowawayKeys are public keys minted as demo/smoke throwaways this project
// has used. A deployment carrying one of these must opt in explicitly
// (PLATE_ALLOW_THROWAWAY_KEYS=true) or fail boot — so a demo key cannot silently
// become a "real" one. Add a value here whenever a throwaway keypair is generated
// and used somewhere it could be copied from.
var knownThrowawayKeys = map[string]bool{
	// The 2026-09-09 smoke/demo keypair. RETIRED 2026-09-10 — rotated OFF this key
	// (its private half was never recoverable; a token minted with a candidate key
	// 401'd against the deployed API, forcing the rotation). No deployment carries
	// it anymore; kept as a historical guard so it can never be re-adopted.
	"9SRBsqY2/qVTTwxviZ5GiTFKmxu8DY14lIZ0W890RwU=": true,

	// The 2026-09-10 demo keypair, deployed on plate-demo-api after the rotation.
	// It is a DEMO key: its private half is held in ~/Dev/plate/.env (gitignored,
	// but a loose private half a token could be minted from), so by this list's
	// rule it is throwaway-class. The demo opts past the guard with
	// PLATE_ALLOW_THROWAWAY_KEYS=true; a real prod deployment must generate its own
	// keypair and must NOT set that flag (a copied demo config then fails boot).
	"SEy/Ysvsr9il4zU4jfxAmdehVhoo32K1aFVdsgA9DNc=": true,
}

func isThrowawayKey(pub string) bool {
	return knownThrowawayKeys[strings.TrimSpace(pub)]
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

// splitCSV splits a comma-separated env value into trimmed, non-empty parts.
func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
