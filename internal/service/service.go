// Package service is Plate's HTTP layer for the Phase 1 read path (spec §8):
// it serves delivery URLs by intent and reads asset/rendition/job/grant
// metadata. Nothing writes bytes; delivery returns URL strings (spec Q5).
//
// The single discipline this layer holds above all else: the caller's account
// comes from the verified token claim (auth.FromContext), NEVER from a path,
// query, or body parameter — there is no such parameter in the contract. Every
// store call passes that account, and every store query predicates on it, so a
// cross-account request matches zero rows and is answered as "not found for this
// account" (spec Q3.A, Q4). This is what the cross-account isolation conformance
// test proves at every endpoint.
package service

import (
	"log/slog"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// Config wires the service's dependencies. All values come from the environment
// in production (twelve-factor, spec Q4); tests construct it directly.
type Config struct {
	Store    store.Store
	Verifier *auth.Verifier
	URLs     URLBuilder

	// Storage and Prober are the write-path dependencies (Phase 2). They are nil
	// on a read-only deployment; the write handlers guard on nil and return 501 so
	// a read-path-only service is honest rather than panicking.
	Storage storage.Storage
	Prober  *probe.Prober

	// UploadTTL and UploadMaxBytes bound the presigned PUT (spec Q3.C). Zero
	// values fall back to safe defaults.
	UploadTTL      time.Duration
	UploadMaxBytes int64

	// DeliverySigningKey signs granted-mode A/V delivery URLs — Plate's own HMAC
	// over the /v1/download redirect (spec Q3.B). Empty means granted A/V is
	// refused (503) rather than served unsigned — fail closed. Read from
	// PLATE_DELIVERY_SIGNING_KEY.
	DeliverySigningKey string

	// ImgproxyKey / ImgproxySalt are the hex-encoded imgproxy signing pair
	// (IMGPROXY_KEY / IMGPROXY_SALT). They sign every NON-PUBLIC image URL
	// (granted + signed mode) so imgproxy enforces expiry/tamper at the byte edge.
	// Empty means non-public image delivery is refused (fail closed); public
	// images stay unsigned and cacheable regardless.
	ImgproxyKey  string
	ImgproxySalt string

	// Health tunes /readyz (worker staleness, queue lag, per-check timeout,
	// check allowlist, reported version). Zero values take safe defaults. Log is
	// used for readiness transitions; nil = slog.Default().
	Health HealthConfig
	Log    *slog.Logger

	// GrantURLTTL is how long a granted delivery URL (and its signature) is valid.
	// Short by design so a forwarded link stops working soon after revocation or
	// expiry (spec Q3.B). Zero falls back to a safe default.
	GrantURLTTL time.Duration

	// GrantCacheTTL bounds how often the per-request grant lookup hits the store
	// (spec Q3.B: revocation eventually-consistent within this window). Zero falls
	// back to a safe short default.
	GrantCacheTTL time.Duration
}

// Service holds the wired dependencies and exposes an http.Handler (Router).
type Service struct {
	store          store.Store
	verf           *auth.Verifier
	urls           URLBuilder
	storage        storage.Storage
	prober         *probe.Prober
	uploadTTL      time.Duration
	uploadMaxBytes int64

	signer      *signer         // nil when no download key: granted A/V refuses (503)
	imgsigner   *imgproxySigner // nil when no imgproxy key/salt: non-public images refuse
	grants      *grantCache     // short-TTL grant-verdict cache (spec Q3.B)
	grantURLTTL time.Duration
	health      *health // /readyz state + thresholds (Tier 1 monitoring)
}

// GrantedImageMaxTTL hard-caps how long a granted (or signed) image URL may live.
// imgproxy enforces expiry but has NO concept of grant liveness, so a revoked
// granted image keeps loading until its signature expires (the named
// images/A/V asymmetry, spec Q3.B). Capping the expiry bounds that window: a
// revoked granted image is un-loadable within this cap, always. Raising
// PLATE_GRANTED_URL_TTL past it is a boot-time error (LoadEnv), not a silent
// hour-long un-revocable window.
const GrantedImageMaxTTL = 120 * time.Second

// DefaultGrantedURLTTL is the granted-URL window when PLATE_GRANTED_URL_TTL is
// unset. It must sit UNDER GrantedImageMaxTTL: the cap used to be checked only
// against an explicit env value, so the old 5-minute default silently gave an
// unconfigured deployment a revoked image that kept loading for 5 minutes. 90s
// matches what production sets explicitly.
const DefaultGrantedURLTTL = 90 * time.Second

// New builds a Service from Config.
func New(cfg Config) *Service {
	ttl := cfg.UploadTTL
	if ttl <= 0 {
		ttl = time.Hour // generous for a studio's slow connection (spec Q3.C)
	}
	gurlTTL := cfg.GrantURLTTL
	if gurlTTL <= 0 {
		gurlTTL = DefaultGrantedURLTTL // short: a forwarded link expires soon (spec Q3.B)
	}
	// The cap holds on the EFFECTIVE value, however it was configured. LoadEnv
	// already refuses to boot on an env value past the cap; this keeps any other
	// constructor path (tests, future callers) from minting a longer window.
	if gurlTTL > GrantedImageMaxTTL {
		gurlTTL = GrantedImageMaxTTL
	}
	return &Service{
		store:          cfg.Store,
		verf:           cfg.Verifier,
		urls:           cfg.URLs,
		storage:        cfg.Storage,
		prober:         cfg.Prober,
		uploadTTL:      ttl,
		uploadMaxBytes: cfg.UploadMaxBytes,
		signer:         newSigner(cfg.DeliverySigningKey),
		imgsigner:      newImgproxySigner(cfg.ImgproxyKey, cfg.ImgproxySalt),
		grants:         newGrantCache(cfg.GrantCacheTTL),
		grantURLTTL:    gurlTTL,
		health:         newHealth(cfg.Health, cfg.Log),
	}
}
