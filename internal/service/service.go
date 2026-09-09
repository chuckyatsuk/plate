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
}

// New builds a Service from Config.
func New(cfg Config) *Service {
	ttl := cfg.UploadTTL
	if ttl <= 0 {
		ttl = time.Hour // generous for a studio's slow connection (spec Q3.C)
	}
	return &Service{
		store:          cfg.Store,
		verf:           cfg.Verifier,
		urls:           cfg.URLs,
		storage:        cfg.Storage,
		prober:         cfg.Prober,
		uploadTTL:      ttl,
		uploadMaxBytes: cfg.UploadMaxBytes,
	}
}

// expiresSoon is the short expiry for signed/original URLs. Kept here so the
// value is one place; production reads PLATE_SIGNED_URL_TTL.
func expiresSoon() time.Time { return time.Now().Add(5 * time.Minute) }
