package service

import (
	"testing"
	"time"
)

// The granted-image expiry hard cap (spec Q3.B): a granted/signed image is
// enforced by imgproxy, which cannot check grant liveness, so its expiry bounds
// how long a revoked image stays loadable. A PLATE_GRANTED_URL_TTL past the cap
// would silently create an un-revocable window; LoadEnv must refuse to boot.

func TestLoadEnv_GrantedURLTTLOverCapFailsBoot(t *testing.T) {
	// DATABASE_URL is required for LoadEnv to proceed to the cap check.
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("PLATE_GRANTED_URL_TTL", (GrantedImageMaxTTL + time.Second).String())

	if _, err := LoadEnv(); err == nil {
		t.Fatalf("PLATE_GRANTED_URL_TTL over the %s cap must fail boot", GrantedImageMaxTTL)
	}
}

func TestLoadEnv_GrantedURLTTLAtCapBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("PLATE_GRANTED_URL_TTL", GrantedImageMaxTTL.String())

	if _, err := LoadEnv(); err != nil {
		t.Fatalf("PLATE_GRANTED_URL_TTL exactly at the cap must boot; got %v", err)
	}
}

func TestLoadEnv_NoGrantedTTLBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	// unset PLATE_GRANTED_URL_TTL → default (well under the cap)
	if _, err := LoadEnv(); err != nil {
		t.Fatalf("default granted TTL must boot; got %v", err)
	}
}
