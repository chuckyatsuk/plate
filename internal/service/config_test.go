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

// The transaction-pooler (6543) guard: SKIP LOCKED + goose DDL need session
// semantics, so a 6543 DSN must fail boot, not half-work at runtime.
func TestLoadEnv_TransactionPoolerFailsBoot(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://postgres.ref:pw@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require")
	if _, err := LoadEnv(); err == nil {
		t.Fatal("a :6543 transaction-pooler DSN must fail boot")
	}
}

func TestLoadEnv_SessionPoolerBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://postgres.ref:pw@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require")
	if _, err := LoadEnv(); err != nil {
		t.Fatalf("the :5432 session pooler must boot; got %v", err)
	}
}

// The known-throwaway-key guard: the demo keypair must fail boot unless the
// operator explicitly opts in, so a copied demo .env can't silently ship as prod.
func TestLoadEnv_ThrowawayKeyFailsBootWithoutOptIn(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	for k := range knownThrowawayKeys { // any known throwaway value
		t.Setenv("PLATE_JWT_PUBLIC_KEY", k)
		break
	}
	if _, err := LoadEnv(); err == nil {
		t.Fatal("a known-throwaway JWT key must fail boot without PLATE_ALLOW_THROWAWAY_KEYS")
	}
}

func TestLoadEnv_ThrowawayKeyBootsWithOptIn(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	var throwaway string
	for k := range knownThrowawayKeys {
		throwaway = k
		break
	}
	t.Setenv("PLATE_JWT_PUBLIC_KEY", throwaway)
	t.Setenv("PLATE_ALLOW_THROWAWAY_KEYS", "true")
	// It will still try to parse the key as Ed25519; the demo key is a valid one,
	// so boot should succeed. (If it weren't parseable that'd be a different error.)
	if _, err := LoadEnv(); err != nil {
		t.Fatalf("throwaway key WITH opt-in must boot; got %v", err)
	}
}

// The granted-image host must never be the public presets-only host: that
// imgproxy rejects every granted (exp) URL 404 "Invalid URL" (2026-09-24).
func TestLoadEnv_GrantedImageBaseEqualToPublicFailsBoot(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("IMGPROXY_BASE_URL", "https://plate-img.example")
	t.Setenv("IMGPROXY_GRANTED_BASE_URL", "https://plate-img.example/")
	if _, err := LoadEnv(); err == nil {
		t.Fatalf("IMGPROXY_GRANTED_BASE_URL equal to IMGPROXY_BASE_URL must fail boot")
	}
}

func TestLoadEnv_GrantedImageBaseDistinctBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("IMGPROXY_BASE_URL", "https://plate-img.example")
	t.Setenv("IMGPROXY_GRANTED_BASE_URL", "https://plate-img-granted.example")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatalf("distinct granted base must boot; got %v", err)
	}
	if cfg.URLs.GrantedImageBase != "https://plate-img-granted.example" {
		t.Fatalf("GrantedImageBase not loaded; got %q", cfg.URLs.GrantedImageBase)
	}
}

func TestLoadEnv_NoGrantedImageBaseBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("IMGPROXY_BASE_URL", "https://plate-img.example")
	t.Setenv("IMGPROXY_GRANTED_BASE_URL", "")
	if _, err := LoadEnv(); err != nil {
		t.Fatalf("unset granted base must boot (granted images then refuse 503); got %v", err)
	}
}
