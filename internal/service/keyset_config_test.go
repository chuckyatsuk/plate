package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// PLATE_JWT_PUBLIC_KEYS parsing (Tier 1 credential rotation). Every malformed
// shape must refuse BOOT — a key that "looks configured but isn't" would
// surface as a bare 401 at first use, far from its cause (the empty-Fly-secret
// lesson, 2026-09-13).

func b64Key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func TestParseKeyset_ValidSet(t *testing.T) {
	keys, err := parseKeyset("files=" + b64Key(t) + ", ops=" + b64Key(t) + ",")
	if err != nil {
		t.Fatalf("valid keyset refused: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	for _, kid := range []string{"files", "ops"} {
		if _, ok := keys[kid]; !ok {
			t.Errorf("kid %q missing from parsed set", kid)
		}
	}
}

func TestParseKeyset_EmptyIsNil(t *testing.T) {
	for _, s := range []string{"", "  "} {
		keys, err := parseKeyset(s)
		if err != nil || keys != nil {
			t.Errorf("parseKeyset(%q) = (%v, %v), want (nil, nil)", s, keys, err)
		}
	}
}

func TestParseKeyset_Malformed(t *testing.T) {
	valid := b64Key(t)
	for _, s := range []string{
		"noequalsign",                        // not kid=key
		"=" + valid,                          // empty kid
		"files=",                             // empty value — the looks-configured trap
		"files=notbase64!!",                  // undecodable key
		"files=" + valid[:10],                // wrong size
		"bad kid=" + valid,                   // kid with a space
		"files=" + valid + ",files=" + valid, // duplicate kid
		",",                                  // only separators, no entries
	} {
		if _, err := parseKeyset(s); err == nil {
			t.Errorf("parseKeyset(%q) accepted a malformed keyset", s)
		}
	}
}

// A throwaway-class key in the NAMED set is refused without the opt-in, same as
// the legacy slot — a demo key must not sneak into prod under a kid either.
func TestParseKeyset_ThrowawayKeyRefusedWithoutOptIn(t *testing.T) {
	var throwaway string
	for k := range knownThrowawayKeys {
		throwaway = k
		break
	}
	if _, err := parseKeyset("files=" + throwaway); err == nil {
		t.Fatal("a known-throwaway key under a kid must fail without PLATE_ALLOW_THROWAWAY_KEYS")
	}
	t.Setenv("PLATE_ALLOW_THROWAWAY_KEYS", "true")
	if _, err := parseKeyset("files=" + throwaway); err != nil {
		t.Fatalf("throwaway key WITH opt-in must parse; got %v", err)
	}
}

// LoadEnv wires the keyset: keyset-only boots with a working (non-deny-all)
// verifier; a malformed keyset refuses boot; keyset + legacy combine.
func TestLoadEnv_KeysetOnlyBoots(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	t.Setenv("PLATE_JWT_PUBLIC_KEYS", "files="+b64Key(t))
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatalf("keyset-only env must boot; got %v", err)
	}
	if !cfg.Verifier.Configured() {
		t.Fatal("keyset-only env produced an unconfigured (deny-all) verifier")
	}
}

func TestLoadEnv_MalformedKeysetFailsBoot(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	t.Setenv("PLATE_JWT_PUBLIC_KEYS", "files=")
	if _, err := LoadEnv(); err == nil {
		t.Fatal("a malformed PLATE_JWT_PUBLIC_KEYS must fail boot")
	}
}

func TestLoadEnv_NoKeysIsDenyAll(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatalf("no-key env must still boot (deny-all); got %v", err)
	}
	if cfg.Verifier.Configured() {
		t.Fatal("no-key env must produce a deny-all verifier")
	}
}
