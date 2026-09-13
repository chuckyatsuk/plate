package auth

import (
	"crypto/ed25519"
	"testing"
)

// The keyset properties (Tier 1 credential rotation). What must hold, in the
// verifier's own terms: a kid selects EXACTLY its key; an unknown/retired kid
// is rejected with NO fallback to the legacy key (fallback would resurrect a
// revoked credential); a no-kid token uses only the legacy key; and the two
// populations coexist during a migration window.

// A kid-bearing token verifies against exactly its named key.
func TestKeyset_KidSelectsItsKey(t *testing.T) {
	pubA, privA := TestKeyPair()
	v := NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"files": pubA}, "", "")

	tok, err := SignWithKid(privA, "files", claims("acct-a", "assets:read"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("kid-bearing token rejected by its own key: %v", err)
	}
	if got.Account != "acct-a" {
		t.Errorf("account = %q, want acct-a", got.Account)
	}
}

// An unknown kid is rejected even when the SAME private key signed it and the
// verifier trusts that key under another name — the kid is the identity being
// checked, and a retired kid must stay dead.
func TestKeyset_UnknownKidRejected_NoFallback(t *testing.T) {
	pub, priv := TestKeyPair()
	// The verifier trusts this key BOTH as legacy and as kid "files".
	v := NewKeysetVerifier(pub, map[string]ed25519.PublicKey{"files": pub}, "", "")

	tok, err := SignWithKid(priv, "retired", claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("SECURITY: accepted a token with an unknown kid — a retired kid must never fall back to another trusted key")
	}
}

// A kid-bearing token must not verify under a DIFFERENT kid's key.
func TestKeyset_KidCannotBorrowAnotherKidsKey(t *testing.T) {
	pubA, _ := TestKeyPair()
	_, privB := TestKeyPair()
	v := NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"files": pubA}, "", "")

	// Signed by B's key but claiming kid "files" (A's slot): signature mismatch.
	tok, err := SignWithKid(privB, "files", claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("SECURITY: a kid verified against a key it was not signed by")
	}
}

// A no-kid (legacy) token verifies only against the legacy key — never a named
// key — so a keyset-only deployment rejects legacy tokens outright.
func TestKeyset_NoKidUsesOnlyLegacyKey(t *testing.T) {
	pubA, privA := TestKeyPair()

	// Keyset-only verifier: the same key is trusted, but ONLY under a kid.
	keysetOnly := NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"files": pubA}, "", "")
	legacyTok, err := Sign(privA, claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keysetOnly.Verify(legacyTok); err == nil {
		t.Fatal("SECURITY: a no-kid token verified against a NAMED key — legacy tokens must require the legacy slot")
	}

	// With the legacy slot populated, the same token verifies.
	both := NewKeysetVerifier(pubA, nil, "", "")
	if _, err := both.Verify(legacyTok); err != nil {
		t.Fatalf("legacy token rejected by legacy key: %v", err)
	}
}

// The migration window: legacy no-kid tokens AND kid tokens verify side by
// side, each against its own slot — the overlap that makes rotation zero-
// downtime.
func TestKeyset_LegacyAndKidCoexist(t *testing.T) {
	pubOld, privOld := TestKeyPair()
	pubNew, privNew := TestKeyPair()
	v := NewKeysetVerifier(pubOld, map[string]ed25519.PublicKey{"files": pubNew}, "", "")

	oldTok, err := Sign(privOld, claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	newTok, err := SignWithKid(privNew, "files", claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(oldTok); err != nil {
		t.Fatalf("legacy token rejected during migration window: %v", err)
	}
	if _, err := v.Verify(newTok); err != nil {
		t.Fatalf("kid token rejected during migration window: %v", err)
	}
}

// Retiring a kid — a verifier built WITHOUT it — kills that kid's tokens while
// other kids keep working: revocation scoped to one consumer.
func TestKeyset_RetiringKidRevokesOnlyThatConsumer(t *testing.T) {
	pubFiles, privFiles := TestKeyPair()
	pubOps, privOps := TestKeyPair()

	filesTok, err := SignWithKid(privFiles, "files", claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	opsTok, err := SignWithKid(privOps, "ops", claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}

	before := NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"files": pubFiles, "ops": pubOps}, "", "")
	if _, err := before.Verify(filesTok); err != nil {
		t.Fatalf("files token rejected before retirement: %v", err)
	}

	after := NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"ops": pubOps}, "", "")
	if _, err := after.Verify(filesTok); err == nil {
		t.Fatal("retired kid's token still verifies — revocation did not take")
	}
	if _, err := after.Verify(opsTok); err != nil {
		t.Fatalf("unrelated kid's token was collateral damage of a retirement: %v", err)
	}
}

// SignWithKid refuses an empty kid — that shape belongs to Sign (legacy), and
// minting it here would produce a token whose verification slot is ambiguous.
func TestSignWithKid_RefusesEmptyKid(t *testing.T) {
	_, priv := TestKeyPair()
	if _, err := SignWithKid(priv, "", claims("acct-a")); err == nil {
		t.Fatal("SignWithKid accepted an empty kid")
	}
}

// Configured reports whether ANY key is trusted — the boot warning's input.
func TestConfigured(t *testing.T) {
	pub, _ := TestKeyPair()
	if DenyAllVerifier().Configured() {
		t.Error("deny-all verifier reports configured")
	}
	if !NewVerifier(pub, "", "").Configured() {
		t.Error("legacy-key verifier reports unconfigured")
	}
	if !NewKeysetVerifier(nil, map[string]ed25519.PublicKey{"files": pub}, "", "").Configured() {
		t.Error("keyset verifier reports unconfigured")
	}
}
