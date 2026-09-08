package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func claims(account string, scopes ...string) Claims {
	return Claims{
		Account: account,
		Scope:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
}

// A validly-signed token is accepted and its account/scope survive the round trip.
func TestVerify_AcceptsValidToken(t *testing.T) {
	pub, priv := TestKeyPair()
	v := NewVerifier(pub, "", "")

	tok, err := Sign(priv, claims("acct-a", "assets:read"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if got.Account != "acct-a" {
		t.Errorf("account = %q, want acct-a", got.Account)
	}
	if !got.HasScope("assets:read") {
		t.Errorf("scope not carried through")
	}
}

// The deny-all verifier (no key configured) must reject even a validly-signed
// token — absence of a validation key DENIES, never allows. This is the
// fail-safe the quickstart boot depends on.
func TestDenyAll_RejectsValidlySignedToken(t *testing.T) {
	_, priv := TestKeyPair()
	tok, err := Sign(priv, claims("acct-a", "assets:read"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DenyAllVerifier().Verify(tok); err == nil {
		t.Fatal("SECURITY: deny-all verifier accepted a token; a missing key must never allow")
	}
}

// An unsigned ("alg: none") token must be rejected — no algorithm downgrade.
func TestVerify_RejectsAlgNone(t *testing.T) {
	pub, _ := TestKeyPair()
	v := NewVerifier(pub, "", "")

	// Build an alg:none token by hand.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims("acct-a"))
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(s); err == nil {
		t.Fatal("SECURITY: accepted an alg:none token")
	}
}

// An HMAC-signed token verified against an Ed25519 key must be rejected — the
// classic algorithm-confusion attack (treating the public key as an HMAC secret).
func TestVerify_RejectsHMACConfusion(t *testing.T) {
	pub, _ := TestKeyPair()
	v := NewVerifier(pub, "", "")

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims("acct-a"))
	s, err := tok.SignedString([]byte(pub)) // attacker uses the public key as HMAC secret
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(s); err == nil {
		t.Fatal("SECURITY: accepted an HMAC token against an Ed25519 verifier (alg confusion)")
	}
}

// A structurally-valid token with no account claim is not a valid caller.
func TestVerify_RejectsMissingAccount(t *testing.T) {
	pub, priv := TestKeyPair()
	v := NewVerifier(pub, "", "")

	tok, err := Sign(priv, claims("")) // empty account
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("accepted a token with no account claim")
	}
}

// An expired token is rejected.
func TestVerify_RejectsExpired(t *testing.T) {
	pub, priv := TestKeyPair()
	v := NewVerifier(pub, "", "")

	c := claims("acct-a")
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	tok, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("accepted an expired token")
	}
}

// A token signed by a DIFFERENT key than the verifier trusts is rejected.
func TestVerify_RejectsWrongKey(t *testing.T) {
	pub, _ := TestKeyPair()
	_, otherPriv := TestKeyPair()
	v := NewVerifier(pub, "", "")

	tok, err := Sign(otherPriv, claims("acct-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("accepted a token signed by an untrusted key")
	}
}
