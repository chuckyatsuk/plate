package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// recomputeImgproxy independently reproduces imgproxy's /{sig}{path} form, so the
// production signer is checked against a from-scratch computation, not itself.
func recomputeImgproxy(t *testing.T, key, salt []byte, path string) string {
	t.Helper()
	h := hmac.New(sha256.New, key)
	h.Write(salt)
	h.Write([]byte(path))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return "/" + sig + path
}

func timeUnix(sec int64) time.Time { return time.Unix(sec, 0) }

// The signer is the security primitive under granted-mode delivery: a signed URL
// is a bearer capability for a short window, so tamper and expiry must both be
// caught. These are fast, in-package, no infra.

func TestSigner_SignVerifyRoundTrip(t *testing.T) {
	s := newSigner("k")
	url := "https://cdn.example/lightbox/plain/acct/asset"
	signed := s.sign(url, "lightbox", "g1", time.Now().Add(time.Minute))
	if !strings.Contains(signed, "sig=") || !strings.Contains(signed, "exp=") {
		t.Fatalf("signed URL missing sig/exp: %q", signed)
	}
	if !s.verify(signed, "lightbox", "g1") {
		t.Fatalf("freshly signed URL failed verify")
	}
}

func TestSigner_RejectsTamper(t *testing.T) {
	s := newSigner("k")
	exp := time.Now().Add(time.Minute)
	signed := s.sign("https://cdn.example/lightbox/plain/acct/asset", "lightbox", "g1", exp)

	cases := map[string]struct{ url, intent, grant string }{
		"path swapped to another object": {strings.Replace(signed, "acct/asset", "acct/other", 1), "lightbox", "g1"},
		"intent changed":                 {signed, "detail", "g1"},
		"grant changed":                  {signed, "lightbox", "g2"},
	}
	for name, c := range cases {
		if s.verify(c.url, c.intent, c.grant) {
			t.Errorf("%s: verify should have failed", name)
		}
	}
}

func TestSigner_RejectsExpired(t *testing.T) {
	s := newSigner("k")
	signed := s.sign("https://cdn.example/lightbox/plain/acct/asset", "lightbox", "g1", time.Now().Add(-time.Second))
	if s.verify(signed, "lightbox", "g1") {
		t.Fatalf("expired URL must fail verify")
	}
}

func TestSigner_DifferentKeyDoesNotVerify(t *testing.T) {
	a := newSigner("key-a")
	b := newSigner("key-b")
	signed := a.sign("https://cdn.example/lightbox/plain/acct/asset", "lightbox", "g1", time.Now().Add(time.Minute))
	if b.verify(signed, "lightbox", "g1") {
		t.Fatalf("a URL signed with key-a must not verify under key-b")
	}
}

func TestNewSigner_NilWithoutKey(t *testing.T) {
	if newSigner("") != nil {
		t.Fatalf("no key must yield a nil signer (granted mode then refuses, fail closed)")
	}
}

// ── imgproxy signer ──────────────────────────────────────────────────────────

func TestImgproxySigner_NilOnMissingOrBadHex(t *testing.T) {
	cases := map[string]struct{ key, salt string }{
		"no key":       {"", "abcd"},
		"no salt":      {"abcd", ""},
		"bad hex key":  {"zz", "abcd"},
		"bad hex salt": {"abcd", "zz"},
	}
	for name, c := range cases {
		if newImgproxySigner(c.key, c.salt) != nil {
			t.Errorf("%s: expected nil signer (fail closed)", name)
		}
	}
}

func TestImgproxySigner_KnownAnswerFormat(t *testing.T) {
	// imgproxy signs HMAC-SHA256(key, salt_bytes+path_bytes), URL-safe base64 no
	// padding, placed as /{sig}{path}. Verify the exact format against a
	// recomputation so a future refactor that changes salt ordering or encoding
	// fails here (not silently as a 403 from a real imgproxy).
	s := newImgproxySigner("6b6579", "73616c74") // hex for "key","salt"
	if s == nil {
		t.Fatal("valid hex must yield a signer")
	}
	path := "/lightbox/exp:1700000000/plain/acct/asset@jpg"
	got := s.signPath(path)
	// Recompute independently.
	want := recomputeImgproxy(t, []byte("key"), []byte("salt"), path)
	if got != want {
		t.Fatalf("signPath mismatch:\n got %q\nwant %q", got, want)
	}
	if !strings.HasPrefix(got, "/") || !strings.HasSuffix(got, path) {
		t.Fatalf("signed path must be /{sig}{path}; got %q", got)
	}
}

func TestImgproxySigner_ExpInSignedPath(t *testing.T) {
	s := newImgproxySigner("6b6579", "73616c74")
	url := s.signedImageURL("https://cdn.example", "lightbox", "acct/asset", timeUnix(1700000000))
	// The exp: option must be INSIDE the signed path (so imgproxy enforces it),
	// between the preset and the plain source.
	if !strings.Contains(url, "/lightbox/exp:1700000000/plain/acct/asset") {
		t.Fatalf("exp must sit in the signed path between preset and source; got %q", url)
	}
	if !strings.HasPrefix(url, "https://cdn.example/") {
		t.Fatalf("must be built on the base; got %q", url)
	}
}

func TestAssetIDFromRenditionKey(t *testing.T) {
	if got := assetIDFromRenditionKey("acct/asset123/detail"); got != "asset123" {
		t.Errorf("expected asset123, got %q", got)
	}
	for _, bad := range []string{"", "acct/asset", "a/b/c/d", "flat"} {
		if got := assetIDFromRenditionKey(bad); got != "" {
			t.Errorf("malformed key %q should yield \"\", got %q", bad, got)
		}
	}
}
