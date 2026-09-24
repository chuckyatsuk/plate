package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Key → account binding: a bound key may only claim the accounts its pattern
// names; an unbound key behaves exactly as before bindings existed.

func mustPattern(t *testing.T, s string) AccountPattern {
	t.Helper()
	p, err := ParseAccountPattern(s)
	if err != nil {
		t.Fatalf("ParseAccountPattern(%q): %v", s, err)
	}
	return p
}

func TestParseAccountPattern(t *testing.T) {
	for _, ok := range []string{"uriaran", "registry-ci", "e2e-acct", "reg_*", "regci_*", "a.b*", "r*"} {
		if _, err := ParseAccountPattern(ok); err != nil {
			t.Errorf("ParseAccountPattern(%q) refused a valid pattern: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",          // empty
		"*",         // empty prefix: binds to everything
		"**",        // '*' twice
		"re*g_*",    // '*' not only at the end
		"*reg",      // '*' at the start
		"reg_*x",    // '*' in the middle
		"reg/*",     // '/' can never be in an account (it is a storage key separator)
		"reg /*",    // whitespace
		"a",         // one char is not a valid AccountId
		"_reg*",     // AccountId must start alphanumeric
		"uri aran",  // whitespace
		"uriaran/x", // separator
	} {
		if _, err := ParseAccountPattern(bad); err == nil {
			t.Errorf("ParseAccountPattern(%q) accepted a malformed pattern", bad)
		}
	}
}

// The prefix is a TRUE prefix and '*' is one-or-more characters: the decisions
// the brief asked to be made and pinned.
func TestAccountPattern_Matches(t *testing.T) {
	reg := mustPattern(t, "reg_*")
	for acct, want := range map[string]bool{
		"reg_abc":          true,
		"reg_x":            true,
		"reg_AbC-12.z_":    true,
		"reg_":             false, // the namespace root is not an account ('*' = one or more)
		"reg":              false, // shorter than the prefix
		"regx":             false, // not a true prefix match
		"regx_abc":         false,
		"REG_abc":          false, // case-sensitive
		"xreg_abc":         false, // prefix, not substring
		"reg_a/b":          false, // suffix must keep the AccountId alphabet (storage keys)
		"reg_a b":          false,
		"":                 false,
		"reg_" + long(200): false, // AccountId length bound holds through a prefix
	} {
		if got := reg.Matches(acct); got != want {
			t.Errorf("reg_* .Matches(%q) = %v, want %v", acct, got, want)
		}
	}
	uri := mustPattern(t, "uriaran")
	for acct, want := range map[string]bool{
		"uriaran":  true,
		"uriaran2": false, // exact means exact
		"uriara":   false,
		"Uriaran":  false,
	} {
		if got := uri.Matches(acct); got != want {
			t.Errorf("uriaran .Matches(%q) = %v, want %v", acct, got, want)
		}
	}
	if !reg.IsPrefix() || uri.IsPrefix() {
		t.Error("IsPrefix wrong")
	}
	if reg.String() != "reg_*" || uri.String() != "uriaran" {
		t.Errorf("String() = %q, %q", reg.String(), uri.String())
	}
}

func long(n int) string { return strings.Repeat("a", n) }

// boundFixture: kids uri (exact → uriaran), registry (prefix → reg_*), files
// (unbound), and a legacy key bound to "legacyacct".
type boundFixture struct {
	v                                   *Verifier
	uri, registry, files, legacy, rogue ed25519.PrivateKey
}

func newBoundFixture(t *testing.T) boundFixture {
	t.Helper()
	pubURI, privURI := TestKeyPair()
	pubReg, privReg := TestKeyPair()
	pubFiles, privFiles := TestKeyPair()
	pubLegacy, privLegacy := TestKeyPair()
	_, rogue := TestKeyPair()
	v, err := NewBoundKeysetVerifier(pubLegacy,
		map[string]ed25519.PublicKey{"uri": pubURI, "registry": pubReg, "files": pubFiles},
		map[string]AccountPattern{
			"uri":         mustPattern(t, "uriaran"),
			"registry":    mustPattern(t, "reg_*"),
			LegacyKeyName: mustPattern(t, "legacyacct"),
		}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return boundFixture{v: v, uri: privURI, registry: privReg, files: privFiles, legacy: privLegacy, rogue: rogue}
}

func signKid(t *testing.T, priv ed25519.PrivateKey, kid, account string, scopes ...string) string {
	t.Helper()
	var (
		tok string
		err error
	)
	if kid == "" {
		tok, err = Sign(priv, claims(account, scopes...))
	} else {
		tok, err = SignWithKid(priv, kid, claims(account, scopes...))
	}
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerify_BoundKey_InPatternAccepted(t *testing.T) {
	f := newBoundFixture(t)
	for _, c := range []struct {
		priv    ed25519.PrivateKey
		kid     string
		account string
	}{
		{f.uri, "uri", "uriaran"},
		{f.registry, "registry", "reg_tenant1"},
		{f.registry, "registry", "reg_x"},
		{f.legacy, "", "legacyacct"},
	} {
		got, err := f.v.Verify(signKid(t, c.priv, c.kid, c.account))
		if err != nil {
			t.Errorf("kid %q claiming %q (inside its binding) rejected: %v", c.kid, c.account, err)
			continue
		}
		if got.Account != c.account {
			t.Errorf("account = %q, want %q", got.Account, c.account)
		}
	}
}

func TestVerify_BoundKey_OutOfPatternRejected(t *testing.T) {
	f := newBoundFixture(t)
	for _, c := range []struct {
		priv    ed25519.PrivateKey
		kid     string
		account string
	}{
		{f.uri, "uri", "reg_tenant1"},       // exact binding, other account
		{f.uri, "uri", "uriaran2"},          // exact means exact
		{f.registry, "registry", "uriaran"}, // namespace key reaching Uri — the headline
		{f.registry, "registry", "regx"},    // not a true prefix
		{f.registry, "registry", "reg"},     // shorter than the prefix
		{f.registry, "registry", "reg_"},    // the bare namespace root
		{f.legacy, "", "uriaran"},           // bound legacy key
	} {
		_, err := f.v.Verify(signKid(t, c.priv, c.kid, c.account))
		if !errors.Is(err, ErrAccountNotBound) {
			t.Errorf("SECURITY: kid %q claiming %q (outside its binding) = %v, want ErrAccountNotBound", c.kid, c.account, err)
		}
	}
}

// An unbound kid in a verifier that binds others is exactly as before: any account.
func TestVerify_UnboundKeyUnchanged(t *testing.T) {
	f := newBoundFixture(t)
	for _, acct := range []string{"uriaran", "reg_tenant1", "anything-at-all", "x"} {
		got, err := f.v.Verify(signKid(t, f.files, "files", acct, "assets:read"))
		if err != nil {
			t.Fatalf("unbound kid claiming %q rejected: %v", acct, err)
		}
		if got.Account != acct || !got.HasScope("assets:read") || got.NamespaceIssuer() || got.KeyName() != "files" {
			t.Fatalf("unbound kid claims = %+v (namespace=%v key=%q)", got, got.NamespaceIssuer(), got.KeyName())
		}
	}
}

// Binding is checked only after the signature: a forged token for an in-pattern
// account is still just a bad signature.
func TestVerify_BindingDoesNotWeakenSignature(t *testing.T) {
	f := newBoundFixture(t)
	if _, err := f.v.Verify(signKid(t, f.rogue, "registry", "reg_tenant1")); err == nil {
		t.Fatal("SECURITY: a token signed by the wrong key verified because its account was in-pattern")
	}
}

func TestClaims_NamespaceIssuer(t *testing.T) {
	f := newBoundFixture(t)
	for _, c := range []struct {
		priv    ed25519.PrivateKey
		kid     string
		account string
		want    bool
	}{
		{f.registry, "registry", "reg_t", true}, // prefix-bound
		{f.uri, "uri", "uriaran", false},        // exact-bound
		{f.files, "files", "reg_t", false},      // unbound, even claiming inside a namespace
		{f.legacy, "", "legacyacct", false},     // exact-bound legacy
	} {
		got, err := f.v.Verify(signKid(t, c.priv, c.kid, c.account))
		if err != nil {
			t.Fatal(err)
		}
		if got.NamespaceIssuer() != c.want {
			t.Errorf("kid %q: NamespaceIssuer = %v, want %v", c.kid, got.NamespaceIssuer(), c.want)
		}
	}
}

// The binding facts come from the verifying key, never the token body: a token
// that stuffs look-alike fields into its JSON gains nothing.
func TestClaims_BindingNotForgeableFromBody(t *testing.T) {
	f := newBoundFixture(t)
	c := claims("reg_t")
	raw, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["keyName"], m["binding"], m["KeyName"], m["NamespaceIssuer"] = "registry", map[string]any{"prefix": true, "value": "reg_"}, "registry", true
	body, _ := json.Marshal(m)
	// Sign the tampered claim set with the UNBOUND files key.
	tok, err := signRaw(f.files, "files", body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.NamespaceIssuer() || got.KeyName() != "files" {
		t.Fatalf("SECURITY: token body set binding facts (namespace=%v key=%q)", got.NamespaceIssuer(), got.KeyName())
	}
}

// signRaw signs an arbitrary JSON claims body with a kid header.
func signRaw(priv ed25519.PrivateKey, kid string, body []byte) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	return signing + "." + enc.EncodeToString(ed25519.Sign(priv, []byte(signing))), nil
}

func TestNewBoundKeysetVerifier_RefusesUnknownKeys(t *testing.T) {
	pub, _ := TestKeyPair()
	p := mustPattern(t, "uriaran")
	if _, err := NewBoundKeysetVerifier(nil, map[string]ed25519.PublicKey{"uri": pub},
		map[string]AccountPattern{"retired": p}, "", ""); err == nil {
		t.Error("a binding for a kid that is not trusted must be refused")
	}
	if _, err := NewBoundKeysetVerifier(nil, map[string]ed25519.PublicKey{"uri": pub},
		map[string]AccountPattern{LegacyKeyName: p}, "", ""); err == nil {
		t.Errorf("a %s binding with no legacy key must be refused", LegacyKeyName)
	}
	if _, err := NewBoundKeysetVerifier(pub, nil,
		map[string]AccountPattern{LegacyKeyName: {}}, "", ""); err == nil {
		t.Error("a zero-value (empty) pattern must be refused")
	}
}

func TestUnboundAndBoundKeys(t *testing.T) {
	f := newBoundFixture(t)
	if got := f.v.UnboundKeys(); !reflect.DeepEqual(got, []string{"files"}) {
		t.Errorf("UnboundKeys = %v, want [files]", got)
	}
	if got := f.v.BoundKeys(); !reflect.DeepEqual(got, []string{LegacyKeyName, "registry", "uri"}) {
		t.Errorf("BoundKeys = %v", got)
	}
	pub, _ := TestKeyPair()
	plain := NewKeysetVerifier(pub, map[string]ed25519.PublicKey{"b": pub, "a": pub}, "", "")
	if got := plain.UnboundKeys(); !reflect.DeepEqual(got, []string{LegacyKeyName, "a", "b"}) {
		t.Errorf("unbound verifier UnboundKeys = %v, want every key", got)
	}
	if got := DenyAllVerifier().UnboundKeys(); len(got) != 0 {
		t.Errorf("deny-all UnboundKeys = %v, want none", got)
	}
}
