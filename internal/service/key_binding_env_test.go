package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chuckyatsuk/plate/internal/auth"
)

// Key → account binding, driven the way production drives it: environment in,
// LoadEnv, the real router and auth middleware, a real HTTP answer out. These
// use only surfaces that existed before the batch (env vars, LoadEnv, Router),
// so run against the pre-batch code they FAIL: PLATE_JWT_KEY_ACCOUNTS is simply
// ignored there and every out-of-binding token is let through.

type envKey struct {
	pub  string
	priv ed25519.PrivateKey
}

func newEnvKey(t *testing.T) envKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return envKey{pub: base64.StdEncoding.EncodeToString(pub), priv: priv}
}

// envToken mints a token the way `plate token` does: kid "" = legacy no-kid.
func envToken(t *testing.T, k envKey, kid, account string, scopes ...string) string {
	t.Helper()
	c := auth.Claims{Account: account, Scope: scopes, RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	var (
		tok string
		err error
	)
	if kid == "" {
		tok, err = auth.Sign(k.priv, c)
	} else {
		tok, err = auth.SignWithKid(k.priv, kid, c)
	}
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// prodShapedKeys mirrors the live deployment's trusted set: a legacy key plus
// kids files, uri, registry-ci, registry-prod — and one future namespace kid.
type prodShapedKeys struct {
	legacy, files, uri, registryCI, registryProd, registry envKey
}

func setProdShapedKeys(t *testing.T) prodShapedKeys {
	t.Helper()
	k := prodShapedKeys{
		legacy: newEnvKey(t), files: newEnvKey(t), uri: newEnvKey(t),
		registryCI: newEnvKey(t), registryProd: newEnvKey(t), registry: newEnvKey(t),
	}
	t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
	t.Setenv("PLATE_JWT_PUBLIC_KEY", k.legacy.pub)
	t.Setenv("PLATE_JWT_PUBLIC_KEYS", strings.Join([]string{
		"files=" + k.files.pub, "uri=" + k.uri.pub, "registry-ci=" + k.registryCI.pub,
		"registry-prod=" + k.registryProd.pub, "registry=" + k.registry.pub,
	}, ","))
	return k
}

func routerFromEnv(t *testing.T) http.Handler {
	t.Helper()
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatalf("LoadEnv: %v", err)
	}
	return stubService(t, newStubStore(), cfg.Verifier).Router()
}

// passedAuth: the request reached the handler (the stub store answers 404 for
// the unknown asset). 401 means the verifier refused the token.
func getAsset(t *testing.T, h http.Handler, tok string) (int, string) {
	rec := do(t, h, "GET", "/v1/assets/01NOSUCHASSET0000000000000", tok)
	return rec.Code, trimBody(rec)
}

// The Uri-safety half: with NO binding configured, every trusted key verifies
// for every account exactly as before the batch — nothing changes on deploy.
func TestKeyBinding_Unset_EveryKeyVerifiesAsBefore(t *testing.T) {
	k := setProdShapedKeys(t)
	h := routerFromEnv(t)
	for _, c := range []struct {
		key envKey
		kid string
	}{{k.legacy, ""}, {k.files, "files"}, {k.uri, "uri"}, {k.registryCI, "registry-ci"}, {k.registryProd, "registry-prod"}, {k.registry, "registry"}} {
		for _, acct := range []string{"uriaran", "registry-ci", "reg_t1", "anyone"} {
			if code, body := getAsset(t, h, envToken(t, c.key, c.kid, acct, "assets:read")); code != http.StatusNotFound {
				t.Errorf("no bindings: kid %q claiming %q = %d %s; want it to pass auth (404 from the handler) as before", c.kid, acct, code, body)
			}
		}
	}
}

func TestKeyBinding_EnforcedThroughRouter(t *testing.T) {
	k := setProdShapedKeys(t)
	t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "uri=uriaran, registry-ci=registry-ci, registry=reg_*, @legacy=legacyacct")
	h := routerFromEnv(t)

	// The refusal body every invalid token gets — a bound-key refusal must be
	// byte-identical to it (no oracle about which accounts or bindings exist).
	_, garbage := getAsset(t, h, "not-a-token")

	for _, c := range []struct {
		key      envKey
		kid      string
		acct     string
		wantPass bool
	}{
		{k.uri, "uri", "uriaran", true},
		{k.uri, "uri", "registry-ci", false},
		{k.uri, "uri", "uriaran2", false},
		{k.registryCI, "registry-ci", "registry-ci", true},
		{k.registryCI, "registry-ci", "uriaran", false},
		{k.registry, "registry", "reg_tenant1", true},
		{k.registry, "registry", "uriaran", false}, // namespace issuer reaching Uri
		{k.registry, "registry", "regx", false},    // true prefix only
		{k.registry, "registry", "reg", false},
		{k.registry, "registry", "reg_", false},
		{k.legacy, "", "legacyacct", true},
		{k.legacy, "", "uriaran", false},
		{k.files, "files", "uriaran", true}, // unbound: unchanged
		{k.files, "files", "reg_tenant1", true},
		{k.registryProd, "registry-prod", "anyone", true}, // unbound: unchanged
	} {
		code, body := getAsset(t, h, envToken(t, c.key, c.kid, c.acct, "assets:read"))
		switch {
		case c.wantPass && code != http.StatusNotFound:
			t.Errorf("kid %q claiming %q (inside/unbound) = %d %s, want to pass auth", c.kid, c.acct, code, body)
		case !c.wantPass && code != http.StatusUnauthorized:
			t.Errorf("SECURITY: kid %q claiming %q (outside its binding) = %d %s, want 401", c.kid, c.acct, code, body)
		case !c.wantPass && body != garbage:
			t.Errorf("bound-key refusal body %q differs from an ordinary invalid-token body %q — an oracle", body, garbage)
		}
	}
}

func TestKeyBinding_BootValidation(t *testing.T) {
	for name, bindings := range map[string]string{
		"unknown kid":             "retired=uriaran",
		"malformed entry":         "uri",
		"empty pattern":           "uri=",
		"bare star":               "uri=*",
		"star not at end":         "registry=re*g_",
		"bad account chars":       "uri=uri/aran",
		"duplicate kid":           "uri=uriaran,uri=uriaran",
		"bad key name":            "bad kid=uriaran",
		"only separators":         ",",
		"legacy name misspelled":  "@legacyx=uriaran",
		"two stars (empty stem)":  "registry=**",
		"space inside pattern":    "uri=uri aran",
		"one-char exact account":  "uri=u",
		"prefix not alnum-led":    "registry=_reg*",
		"duplicate legacy":        "@legacy=a1,@legacy=a2",
		"star prefix of anything": "files=*",
	} {
		t.Run(name, func(t *testing.T) {
			setProdShapedKeys(t)
			t.Setenv("PLATE_JWT_KEY_ACCOUNTS", bindings)
			if _, err := LoadEnv(); err == nil {
				t.Fatalf("PLATE_JWT_KEY_ACCOUNTS=%q must refuse boot", bindings)
			}
		})
	}
	t.Run("legacy binding without a legacy key", func(t *testing.T) {
		setProdShapedKeys(t)
		t.Setenv("PLATE_JWT_PUBLIC_KEY", "")
		t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "@legacy=uriaran")
		if _, err := LoadEnv(); err == nil {
			t.Fatal("binding @legacy with no PLATE_JWT_PUBLIC_KEY must refuse boot")
		}
	})
	t.Run("bindings with no trusted keys at all", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://x@h:5432/db")
		t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "uri=uriaran")
		if _, err := LoadEnv(); err == nil {
			t.Fatal("bindings on a deny-all deployment name unknown keys and must refuse boot")
		}
	})
}

func TestKeyBinding_RequireBinding(t *testing.T) {
	allBound := "@legacy=legacyacct,files=files-acct,uri=uriaran,registry-ci=registry-ci,registry-prod=registry-ci,registry=reg_*"
	cases := []struct {
		name, bindings, require string
		wantBoot                bool
	}{
		{"off by default, nothing bound", "", "", true},
		{"explicit false", "", "false", true},
		{"required, nothing bound", "", "true", false},
		{"required, one kid unbound", strings.Replace(allBound, "files=files-acct,", "", 1), "true", false},
		{"required, legacy unbound", strings.Replace(allBound, "@legacy=legacyacct,", "", 1), "true", false},
		{"required, all bound", allBound, "true", true},
		{"typo in the switch", allBound, "ture", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setProdShapedKeys(t)
			t.Setenv("PLATE_JWT_KEY_ACCOUNTS", c.bindings)
			t.Setenv("PLATE_JWT_REQUIRE_KEY_BINDING", c.require)
			_, err := LoadEnv()
			if c.wantBoot && err != nil {
				t.Fatalf("want boot, got %v", err)
			}
			if !c.wantBoot && err == nil {
				t.Fatal("want boot refused, got a running config")
			}
		})
	}
}
