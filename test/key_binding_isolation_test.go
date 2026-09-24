package plate_test

// Key → account binding, proven end to end against the real service and real
// Postgres + storage: a key bound to a namespace (the registry's "reg_*") or to
// one account ("uri") cannot read, grant, upload, delete, export or provision for
// an account outside its binding — even with every scope, even for an account
// that exists and holds data. Before the batch, ANY trusted key could sign for
// ANY account; this is the headline hole, and this test fails on that code
// (PLATE_JWT_KEY_ACCOUNTS is ignored there and every call below succeeds).
//
// The verifier is built exactly as production builds it: env → service.LoadEnv.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/test/harness"
)

type namedKey struct {
	kid  string
	pub  string
	priv ed25519.PrivateKey
}

func newNamedKey(t *testing.T, kid string) namedKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return namedKey{kid: kid, pub: base64.StdEncoding.EncodeToString(pub), priv: priv}
}

func (k namedKey) token(t *testing.T, account string, scopes ...string) string {
	t.Helper()
	tok, err := auth.SignWithKid(k.priv, k.kid, auth.Claims{
		Account: account,
		Scope:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "e2e",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var allScopes = []string{"assets:read", "assets:write", "renditions:generate", "grants:manage", "assets:export", "accounts:provision"}

// boundKeysEnv sets a production-shaped trusted set with bindings and returns a
// verifier LoadEnv built from it: uri → exactly uri-e2e, registry → reg_*, files
// unbound.
func boundKeysEnv(t *testing.T) (uri, registry, files namedKey, verf *auth.Verifier) {
	t.Helper()
	uri, registry, files = newNamedKey(t, "uri"), newNamedKey(t, "registry"), newNamedKey(t, "files")
	t.Setenv("DATABASE_URL", "postgres://unused@localhost:5432/unused") // LoadEnv requires one; the e2e store is its own
	t.Setenv("PLATE_JWT_PUBLIC_KEY", "")
	t.Setenv("PLATE_JWT_PUBLIC_KEYS", "uri="+uri.pub+",registry="+registry.pub+",files="+files.pub)
	t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "uri=uri-e2e,registry=reg_*")
	cfg, err := service.LoadEnv()
	if err != nil {
		t.Fatalf("LoadEnv: %v", err)
	}
	return uri, registry, files, cfg.Verifier
}

func (e *e2e) as(token, method, path string, body []byte) (int, string) {
	e.t.Helper()
	rec := newRecorder()
	e.handler.ServeHTTP(rec, reqWithToken(method, path, body, token))
	return rec.Code, rec.Body.String()
}

func TestKeyBinding_BoundKeyCannotActForAnotherAccount(t *testing.T) {
	uri, registry, files, verf := boundKeysEnv(t)
	e := newE2EWithVerifier(t, 720, verf)
	ctx := context.Background()
	for _, a := range []string{"uri-e2e", "reg_alpha"} {
		if err := e.st.CreateAccount(ctx, a, "", ""); err != nil {
			t.Fatal(err)
		}
	}

	// Uri's own data, created with Uri's own (exact-bound) key.
	uriTok := uri.token(t, "uri-e2e", allScopes...)
	e.token, e.account = uriTok, "uri-e2e"
	uriAsset := e.uploadAndFinalize(harness.SynthImage(t, t.TempDir(), "uri.png", 640, 480), "image/png")
	uriGrant := e.createGrant(time.Now().Add(time.Hour), uriAsset)
	exportBody := mustJSON(map[string]any{"assets": []string{uriAsset}, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if code, body := e.as(uriTok, "POST", "/v1/exports", exportBody); code != http.StatusCreated {
		t.Fatalf("precondition: Uri's own export = %d %s", code, body)
	}

	// The registry's namespace key, fully scoped, claiming Uri's account. Every
	// endpoint must refuse it at the verifier: 401, and the same body as a
	// garbage token.
	_, garbageBody := e.as("garbage", "GET", "/v1/assets/"+uriAsset, nil)
	rogue := registry.token(t, "uri-e2e", allScopes...)
	grantBody := mustJSON(map[string]any{"assets": []string{uriAsset}, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	uploadBody := mustJSON(map[string]any{"content_type": "image/png", "size_bytes": 1024})
	for _, c := range []struct {
		method, path string
		body         []byte
	}{
		{"GET", "/v1/assets/" + uriAsset, nil},
		{"GET", "/v1/assets", nil},
		{"GET", "/v1/assets/" + uriAsset + "/url?intent=lightbox", nil},
		{"GET", "/v1/assets/" + uriAsset + "/url?intent=original", nil},
		{"POST", "/v1/grants", grantBody},
		{"GET", "/v1/grants/" + uriGrant, nil},
		{"DELETE", "/v1/grants/" + uriGrant, nil},
		{"POST", "/v1/uploads", uploadBody},
		{"POST", "/v1/exports", exportBody},
		{"POST", "/v1/assets/" + uriAsset + "/renditions", mustJSON(map[string]any{"intent": "lightbox"})},
		{"DELETE", "/v1/assets/" + uriAsset, nil},
		{"PUT", "/v1/account", nil},
	} {
		code, body := e.as(rogue, c.method, c.path, c.body)
		if code != http.StatusUnauthorized {
			t.Errorf("SECURITY: registry key claiming Uri's account: %s %s = %d %s, want 401", c.method, c.path, code, body)
		} else if body != garbageBody {
			t.Errorf("%s %s: bound-key refusal body %q differs from an invalid-token body %q", c.method, c.path, body, garbageBody)
		}
	}
	// Uri's key is exact-bound: it cannot claim a registry tenant either.
	if code, _ := e.as(uri.token(t, "reg_alpha", allScopes...), "POST", "/v1/uploads", uploadBody); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: uri key claiming reg_alpha uploaded (%d), want 401", code)
	}

	// Nothing the rogue calls attempted took effect.
	if code, body := e.as(uriTok, "GET", "/v1/assets/"+uriAsset, nil); code != http.StatusOK || strings.Contains(body, `"deleted_at"`) {
		t.Fatalf("Uri's asset after the rogue calls = %d %s, want intact", code, body)
	}
	if code, body := e.as(uriTok, "GET", "/v1/grants/"+uriGrant, nil); code != http.StatusOK || strings.Contains(body, `"revoked_at":"`) {
		t.Fatalf("Uri's grant after the rogue calls = %d %s, want live", code, body)
	}

	// Inside its namespace the registry key works — and ordinary account
	// isolation still holds on top (Uri's asset is not the tenant's).
	tenant := registry.token(t, "reg_alpha", allScopes...)
	e.token, e.account = tenant, "reg_alpha"
	own := e.uploadAndFinalize(harness.SynthImage(t, t.TempDir(), "t.png", 320, 240), "image/png")
	if code, body := e.as(tenant, "GET", "/v1/assets/"+own, nil); code != http.StatusOK {
		t.Fatalf("namespace key reading its own tenant's asset = %d %s", code, body)
	}
	if code, _ := e.as(tenant, "GET", "/v1/assets/"+uriAsset, nil); code != http.StatusNotFound {
		t.Errorf("tenant reading Uri's asset = %d, want 404", code)
	}

	// An UNBOUND key is unchanged by bindings on other keys: it can still claim
	// any account (why chuck binds every key before requiring binding).
	if code, body := e.as(files.token(t, "uri-e2e", "assets:read"), "GET", "/v1/assets/"+uriAsset, nil); code != http.StatusOK {
		t.Errorf("unbound key = %d %s, want unchanged behaviour (200)", code, body)
	}
}

// The binding applies to the granted-A/V byte edge's precursor too: a namespace
// key cannot resolve a delivery URL for a video in another account.
func TestKeyBinding_BoundKeyCannotResolveForeignVideo(t *testing.T) {
	harness.RequireFFmpeg(t)
	uri, registry, _, verf := boundKeysEnv(t)
	e := newE2EWithVerifier(t, 720, verf)
	if err := e.st.CreateAccount(context.Background(), "uri-e2e", "", ""); err != nil {
		t.Fatal(err)
	}
	e.token, e.account = uri.token(t, "uri-e2e", allScopes...), "uri-e2e"
	vid := e.uploadAndFinalize(harness.SynthVideo(t, filepath.Join(t.TempDir(), "v.mp4"), harness.Seconds(2), true), "video/mp4")
	e.drainWorker()
	if code, body := e.as(registry.token(t, "uri-e2e", "assets:read"), "GET", "/v1/assets/"+vid+"/url?intent=detail", nil); code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: namespace key resolved Uri's video: %d %s", code, body)
	}
}
