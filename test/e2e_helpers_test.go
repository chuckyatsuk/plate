package plate_test

// Small shared helpers for the end-to-end delivery tests.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func ed25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	return auth.TestKeyPair()
}

func newVerifier(t *testing.T, pub ed25519.PublicKey) *auth.Verifier {
	t.Helper()
	return auth.NewVerifier(pub, "", "") // issuer/aud checks off in tests
}

func signToken(t *testing.T, priv ed25519.PrivateKey, account, scopesCSV string) string {
	t.Helper()
	tok, err := auth.Sign(priv, auth.Claims{
		Account: account,
		Scope:   strings.Split(scopesCSV, ","),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "e2e",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// reqWithToken builds a request carrying an ARBITRARY bearer token (unlike
// e.req, which always uses the harness account's token) — for tests that act as a
// different account, e.g. an unprovisioned one.
func reqWithToken(method, path string, body []byte, token string) *http.Request {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// createGrant issues a grant over the given asset ids, expiring at exp, and
// returns the new grant id. Uses the real POST /v1/grants endpoint (the e2e
// token carries grants:manage), so the grant row is created exactly as
// production would create it.
func (e *e2e) createGrant(exp time.Time, assets ...string) string {
	e.t.Helper()
	body := mustJSON(map[string]any{"assets": assets, "expires": exp.UTC().Format(time.RFC3339Nano)})
	resp := e.req("POST", "/v1/grants", body)
	if resp.Code != 201 {
		e.t.Fatalf("createGrant: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	mustDecode(e.t, resp.Body.Bytes(), &out)
	return out.ID
}

// revokeGrant revokes a grant via the real DELETE /v1/grants/{id} endpoint.
func (e *e2e) revokeGrant(grantID string) {
	e.t.Helper()
	resp := e.req("DELETE", "/v1/grants/"+grantID, nil)
	if resp.Code != 200 {
		e.t.Fatalf("revokeGrant: HTTP %d: %s", resp.Code, resp.Body.String())
	}
}

// resolveGrant resolves a delivery URL for an asset under a grant, returning the
// full resolution (delivery or refusal reason). Unlike resolve(), it does not
// require HTTP 200-with-delivery — granted refusals are 200 + reason.
func (e *e2e) resolveGrant(assetID, intent, grantID string) plateDeliveryResolution {
	e.t.Helper()
	resp := e.req("GET", "/v1/assets/"+assetID+"/url?intent="+intent+"&grant="+grantID, nil)
	if resp.Code != 200 {
		e.t.Fatalf("resolve grant: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var out plateDeliveryResolution
	mustDecode(e.t, resp.Body.Bytes(), &out)
	return out
}

// downloadPath strips the DownloadBase host off a /v1/download URL, leaving the
// path+query the (unauthenticated, sig-is-auth) /download handler is driven with.
func downloadPath(fullURL string) string {
	i := strings.Index(fullURL, "/v1/download/")
	if i < 0 {
		return fullURL
	}
	return fullURL[i:]
}

// fetchDownload drives the /v1/download handler with the given path+query and NO
// token (the signature is the authorization). Returns the HTTP status and, on a
// 302, the Location (the presigned R2 URL).
func (e *e2e) fetchDownload(pathQuery string) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest("GET", pathQuery, nil) // deliberately no Authorization
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Header().Get("Location")
}

// getBytes follows a presigned R2/MinIO URL (rewriting the host for the test
// endpoint) and returns the fetched body — proving the redirect target actually
// serves the object.
func (e *e2e) getBytes(presignedURL string) (int, []byte) {
	e.t.Helper()
	url := rewriteHost(presignedURL, e.stor.Endpoint)
	resp, err := http.Get(url)
	if err != nil {
		e.t.Fatalf("get presigned bytes: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mustDecode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode json: %v\nbody: %s", err, string(b))
	}
}

// rewriteHost swaps the scheme+host of a presigned URL for the test's storage
// endpoint. StartMinIO builds its storage client with the SAME endpoint the test
// reaches, so the signed host matches and no header override is needed — this
// just ensures the URL host is the reachable one.
func rewriteHost(signedURL, endpoint string) string {
	// signedURL: http://<host>/<bucket>/<key>?<query>
	// endpoint:  http://<host>
	const scheme = "http://"
	rest := strings.TrimPrefix(signedURL, scheme)
	i := strings.Index(rest, "/") // first slash after the host
	if i < 0 {
		return signedURL
	}
	return strings.TrimRight(endpoint, "/") + rest[i:]
}
