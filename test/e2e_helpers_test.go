package plate_test

// Small shared helpers for the end-to-end delivery tests.

import (
	"crypto/ed25519"
	"encoding/json"
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
