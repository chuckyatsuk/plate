// Package auth implements Plate's service-to-service token model (spec Q3.A):
// a scoped JWT whose `account` claim is the ONLY source of the caller's account.
//
// This is the load-bearing rule of the whole architecture once one deployment
// serves many accounts (spec Q4): "the account is a CLAIM, never a request
// parameter." Plate checks `token.account == resource.account`; if the caller
// could instead pass `?account=X`, it would be asserting its own identity, which
// is how cross-tenant leaks happen. So the account travels here, in the verified
// token, and nowhere else — there is no account path or query parameter anywhere
// in the contract.
//
// Issuance is kept separable from validation (OAuth-shaped, not OAuth-
// implemented): the service only VALIDATES (Verifier). Sign() exists for tests
// and for a future issuer, and lives behind the same key material so the two
// cannot drift.
package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are Plate's service-token claims. Standard registered claims (iss, sub,
// aud, exp) plus the two that carry authorization: `account` and `scope`.
type Claims struct {
	Account string   `json:"account"`
	Scope   []string `json:"scope"`
	jwt.RegisteredClaims
}

// HasScope reports whether the token carries a given scope. Scopes are
// first-class from day one (spec Q3): assets:read, assets:write,
// renditions:generate, grants:manage.
func (c Claims) HasScope(s string) bool {
	for _, have := range c.Scope {
		if have == s {
			return true
		}
	}
	return false
}

// Verifier validates incoming service tokens against an Ed25519 public key and
// the expected issuer/audience. It only VALIDATES — it never mints — so the
// service half holds no signing key (spec Q3, issuance separable from validation).
type Verifier struct {
	pub      ed25519.PublicKey
	issuer   string
	audience string
	parser   *jwt.Parser
}

// DenyAllVerifier returns a Verifier with no key: every token fails validation,
// so every authenticated request is 401. It lets the process boot for the
// unauthenticated health/readiness probes when no validation key is configured,
// while failing safe — absence of a key DENIES, never allows.
func DenyAllVerifier() *Verifier {
	return &Verifier{parser: jwt.NewParser()}
}

// NewVerifier builds a Verifier. issuer/audience may be empty to skip that check
// (useful in tests), but in production both are set from PLATE_JWT_ISSUER /
// PLATE_JWT_AUDIENCE.
func NewVerifier(pub ed25519.PublicKey, issuer, audience string) *Verifier {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"EdDSA"}), // reject alg confusion outright
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	return &Verifier{pub: pub, issuer: issuer, audience: audience, parser: jwt.NewParser(opts...)}
}

// ErrNoAccount is returned when a token validates structurally but carries no
// account claim — a token with no account is not a valid caller in Plate.
var ErrNoAccount = errors.New("auth: token has no account claim")

// Verify parses and validates a bearer token string, returning its claims. It
// enforces the signing method (EdDSA only, so an attacker cannot downgrade to
// `alg: none` or an HMAC confusion), the signature, expiry, and iss/aud when
// configured.
func (v *Verifier) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := v.parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %q", t.Header["alg"])
		}
		return v.pub, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.Account == "" {
		return nil, ErrNoAccount
	}
	return claims, nil
}

// Sign mints a token for the given claims using an Ed25519 private key. This is
// the issuer half — used by tests and by a future authorization server, kept
// beside Verify so the claim shape cannot drift between the two.
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	return t.SignedString(priv)
}

// ── HTTP middleware ─────────────────────────────────────────────────────────

type ctxKey struct{}

// FromContext returns the verified claims placed by Middleware, or nil.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}

// Middleware validates the Authorization: Bearer token and puts the claims in
// the request context. A missing/invalid/expired token is a 401. This is the
// single place a request acquires its account — downstream handlers read the
// account from the claims, never from the request.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		claims, err := v.Verify(tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearer extracts the token from an `Authorization: Bearer <token>` header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// writeErr writes the contract's structured Error shape. The message NEVER
// leaks another account's data (spec: Error.message "Never leaks another
// account's data").
func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Minimal hand-encoded JSON to avoid pulling encoding/json here for one shape;
	// the service layer uses encoding/json for richer bodies.
	fmt.Fprintf(w, `{"code":%q,"message":%q}`, code, message)
}

// TestKeyPair generates an Ed25519 keypair for tests. It lives in the non-test
// build so both the service's test wiring and any example can mint tokens
// without duplicating key handling. Deterministic seeding is intentionally NOT
// offered — tests should use fresh keys.
func TestKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// ExpiresIn is a small helper for building token expiries.
func ExpiresIn(d time.Duration) *jwt.NumericDate {
	return jwt.NewNumericDate(time.Now().Add(d))
}
