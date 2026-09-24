package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Key → account binding (the security batch's headline fix).
//
// Before binding, ANY trusted key could sign a token for ANY account: the
// verifier checked signature, expiry, iss/aud and a non-empty claim, never which
// accounts a given key may speak for. On a deployment shared by several
// consumers (Uri's site, the registry, CI) that made every consumer's key a
// skeleton key to every other consumer's media.
//
// A binding narrows one key to the accounts it may claim. It is checked AFTER
// key selection, so it only ever REMOVES access: a key with no binding behaves
// exactly as before (every account), which is what lets this ship to a live
// deployment with no configuration and change nothing until the operator binds.

// LegacyKeyName names the legacy no-kid key (PLATE_JWT_PUBLIC_KEY) in a binding
// table. It deliberately contains '@', which a kid can never contain
// ([A-Za-z0-9_-]), so it can never collide with a real kid.
const LegacyKeyName = "@legacy"

// accountIDPattern is the contract's AccountId pattern (contract/openapi.yaml,
// components.schemas.AccountId). A bound key may only claim accounts of this
// shape — the account travels into storage keys (vault/{account}/...), so a
// namespace issuer must not be able to smuggle a '/' through its suffix.
var accountIDPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z_.-]{1,127}$`)

// ValidAccountID reports whether s is a well-formed contract AccountId.
func ValidAccountID(s string) bool { return accountIDPattern.MatchString(s) }

// AccountPattern is what one key may claim: either exactly one account id
// ("uriaran") or a namespace — a prefix written with a trailing '*' ("reg_*").
//
// Prefix semantics, decided and pinned by tests:
//   - it is a TRUE prefix, case-sensitive: "reg_*" matches "reg_abc", never
//     "regx", "xreg_abc" or "REG_abc";
//   - '*' stands for ONE OR MORE characters: "reg_*" never matches "reg_" itself
//     (the namespace root is not an account) nor "reg";
//   - the whole claimed account must still be a valid AccountId.
type AccountPattern struct {
	value  string // the exact account id, or the prefix without its '*'
	prefix bool
}

// ParseAccountPattern parses one binding pattern. It refuses an empty pattern, a
// bare "*" (an empty prefix would bind to everything — the unbound state wearing
// a binding's clothes), a '*' anywhere but the end, and any character an
// AccountId cannot contain.
func ParseAccountPattern(s string) (AccountPattern, error) {
	if s == "" {
		return AccountPattern{}, errors.New("empty account pattern")
	}
	if strings.HasSuffix(s, "*") {
		p := strings.TrimSuffix(s, "*")
		if p == "" {
			return AccountPattern{}, errors.New(`account pattern "*" is an empty prefix — it would bind the key to every account; name a namespace such as "reg_*"`)
		}
		if strings.Contains(p, "*") {
			return AccountPattern{}, fmt.Errorf("account pattern %q: '*' is only allowed once, at the end", s)
		}
		// The prefix plus at least one more character must be able to form an
		// AccountId, so the prefix obeys the same alphabet and length.
		if !accountIDPattern.MatchString(p+"x") || len(p) > 127 {
			return AccountPattern{}, fmt.Errorf("account pattern %q: prefix must be [0-9A-Za-z][0-9A-Za-z_.-]* (an AccountId start)", s)
		}
		return AccountPattern{value: p, prefix: true}, nil
	}
	if strings.Contains(s, "*") {
		return AccountPattern{}, fmt.Errorf("account pattern %q: '*' is only allowed once, at the end", s)
	}
	if !accountIDPattern.MatchString(s) {
		return AccountPattern{}, fmt.Errorf("account pattern %q is not a valid account id ([0-9A-Za-z][0-9A-Za-z_.-]{1,127})", s)
	}
	return AccountPattern{value: s}, nil
}

// Matches reports whether a token claiming account may be accepted under this
// pattern.
func (p AccountPattern) Matches(account string) bool {
	if !p.prefix {
		return account == p.value
	}
	return len(account) > len(p.value) &&
		strings.HasPrefix(account, p.value) &&
		accountIDPattern.MatchString(account)
}

// IsPrefix reports whether the pattern is a namespace (prefix) binding. Only a
// namespace issuer may provision accounts (PUT /v1/account): an exact-bound key
// already names the one account it serves, which an operator provisioned.
func (p AccountPattern) IsPrefix() bool { return p.prefix }

// String renders the pattern as configured ("uriaran", "reg_*").
func (p AccountPattern) String() string {
	if p.prefix {
		return p.value + "*"
	}
	return p.value
}

// ErrAccountNotBound is returned when a token's key is bound and its account
// claim falls outside the binding. The HTTP layer answers it exactly like any
// other invalid token (401, same body) — no oracle about which accounts exist
// or which key serves which namespace.
var ErrAccountNotBound = errors.New("auth: token's key is not bound to its account claim")

// NewBoundKeysetVerifier is NewKeysetVerifier plus a key → account binding
// table, keyed by kid (or LegacyKeyName for the legacy no-kid key). A binding
// that names a key the verifier does not trust is an error: it is either a typo
// or a retired kid, and either way the operator believes a key is narrowed when
// it is not. Keys with no entry stay unbound (today's behaviour).
func NewBoundKeysetVerifier(legacy ed25519.PublicKey, keys map[string]ed25519.PublicKey, bindings map[string]AccountPattern, issuer, audience string) (*Verifier, error) {
	v := NewKeysetVerifier(legacy, keys, issuer, audience)
	if len(bindings) == 0 {
		return v, nil
	}
	b := make(map[string]AccountPattern, len(bindings))
	for name, p := range bindings {
		switch {
		case name == LegacyKeyName:
			if legacy == nil {
				return nil, fmt.Errorf("auth: binding for %s but no legacy key (PLATE_JWT_PUBLIC_KEY) is trusted", LegacyKeyName)
			}
		default:
			if _, ok := keys[name]; !ok {
				return nil, fmt.Errorf("auth: binding for kid %q, which is not a trusted key (PLATE_JWT_PUBLIC_KEYS)", name)
			}
		}
		if p.value == "" {
			return nil, fmt.Errorf("auth: binding for %q has an empty pattern", name)
		}
		b[name] = p
	}
	v.bindings = b
	return v, nil
}

// UnboundKeys lists every trusted key with no binding — kids, plus LegacyKeyName
// when the legacy key is trusted and unbound — sorted. Boot logs each one (WARN)
// and PLATE_JWT_REQUIRE_KEY_BINDING=true refuses to boot while any remain.
func (v *Verifier) UnboundKeys() []string {
	var out []string
	if v.pub != nil {
		if _, ok := v.bindings[LegacyKeyName]; !ok {
			out = append(out, LegacyKeyName)
		}
	}
	for kid := range v.keys {
		if _, ok := v.bindings[kid]; !ok {
			out = append(out, kid)
		}
	}
	sort.Strings(out)
	return out
}

// BoundKeys lists every key name that has a binding, sorted.
func (v *Verifier) BoundKeys() []string {
	out := make([]string, 0, len(v.bindings))
	for name := range v.bindings {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Binding returns the binding for a key name (kid or LegacyKeyName), if any.
func (v *Verifier) Binding(name string) (AccountPattern, bool) {
	p, ok := v.bindings[name]
	return p, ok
}
