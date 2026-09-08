package plate_test

// Requirement (spec Q4, the multi-client isolation note): "a test that account
// A's token cannot read account B's asset AT EVERY ENDPOINT, per-account
// bucket/key prefixes, and that test in CI — the way smoke-negative-access is
// today."
//
// Why this is the most important test in the suite, in the spec's own words:
// Files gets isolation STRUCTURALLY — one process, one DB, one bucket, no code
// path can name another artist's data. Plate deliberately trades that for ONE
// deployment with MANY accounts, so isolation is enforced by CODE, not
// architecture. The Q3.A rule — the account is a token CLAIM, never a request
// parameter — now carries the weight separate deployments used to carry. This
// test is what proves an implementation honours it.
//
// It is written NOW, before any handler exists, so it is written against the
// REQUIREMENT rather than around an implementation. It drives the
// support.AccountScopedService seam and asserts on real response shapes (denied,
// and B's data never in the body) — never on a recorded mock call. Until a real
// service registers via support.SetAccountScopedService, it SKIPS as pending:
// it fails toward "not yet proven," never toward a false green.

import (
	"strings"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/support"
)

// The victim account and a sentinel that only B's data would carry. The service
// under test seeds B's resources with these so any echo of B's data in a
// response to A is caught — including a "safe-looking" 404 whose body names B's
// storage key.
const (
	accountA     = plate.AccountId("acct-a")
	accountB     = plate.AccountId("acct-b")
	bAssetID     = "01BBBBBBBBBBBBBBBBBBBBBBBB"
	bJobID       = "01BBBBBBBBBBBBBBBBBBBBJOB0"
	bGrantID     = "01BBBBBBBBBBBBBBBBBBBGRANT"
	bKeySentinel = "acct-b/01BBBBBBBBBBBBBBBBBBBBBBBB" // B's {account}/{asset-id} storage key

	// A's own asset. The enumeration assertion (listAssets) checks BOTH
	// directions: B's data ABSENT and A's own asset PRESENT — so an implementation
	// that returns an empty list for everyone cannot pass for the wrong reason.
	aAssetID = "01AAAAAAAAAAAAAAAAAAAAAAAA"
)

// callerA is maximally privileged: it holds EVERY scope. A denial that survives
// this actor is a true account-isolation denial, not an accident of a missing
// scope (which would deny for the wrong reason and hide a missing account check).
func callerA() support.Actor {
	return support.Actor{Account: accountA, Scopes: support.AllScopes()}
}

func targetFor(ep support.EndpointID) support.Resource {
	switch ep {
	case support.EpGetJob:
		return support.Resource{Kind: support.ResourceJob, ID: bJobID, Owner: accountB}
	case support.EpGetGrant, support.EpRevokeGrant:
		return support.Resource{Kind: support.ResourceGrant, ID: bGrantID, Owner: accountB}
	default:
		// All the asset-scoped endpoints (delivery, getAsset, deleteAsset,
		// listAssets, requestRendition, finalizeUpload, createGrant-over-B's-assets)
		// target a B-owned asset.
		return support.Resource{Kind: support.ResourceAsset, ID: bAssetID, Owner: accountB}
	}
}

// TestAccountIsolation_EveryEndpoint_DeniesCrossAccount is the conformance test.
// For EVERY account-scoped endpoint, account A (fully scoped) attempting to reach
// a B-owned resource must be DENIED, and B's data must never appear in the
// response body.
func TestAccountIsolation_EveryEndpoint_DeniesCrossAccount(t *testing.T) {
	svc := support.RegisteredService()
	if svc == nil {
		t.Skip("PENDING: no AccountScopedService registered yet — this conformance test is written against the requirement (spec Q4) before any handler exists. It runs (and must pass) the moment the read-path service registers via support.SetAccountScopedService. It fails toward 'not yet proven', never a false green.")
	}

	for _, ep := range support.AllAccountScopedEndpoints() {
		ep := ep
		t.Run(string(ep), func(t *testing.T) {
			resp := svc.CallCrossAccount(ep, callerA(), targetFor(ep))

			switch support.ShapeOf(ep) {
			case support.ShapeScopedEnumeration:
				// An enumeration endpoint (listAssets) has no cross-account target:
				// correct isolation is a 200 whose result set contains ONLY the
				// caller's own data. A denial here would be a FAILURE, not a pass.
				if resp.Status < 200 || resp.Status >= 300 {
					t.Fatalf("%s: enumeration of the caller's OWN resources should succeed (2xx); got HTTP %d. Listing your own assets is not a cross-account access and must not be denied.", ep, resp.Status)
				}
				// The leak that actually happens on a list endpoint: a query that
				// forgot `WHERE account = $claim` and returned B's rows too.
				if support.LeaksAccountData(resp.Body, accountB, bKeySentinel, bAssetID, bJobID, bGrantID) {
					t.Fatalf("%s: account A's listing contained account B's data (status %d) — the result set was not scoped to the caller (a missing `WHERE account = $claim`). Body: %q", ep, resp.Status, string(resp.Body))
				}
				// And it must actually contain A's own asset — otherwise "no B data"
				// is a vacuous pass on an empty list for everyone.
				if !containsStr(resp.Body, aAssetID) {
					t.Fatalf("%s: account A's listing did not contain A's own asset %q (status %d) — assert BOTH directions so an empty-list-for-everyone implementation cannot pass. Body: %q", ep, aAssetID, resp.Status, string(resp.Body))
				}

			default: // ShapeDenyTarget
				if !support.IsDenied(resp.Status) {
					t.Fatalf("%s: account A reached a B-owned resource — HTTP %d, expected a denial (403/404). This is the worst bug this architecture can have: a code-enforced boundary that was not enforced on THIS endpoint (spec Q4).", ep, resp.Status)
				}
				if support.LeaksAccountData(resp.Body, accountB, bKeySentinel, bAssetID, bJobID, bGrantID) {
					t.Fatalf("%s: response to account A contained account B's data (status %d) — even a leak-safe 404 must not echo B's account, key, or ids. Body: %q", ep, resp.Status, string(resp.Body))
				}
			}
		})
	}
}

// containsStr is a tiny helper for the enumeration "A present" assertion.
func containsStr(body []byte, s string) bool {
	return strings.Contains(string(body), s)
}

// createUpload has no target resource — it creates under the CALLER's account —
// so its isolation property is the per-account key prefix (spec Q4: "per-account
// bucket/key prefixes"). Even if a caller tries to smuggle another account into
// the request, the minted key MUST be prefixed by the caller's OWN account claim.
func TestAccountIsolation_UploadKey_ScopedToCallerAccount(t *testing.T) {
	svc := support.RegisteredService()
	if svc == nil {
		t.Skip("PENDING: no AccountScopedService registered yet — see TestAccountIsolation_EveryEndpoint_DeniesCrossAccount.")
	}

	// A (fully scoped) requests an upload, trying to hint account B. The key must
	// still be prefixed with A's account, never B's.
	key, resp := svc.MintUploadKey(callerA(), accountB)

	if resp.Status < 200 || resp.Status >= 300 {
		// A denial is also acceptable (e.g. if hinting another account is rejected
		// outright). What must NEVER happen is a success that mints a B-prefixed key.
		return
	}
	if !hasAccountPrefix(key, accountA) {
		t.Fatalf("createUpload minted key %q for a caller on account %q — the key must be prefixed by the CALLER's account claim, never a requested account (spec §3.3, Q4 per-account key prefixes). This is how one account writes into another's bucket path.", key, accountA)
	}
	if hasAccountPrefix(key, accountB) {
		t.Fatalf("createUpload minted a key prefixed with account B (%q) for a caller on account A — a request hint overrode the token claim, which is exactly the cross-tenant leak Q3.A forbids.", key)
	}
}

func hasAccountPrefix(key string, account plate.AccountId) bool {
	prefix := string(account) + "/"
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}
