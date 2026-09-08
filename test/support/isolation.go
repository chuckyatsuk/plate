package support

import (
	"strings"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// This file defines the SEAM for the cross-account isolation conformance test
// (spec Q4). It is the single most important boundary in Plate's architecture:
// Files gets isolation structurally (separate process, DB, bucket, no code path
// can name another artist's data). Plate deliberately trades that for ONE
// deployment with MANY accounts — so isolation is enforced by CODE, and the
// Q3.A rule ("the account is a token CLAIM, never a request parameter") now
// carries the weight separate deployments used to carry.
//
// The spec is explicit that the guard is a test "that account A's token cannot
// read account B's asset AT EVERY ENDPOINT, per-account bucket/key prefixes, and
// that test in CI — the way smoke-negative-access is today."
//
// The test drives this interface, not a mock. When the real service lands it
// implements AccountScopedService by wrapping its HTTP handlers; the assertions
// (denied, and B's data never in the body) hold unchanged, because they check a
// real response shape, not a recorded call. Until a service registers via
// SetAccountScopedService, the conformance test SKIPS (pending), so it fails
// toward "not yet proven," never toward a false green.

// Scope mirrors the contract's `Scope` enum. The contract defines it as a named
// schema referenced only from the securityScheme description (it lives in the
// JWT, not in any body), so oapi-codegen's type generation does not emit a Go
// type for it (see redocly.yaml, no-unused-components). We restate the closed
// set here so a test can construct a fully-scoped actor — a cross-account denial
// must hold even when the caller HAS the scope, or the test would pass for the
// wrong reason (missing scope) and hide a missing account check.
type Scope string

const (
	ScopeAssetsRead         Scope = "assets:read"
	ScopeAssetsWrite        Scope = "assets:write"
	ScopeRenditionsGenerate Scope = "renditions:generate"
	ScopeGrantsManage       Scope = "grants:manage"
)

// AllScopes is the full set — a maximally-privileged token. A denial that holds
// for THIS actor is a true account-isolation denial, not an accident of scope.
func AllScopes() []Scope {
	return []Scope{ScopeAssetsRead, ScopeAssetsWrite, ScopeRenditionsGenerate, ScopeGrantsManage}
}

// Actor identifies a caller by the account claim inside its (real, in
// production) service JWT. The test constructs actors for accounts A and B; the
// point is that the account travels as the token's claim, and the service must
// derive scope from it — never from a parameter.
type Actor struct {
	// Account is the value of the token's `account` claim.
	Account plate.AccountId
	// Scopes the token carries. A cross-account denial must hold even when the
	// caller has every scope — lacking scope would deny for the WRONG reason and
	// hide a missing account check.
	Scopes []Scope
}

// Resource is a target owned by some account. The conformance test creates
// resources owned by B and calls every endpoint as A.
type Resource struct {
	Kind  ResourceKind
	ID    string
	Owner plate.AccountId
}

type ResourceKind int

const (
	ResourceAsset ResourceKind = iota
	ResourceJob
	ResourceGrant
	ResourceUpload
)

// ConformanceResponse is the shape an endpoint call returns: the HTTP status and
// the response body as bytes. The isolation assertions look at BOTH — a denial
// status is necessary but not sufficient; the body must also never contain the
// victim account's data (a 200 that leaks, or even a 404 whose body echoes B's
// key, is a failure).
type ConformanceResponse struct {
	Status int
	Body   []byte
}

// EndpointID names each account-scoped operation from the contract, so the test
// table is exhaustive and a newly-added endpoint that is not covered is visible.
type EndpointID string

const (
	EpResolveDeliveryUrl EndpointID = "resolveDeliveryUrl"
	EpGetAsset           EndpointID = "getAsset"
	EpDeleteAsset        EndpointID = "deleteAsset"
	EpListAssets         EndpointID = "listAssets"
	EpRequestRendition   EndpointID = "requestRendition"
	EpGetJob             EndpointID = "getJob"
	EpFinalizeUpload     EndpointID = "finalizeUpload"
	EpCreateUpload       EndpointID = "createUpload"
	EpCreateGrant        EndpointID = "createGrant"
	EpGetGrant           EndpointID = "getGrant"
	EpRevokeGrant        EndpointID = "revokeGrant"
)

// AccountScopedService is what the real service implements to be conformance-
// tested. Each method performs the named endpoint's operation AS the given actor
// AGAINST the given (B-owned) resource, returning the real response.
//
// The test never inspects HOW isolation is enforced — only the response. That is
// the whole point: an implementation that forgets the check on one endpoint is
// caught by a real denied/leak assertion, not by a recorded-call expectation.
type AccountScopedService interface {
	// CallCrossAccount performs `endpoint` as `caller` against `target` (owned by
	// another account) and returns the response.
	CallCrossAccount(endpoint EndpointID, caller Actor, target Resource) ConformanceResponse

	// MintUploadKey performs createUpload as `caller`. createUpload has no target
	// resource — it creates under the caller's OWN account — so its isolation
	// property is different: the storage key it returns MUST be prefixed by the
	// caller's account, never by any account named in the request. Returns the
	// storage key the presigned PUT is bound to.
	MintUploadKey(caller Actor, requestedAccountHint plate.AccountId) (key string, resp ConformanceResponse)
}

// registeredService is set by the real implementation (from its own package's
// tests, or a wiring file) once it exists. Nil until then.
var registeredService AccountScopedService

// SetAccountScopedService registers the implementation under test. The real
// service calls this from a test wiring point; until then the conformance test
// skips-pending.
func SetAccountScopedService(s AccountScopedService) { registeredService = s }

// RegisteredService returns the implementation under test, or nil if none is
// registered yet (the conformance test then skips-pending rather than passing).
func RegisteredService() AccountScopedService { return registeredService }

// AllAccountScopedEndpoints is the exhaustive list of endpoints that target a
// resource owned by an account — every secured operation EXCEPT createUpload,
// which has no target (it is covered by the MintUploadKey property instead). If
// the contract grows an account-scoped endpoint, add it here; the test asserts
// this list against the contract's operation set so an omission is visible.
func AllAccountScopedEndpoints() []EndpointID {
	return []EndpointID{
		EpResolveDeliveryUrl,
		EpGetAsset,
		EpDeleteAsset,
		EpListAssets,
		EpRequestRendition,
		EpGetJob,
		EpFinalizeUpload,
		EpCreateGrant, // grant over B's assets must be refused
		EpGetGrant,
		EpRevokeGrant,
	}
}

// IsDenied reports whether a response denied the cross-account access. Per the
// contract, the boundary is a 403 (token valid, account claim does not match the
// target — spec Q3.A / the Forbidden response) or a 404 ("No such resource for
// THIS account" — the contract's NotFound description, which is the leak-safe way
// to answer for a resource the caller may not even know exists). Both are
// acceptable; a 2xx is never.
func IsDenied(status int) bool {
	return status == 403 || status == 404 || status == 401
}

// LeaksAccountData reports whether a response body contains a marker that only
// the victim account's data would carry. The test seeds B's resources with a
// recognizable token (its account id and a sentinel in the key/checksum) so any
// echo of B's data in a body returned to A is caught — including a "safe-looking"
// 404 whose message names B's key.
func LeaksAccountData(body []byte, victim plate.AccountId, sentinels ...string) bool {
	s := string(body)
	if victim != "" && strings.Contains(s, string(victim)) {
		return true
	}
	for _, sen := range sentinels {
		if sen != "" && strings.Contains(s, sen) {
			return true
		}
	}
	return false
}
