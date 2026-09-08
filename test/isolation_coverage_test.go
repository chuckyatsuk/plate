package plate_test

// Coverage guard for the account-isolation conformance test.
//
// "At every endpoint" (spec Q4) is only true if the endpoint TABLE the
// conformance test iterates actually equals the contract's set of secured,
// account-targeting operations. This test parses the contract and asserts
// exactly that — so a NEWLY-ADDED account-scoped endpoint that is not added to
// the isolation coverage fails the build, rather than silently shipping without
// an isolation test (which is how the "one endpoint forgot the check" bug ships).
//
// This does not need the service; it is a static check of the contract against
// the coverage list, and runs now.

import (
	"os"
	"sort"
	"testing"

	"github.com/chuckyatsuk/plate/test/support"
	"gopkg.in/yaml.v3"
)

// contractPath is the single source of truth the whole project generates from.
const contractPath = "../contract/openapi.yaml"

// securedOperationIDs parses the contract and returns the operationIds of every
// operation that requires the service token — i.e. every operation EXCEPT the
// ones that opt out with `security: []` (the health/readiness probes). These are
// exactly the operations where account isolation must be enforced.
func securedOperationIDs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading contract %s: %v", contractPath, err)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string       `yaml:"operationId"`
			Security    *[]yaml.Node `yaml:"security"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing contract yaml: %v", err)
	}

	var secured []string
	for _, methods := range doc.Paths {
		for method, op := range methods {
			// Only real HTTP methods carry operations; skip path-level keys like
			// `parameters` if any appear.
			switch method {
			case "get", "put", "post", "delete", "patch", "head", "options":
			default:
				continue
			}
			if op.OperationID == "" {
				continue
			}
			// `security: []` (an empty, non-nil list) opts the operation OUT of the
			// global security requirement. A nil Security inherits the global
			// requirement — i.e. it IS secured.
			if op.Security != nil && len(*op.Security) == 0 {
				continue
			}
			secured = append(secured, op.OperationID)
		}
	}
	sort.Strings(secured)
	return secured
}

// The isolation coverage — the account-targeting endpoints plus createUpload
// (covered by the key-prefix property) — must equal exactly the contract's
// secured operations. Not a subset: every secured operation is either
// account-targeting (in AllAccountScopedEndpoints) or createUpload.
func TestIsolationCoverage_MatchesContractSecuredOperations(t *testing.T) {
	secured := securedOperationIDs(t)

	covered := map[string]bool{}
	for _, ep := range support.AllAccountScopedEndpoints() {
		covered[string(ep)] = true
	}
	// createUpload is secured but has no target resource; it is covered by
	// TestAccountIsolation_UploadKey_ScopedToCallerAccount instead.
	covered[string(support.EpCreateUpload)] = true

	// Every secured operation must be covered.
	for _, opID := range secured {
		if !covered[opID] {
			t.Errorf("contract operation %q is secured but has NO account-isolation coverage — add it to support.AllAccountScopedEndpoints (or, if it has no account-scoped target, document why) IN THE SAME CHANGE. 'At every endpoint' (spec Q4) means every one.", opID)
		}
	}

	// And the coverage list must not name operations that don't exist in the
	// contract (a rename would otherwise leave a dead entry that looks like
	// coverage but tests nothing).
	securedSet := map[string]bool{}
	for _, opID := range secured {
		securedSet[opID] = true
	}
	for opID := range covered {
		if !securedSet[opID] {
			t.Errorf("isolation coverage names %q, which is not a secured operation in the contract — a stale entry that appears to cover an endpoint but tests nothing. Remove or rename it.", opID)
		}
	}
}

// Sanity: the health/readiness probes are correctly OUTSIDE the secured set —
// they opt out with `security: []`. If one ever loses its opt-out (or a real
// endpoint gains one by mistake), this catches it, since an unauthenticated
// data endpoint is itself an isolation hole.
func TestIsolationCoverage_OnlyProbesAreUnsecured(t *testing.T) {
	secured := map[string]bool{}
	for _, id := range securedOperationIDs(t) {
		secured[id] = true
	}
	for _, probe := range []string{"health", "ready"} {
		if secured[probe] {
			t.Errorf("%q is marked secured; it is a liveness/readiness probe and should opt out with security: []", probe)
		}
	}
	// Everything that is NOT a probe must be secured.
	allOps := []string{
		"resolveDeliveryUrl", "getAsset", "deleteAsset", "listAssets",
		"requestRendition", "getJob", "createUpload", "finalizeUpload",
		"createGrant", "getGrant", "revokeGrant",
	}
	for _, op := range allOps {
		if !secured[op] {
			t.Errorf("data/operation endpoint %q is NOT secured in the contract — an unauthenticated endpoint is an isolation hole by itself.", op)
		}
	}
}
