package service

import (
	"net/http"

	"github.com/chuckyatsuk/plate/internal/auth"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// handleProvisionAccount is PUT /v1/account (security batch item 2; tenancy
// design option A, rulings T2/T3): a NAMESPACE issuer — e.g. the registry, whose
// key is bound to "reg_*" — ensures its tenant's account exists without an
// operator running `plate accounts create`.
//
// Three gates, all required:
//  1. the token verified (the middleware), which for a bound key already means
//     the account claim is inside the key's binding;
//  2. the `accounts:provision` scope;
//  3. the key is bound by a PREFIX pattern. An unbound key could otherwise mint
//     accounts anywhere on the shared deployment, and an exact-bound key serves
//     one account an operator provisioned — neither is a namespace issuer, so
//     both are 403 even with the scope.
//
// There is no account parameter: the account created is the claim. The store
// call is INSERT … ON CONFLICT DO NOTHING, so a repeat is harmless and never
// re-configures an existing account (unlike the CLI's upsert).
func (s *Service) handleProvisionAccount(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "accounts:provision") {
		return
	}
	c := auth.FromContext(r.Context())
	if c == nil || !c.NamespaceIssuer() {
		writeError(w, http.StatusForbidden, "forbidden", "account provisioning requires a token from a namespace-bound issuer key")
		return
	}
	acct := c.Account
	// A prefix match already implies a valid AccountId; re-check so this handler
	// never depends on how the binding was matched.
	if !auth.ValidAccountID(acct) {
		writeError(w, http.StatusBadRequest, "bad_request", "account claim is not a valid account id")
		return
	}
	a, created, err := s.store.ProvisionAccount(r.Context(), acct)
	if mapStoreErr(w, err) {
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, plate.AccountProvisioning{Account: a, Created: created})
}
