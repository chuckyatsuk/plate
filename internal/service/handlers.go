package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/chuckyatsuk/plate/internal/auth"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/store"
)

// account pulls the caller's account from the verified token claim. This is the
// ONLY source of the caller's account anywhere in the service (spec Q3.A). It is
// never nil here because the auth middleware runs first and 401s a missing token.
func account(r *http.Request) string {
	c := auth.FromContext(r.Context())
	if c == nil {
		return ""
	}
	return c.Account
}

// scopeCheck enforces a required scope; scopes are first-class (spec Q3). A valid
// token that lacks the scope is a 403 — but note account isolation does NOT
// depend on scope: even a fully-scoped token is denied a cross-account resource,
// which is exactly what the conformance test proves.
func scopeCheck(w http.ResponseWriter, r *http.Request, required string) bool {
	c := auth.FromContext(r.Context())
	if c == nil || !c.HasScope(required) {
		writeError(w, http.StatusForbidden, "forbidden", "token lacks required scope")
		return false
	}
	return true
}

// denyNotFound is the leak-safe answer for any resource that is absent OR owned
// by another account — the two are indistinguishable by design (spec: NotFound
// is "No such resource for this account"). The body names nothing about any
// other account.
func denyNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "not_found", "no such resource for this account")
}

// mapStoreErr renders a store error without leaking cross-account data.
func mapStoreErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, store.ErrNotFound):
		denyNotFound(w)
	case errors.Is(err, store.ErrForeignAsset):
		// A grant over an asset the caller does not own. Deny without echoing
		// which asset was foreign.
		writeError(w, http.StatusForbidden, "forbidden", "one or more assets are not owned by this account")
	default:
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
	return true
}

// ── delivery ────────────────────────────────────────────────────────────────

func (s *Service) handleResolveDeliveryURL(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:read") {
		return
	}
	acct := account(r)
	assetID := r.PathValue("assetId")

	intent := plate.Intent(r.URL.Query().Get("intent"))
	if !validIntent(intent) {
		writeError(w, http.StatusBadRequest, "bad_request", "unknown or missing intent")
		return
	}

	// The account-scoped read: this asset must exist AND belong to the caller.
	// A B-owned asset is ErrNotFound here — the isolation boundary for delivery.
	asset, err := s.store.GetAsset(r.Context(), acct, assetID)
	if mapStoreErr(w, err) {
		return
	}

	res, err := s.urls.Resolve(intent, asset.Kind, asset.Vault.Key)
	if err != nil {
		// Unroutable kind fails loud — never a 200 to a metered CDN.
		writeError(w, http.StatusInternalServerError, "unroutable", "no delivery route for this media kind")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func validIntent(i plate.Intent) bool {
	switch i {
	case plate.Thumbnail, plate.Grid, plate.Lightbox, plate.Poster, plate.Loop, plate.Detail, plate.Original:
		return true
	}
	return false
}

// ── assets ──────────────────────────────────────────────────────────────────

func (s *Service) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:read") {
		return
	}
	asset, err := s.store.GetAsset(r.Context(), account(r), r.PathValue("assetId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

func (s *Service) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:write") {
		return
	}
	asset, err := s.store.MarkAssetDeleted(r.Context(), account(r), r.PathValue("assetId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, asset)
}

func (s *Service) handleListAssets(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:read") {
		return
	}
	limit := int32(50)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be 1..200")
			return
		}
		limit = int32(n)
	}
	page, err := s.store.ListAssets(r.Context(), account(r), r.URL.Query().Get("cursor"), limit)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// ── renditions & jobs ───────────────────────────────────────────────────────

func (s *Service) handleRequestRendition(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "renditions:generate") {
		return
	}
	acct := account(r)
	assetID := r.PathValue("assetId")

	// Confirm ownership BEFORE doing anything — a rendition request against a
	// B-owned asset must be denied like every other endpoint (spec Q4).
	owned, err := s.store.AssetOwnedBy(r.Context(), acct, assetID)
	if mapStoreErr(w, err) {
		return
	}
	if !owned {
		denyNotFound(w)
		return
	}

	var req plate.RenditionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIntent(req.Intent) {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid rendition request")
		return
	}

	asset, err := s.store.GetAsset(r.Context(), acct, assetID)
	if mapStoreErr(w, err) {
		return
	}

	// An already-existing rendition for this intent is returned as-is (idempotent
	// per (asset, intent), per the contract).
	for _, rend := range asset.Renditions {
		if rend.Intent == req.Intent {
			writeJSON(w, http.StatusOK, rend)
			return
		}
	}

	// Image intents resolve SYNCHRONOUSLY (spec §5.2): imgproxy transforms on the
	// fly from the vault original, so a ready rendition needs no generation job —
	// the delivery URL is a signed preset URL. The `original` escape hatch is
	// image-independent and also synchronous.
	if asset.Kind == plate.Image || req.Intent == plate.Original {
		writeJSON(w, http.StatusOK, plate.Rendition{
			Intent: req.Intent,
			Status: plate.RenditionStatus("ready"),
		})
		return
	}

	// A/V intents need the worker (transcode). That is PR-(b); until the worker
	// lands, an A/V rendition request is honestly reported as pending rather than
	// enqueued. The account-safety (ownership check above) already holds.
	writeJSON(w, http.StatusAccepted, plate.Rendition{
		Intent: req.Intent,
		Status: plate.RenditionStatus("pending"),
	})
}

func (s *Service) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:read") {
		return
	}
	job, err := s.store.GetJob(r.Context(), account(r), r.PathValue("jobId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// ── grants ──────────────────────────────────────────────────────────────────

func (s *Service) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "grants:manage") {
		return
	}
	var req plate.GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Assets) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid grant request")
		return
	}
	// CreateGrant verifies EVERY asset belongs to the caller; a grant over a
	// B-owned asset is refused wholesale (ErrForeignAsset → 403).
	grant, err := s.store.CreateGrant(r.Context(), account(r), req)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (s *Service) handleGetGrant(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "grants:manage") {
		return
	}
	grant, err := s.store.GetGrant(r.Context(), account(r), r.PathValue("grantId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (s *Service) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "grants:manage") {
		return
	}
	grant, err := s.store.RevokeGrant(r.Context(), account(r), r.PathValue("grantId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

// ── system ──────────────────────────────────────────────────────────────────

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, plate.Health{Status: plate.HealthStatus("ok")})
}

func (s *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	// Readiness is DB/storage reachability. Phase 1 checks nothing external here
	// beyond process liveness; a fuller check lands with the compose stack.
	writeJSON(w, http.StatusOK, plate.Health{Status: plate.HealthStatus("ok")})
}
