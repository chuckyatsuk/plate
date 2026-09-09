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

	// Granted-mode enforcement is NOT built yet (review ruling 3): a `grant` param
	// means the caller wants granted delivery, which requires a live per-request
	// grant check we have not implemented. Returning a working URL here would be a
	// URL that ignores revocation — the exact "copied link works forever" failure
	// grants exist to kill. So refuse loudly with 501 rather than silently degrade
	// to public. (signed mode is likewise not caller-selectable yet.)
	if r.URL.Query().Get("grant") != "" {
		writeError(w, http.StatusNotImplemented, "not_implemented", "granted-mode delivery is not yet implemented")
		return
	}

	// The account-scoped read: this asset must exist AND belong to the caller.
	// A B-owned asset is ErrNotFound here — the isolation boundary for delivery.
	asset, err := s.store.GetAsset(r.Context(), acct, assetID)
	if mapStoreErr(w, err) {
		return
	}

	// original is the named escape hatch (spec §4.1): a short-lived authenticated
	// download URL, independent of rendition state. It resolves even while an A/V
	// asset is still probing. NOTE: its signature is a KNOWN-FORGEABLE placeholder
	// until delivery signing lands (review ruling 3); a test pins that it is
	// currently unsigned so this cannot be mistaken for done.
	if intent == plate.Original {
		res, rerr := s.urls.Resolve(intent, asset.Kind, asset.Vault.Key)
		if rerr != nil {
			writeError(w, http.StatusInternalServerError, "unroutable", "no delivery route for this media kind")
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	writeJSON(w, http.StatusOK, s.resolveNonOriginal(intent, asset))
}

// resolveNonOriginal resolves a non-original intent against the asset's real
// rendition/probe state (review ruling 1 — delivery-side ceiling + readiness).
//
//   - image intents: imgproxy transforms on the fly from the vault original, so a
//     ready image asset resolves immediately (no rendition row needed).
//   - A/V intents (loop/detail): require a rendition. ready → URL; failed →
//     delivery:null + the rendition's reason (the §4.3 honest refusal, e.g.
//     exceeded_duration_ceiling); pending/absent → delivery:null, reason:pending.
func (s *Service) resolveNonOriginal(intent plate.Intent, asset plate.Asset) plate.DeliveryResolution {
	// A failed/pending PROBE blocks everything derived from the object.
	// (probe_status lives on the asset; exposed via the store as a field.)
	if asset.Kind == plate.Image || asset.Kind == plate.Document {
		res, err := s.urls.Resolve(intent, asset.Kind, asset.Vault.Key)
		if err != nil {
			reason := plate.ReasonCodeUnsupportedFormat
			return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &reason}
		}
		return res
	}

	// A/V: find the rendition for this intent.
	for _, rend := range asset.Renditions {
		if rend.Intent != intent {
			continue
		}
		switch rend.Status {
		case plate.RenditionStatus("ready"):
			res, err := s.urls.Resolve(intent, asset.Kind, asset.Vault.Key)
			if err != nil {
				reason := plate.ReasonCodeUnsupportedFormat
				return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &reason}
			}
			return res
		case plate.RenditionStatus("failed"):
			// The honest refusal — carry the rendition's closed-enum reason.
			return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: rend.Reason}
		default: // pending
			pending := plate.ReasonCodePending
			return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &pending}
		}
	}
	// No rendition yet (worker hasn't produced it) → pending.
	pending := plate.ReasonCodePending
	return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &pending}
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

	// A/V intents need the worker (transcode): enqueue a job and return 202 with
	// its state (spec §5.2). Idempotent per (asset, intent). The ownership check
	// above already established account-safety.
	job, err := s.store.EnqueueJob(r.Context(), acct, assetID, req.Intent)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, job)
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
