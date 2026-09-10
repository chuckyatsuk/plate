package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/store"
)

// ownerOriginalSentinel is the "grant id" an owner's `original` download is
// signed with. It is NOT a real grant — it marks the URL as the owner front
// door, so an original signature and a granted signature are cryptographically
// distinct: a grant id can never verify an original download, and this sentinel
// can never verify a granted one. The download handler routes on the query
// intent/grant and re-derives which one to verify against, so a forged swap
// fails the HMAC. The value is fixed and non-secret (the key is the secret).
const ownerOriginalSentinel = "\x00owner-original"

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

	// Granted mode (spec Q3.B): a `grant` param means "serve this only if grant G
	// still permits it." Unlike public/signed, this puts a live per-request check
	// in the hot path — the whole point is that revocation and expiry actually
	// stop the URL working. Handle it entirely here and return; it resolves the
	// asset under the GRANT's account, not the caller's.
	if grantID := r.URL.Query().Get("grant"); grantID != "" {
		s.resolveGranted(w, r, grantID, assetID, intent)
		return
	}

	// The account-scoped read: this asset must exist AND belong to the caller.
	// A B-owned asset is ErrNotFound here — the isolation boundary for delivery.
	asset, err := s.store.GetAsset(r.Context(), acct, assetID)
	if mapStoreErr(w, err) {
		return
	}

	// original is the named escape hatch (spec §4.1): a short-lived authenticated
	// download URL, independent of rendition state — it resolves even while an A/V
	// asset is still probing. It is the OWNER's front door to raw bytes (the caller
	// here is token-authenticated and owns the asset, checked just above), so it is
	// signed with the owner sentinel, NOT a grant — a grant can never mint one
	// (that refusal lives in resolveGranted). This closes the former
	// known-forgeable ?sig=… placeholder: the URL is now a real HMAC capability
	// the /v1/download handler verifies.
	if intent == plate.Original {
		if s.signer == nil {
			writeError(w, http.StatusServiceUnavailable, "unconfigured", "original download requires PLATE_DELIVERY_SIGNING_KEY")
			return
		}
		exp := time.Now().Add(s.grantURLTTL)
		// intent=original travels in the URL; NO grant param (an original is never
		// granted). handleDownload verifies against the owner sentinel.
		base := s.urls.DownloadBase + "/v1/download/" + asset.Vault.Key +
			"?intent=" + url.QueryEscape(string(plate.Original))
		writeJSON(w, http.StatusOK, plate.DeliveryResolution{
			Intent: plate.Original,
			Delivery: &plate.Delivery{
				Url:     s.signer.sign(base, string(plate.Original), ownerOriginalSentinel, exp),
				Mode:    plate.Signed,
				Expires: &exp,
			},
		})
		return
	}

	writeJSON(w, http.StatusOK, s.resolveNonOriginal(intent, asset))
}

// resolveGranted serves granted-mode delivery (spec Q3.B). The grant is the
// capability: it is resolved by id (carrying its own account), checked live
// (not revoked, not expired, covers this asset) through the short-TTL cache,
// and — if live — turned into a SIGNED, short-expiry URL wrapped as mode:granted.
//
// Refusal is the leak-safe honest refusal (§4.3): a not-found, not-covered,
// revoked, or expired grant all collapse to delivery:null + reason:unauthorized
// (HTTP 200), so a recipient cannot distinguish "no such grant" from "revoked"
// from "not in this set" — the contract's stated meaning of `unauthorized`.
func (s *Service) resolveGranted(w http.ResponseWriter, r *http.Request, grantID, assetID string, intent plate.Intent) {
	unauthorized := func() {
		reason := plate.ReasonCodeUnauthorized
		writeJSON(w, http.StatusOK, plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &reason})
	}

	// original is not a granted-delivery intent: it is the owner's authenticated
	// escape hatch, never handed to a share-link recipient. A grant signature must
	// NEVER mint an `original` (raw-bytes) download — this refusal is the boundary,
	// pinned at the grant ENTRY check so it cannot erode into the shared /download
	// tail. (Test: a valid granted sig with intent=original is refused.)
	if intent == plate.Original {
		unauthorized()
		return
	}

	verdict, err := s.grants.resolve(r.Context(), s.store, grantID, assetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not resolve grant")
		return
	}
	if !verdict.Live() {
		unauthorized()
		return
	}

	// The grant is live and covers this asset. Resolve the asset under the
	// GRANT's account (never the request's) — a grant only ever covers its own
	// account's assets (CreateGrant enforced that at issue), so this both builds
	// the right key space and re-confirms the asset still exists.
	asset, err := s.store.GetAsset(r.Context(), verdict.Account, assetID)
	if err != nil {
		// The asset was deleted after the grant was issued (or any read error):
		// nothing to deliver. Treat as the honest refusal, not a 500 leak.
		unauthorized()
		return
	}

	res := s.resolveNonOriginal(intent, asset)
	// A pending/failed/unroutable underlying rendition carries its own reason
	// (pending, exceeded_*, unsupported_format) — pass it through unchanged; the
	// grant is fine, the rendition simply is not ready. Only a resolvable URL gets
	// wrapped as granted + enforced.
	if res.Delivery == nil {
		writeJSON(w, http.StatusOK, res)
		return
	}
	signed, ok := s.enforceGranted(res.Delivery, asset, grantID, intent)
	if !ok {
		// No enforcement mechanism configured for this kind (no imgproxy signer for
		// an image, or no download signer for A/V): refuse rather than ship an
		// unenforced "granted" URL (fail closed — the whole point of the mode).
		writeError(w, http.StatusServiceUnavailable, "unconfigured", "granted-mode delivery is not configured for this media kind (need imgproxy signing keys for images, PLATE_DELIVERY_SIGNING_KEY for A/V)")
		return
	}
	res.Delivery = signed
	writeJSON(w, http.StatusOK, res)
}

// enforceGranted turns a resolved (public) delivery into an ENFORCED granted
// delivery, by media kind (spec Q3.B guidance):
//   - images → an imgproxy-SIGNED URL with `exp`; imgproxy rejects expired/
//     tampered requests at the byte edge (Plate never touches image bytes, Q5).
//     Enforcement is expiry+tamper only — imgproxy has no grant concept, so a
//     revoked granted image stays loadable until expiry (the capped asymmetry).
//   - A/V → a Plate /v1/download URL, HMAC-signed over the rendition key+intent+
//     grant+exp. When the recipient fetches it, handleDownload re-checks grant
//     LIVENESS (so revocation kills issued A/V URLs within one cache window) and
//     302-redirects to a short-lived R2 presigned GET.
//
// Returns ok=false when the required signer for this kind is absent (fail closed).
func (s *Service) enforceGranted(d *plate.Delivery, asset plate.Asset, grantID string, intent plate.Intent) (*plate.Delivery, bool) {
	exp := time.Now().Add(s.grantURLTTL)
	d.Mode = plate.Granted
	d.Expires = &exp

	switch asset.Kind {
	case plate.Image:
		if s.imgsigner == nil {
			return nil, false
		}
		// Granted image: an imgproxy-signed URL WITH expiry (imgproxy enforces the
		// exp; grant liveness can't be checked at imgproxy — the capped asymmetry).
		u, ok := s.signedImageURL(string(intent), asset.Vault.Key, &exp)
		if !ok {
			return nil, false
		}
		d.Url = u
		return d, true
	case plate.Document:
		// Documents pass through R2 like A/V (the base d.Url is already the public
		// delivery-prefix URL); granted enforcement for them rides the same path as
		// A/V below rather than imgproxy.
		if s.signer == nil {
			return nil, false
		}
		rendKey := id.RenditionKey(asset.Vault.Key, string(intent))
		base := s.urls.DownloadBase + "/v1/download/" + rendKey +
			"?intent=" + url.QueryEscape(string(intent)) + "&grant=" + url.QueryEscape(grantID)
		d.Url = s.signer.sign(base, string(intent), grantID, exp)
		return d, true
	default: // video/audio → the /download redirect, verified + liveness-checked
		if s.signer == nil {
			return nil, false
		}
		rendKey := id.RenditionKey(asset.Vault.Key, string(intent))
		// intent + grant travel IN the URL so the recipient's fetch carries them to
		// handleDownload; the signature covers the path (which binds them too), so
		// they cannot be swapped without breaking the signature.
		base := s.urls.DownloadBase + "/v1/download/" + rendKey +
			"?intent=" + url.QueryEscape(string(intent)) + "&grant=" + url.QueryEscape(grantID)
		d.Url = s.signer.sign(base, string(intent), grantID, exp)
		return d, true
	}
}

// handleDownload is the signature-enforcing byte-edge for A/V (granted mode) and
// for the owner's `original` escape hatch. It is mounted OUTSIDE the token
// middleware: the HMAC signature IS the authorization (the URL is a bearer
// capability). It verifies the signature, then:
//   - for `original`: nothing more — a valid owner-sentinel signature is the
//     owner's own short-lived capability (they were token-authenticated when it
//     was issued).
//   - for a granted A/V intent: RE-CHECKS grant liveness through the cache, so a
//     revoked/expired grant stops an ALREADY-ISSUED URL from resolving within one
//     cache window (spec Q3.B guarantee ii).
// On success it mints a short (30–60s) R2 presigned GET and 302-redirects, with
// Cache-Control: private, no-store so no CDN hands one presigned URL to many
// viewers. Plate sees a tiny request; R2 serves the bytes (Q5).
//
// Every failure is a flat 403 with no body detail — this edge is reached by
// recipients, and a "revoked" vs "expired" vs "bad signature" distinction here
// would leak grant state.
func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, "forbidden", http.StatusForbidden) }

	if s.signer == nil || s.storage == nil {
		// No signer means no URL we issued can be valid here; no storage means we
		// cannot presign. Either way there is nothing legitimate to serve.
		deny()
		return
	}

	key := r.PathValue("key")
	q := r.URL.Query()
	intent := q.Get("intent")
	grantID := q.Get("grant")
	if key == "" || intent == "" {
		deny()
		return
	}

	// Reconstruct the exact URL string that was signed and verify it. Using the
	// configured DownloadBase (not the request's host) means the signature is
	// checked against what Plate minted, independent of how the request arrived.
	signedURL := s.urls.DownloadBase + "/v1/download/" + key + "?" + r.URL.RawQuery

	if intent == string(plate.Original) {
		// Owner front door: verified against the owner sentinel, never a grant. A
		// grant-signed URL therefore cannot pull an original (its grantID won't be
		// the sentinel), and this cannot pull a rendition it was not signed for.
		if grantID != "" || !s.signer.verify(signedURL, intent, ownerOriginalSentinel) {
			deny()
			return
		}
	} else {
		// Granted A/V: signature must verify AND the grant must still be live NOW.
		if grantID == "" || !s.signer.verify(signedURL, intent, grantID) {
			deny()
			return
		}
		// The signed key is {account}/{asset-id}/{intent}; the asset id is the
		// middle segment. Re-check liveness against that asset (revocation kills
		// issued URLs, spec Q3.B/ii).
		assetID := assetIDFromRenditionKey(key)
		if assetID == "" {
			deny()
			return
		}
		verdict, err := s.grants.resolve(r.Context(), s.store, grantID, assetID)
		if err != nil || !verdict.Live() {
			deny()
			return
		}
	}

	// Mint a SHORT presigned GET — long enough to survive the redirect hop, not
	// the whole transfer (R2 checks expiry at transfer start, so an in-flight
	// download completes). A leaked presigned URL's window is therefore tiny.
	target, err := s.storage.PresignGet(r.Context(), key, 45*time.Second)
	if err != nil {
		deny()
		return
	}
	// private, no-store: the 302 names a one-time presigned URL; a CDN must never
	// cache it and hand the same URL to another viewer.
	w.Header().Set("Cache-Control", "private, no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// signedImageURL builds the imgproxy-signed delivery URL for an image intent:
// an imgproxy URL whose SOURCE is the PRIVATE S3 vault original
// (s3://{bucket}/vault/...), never the public base — so imgproxy reads the
// original with its own R2 credentials and the vault is never publicly reachable
// (the wall, spec §3.1/Q5). Because imgproxy checks ALL URLs once keyed, EVERY
// image URL is signed — public (exp nil: stable, cacheable) and granted (exp set:
// imgproxy enforces the window). Returns ok=false when imgproxy signing or the
// source bucket is not configured (fail closed — no unsigned image URL ships).
func (s *Service) signedImageURL(intent, vaultKey string, exp *time.Time) (string, bool) {
	if s.imgsigner == nil {
		return "", false
	}
	src := s.urls.imgproxySource(vaultKey)
	if src == "" {
		return "", false
	}
	return s.imgsigner.signedImageURL(s.urls.ImageCDNBase, intent, src, exp), true
}

// assetIDFromRenditionKey extracts the asset id from a rendition key. Since the
// vault/delivery split, that key is `delivery/{account}/{asset-id}/{intent}`
// (4 segments) and the vault key is `vault/{account}/{asset-id}` (3). Accept both
// shapes and return the asset id (second-to-last for a rendition, last for a
// vault key), or "" if the shape is unrecognized. Used by the download edge to
// re-check grant liveness against the asset the signed key names.
func assetIDFromRenditionKey(key string) string {
	parts := strings.Split(key, "/")
	switch {
	case len(parts) == 4 && parts[0] == id.DeliveryPrefix[:len(id.DeliveryPrefix)-1]:
		return parts[2] // delivery/{account}/{asset}/{intent}
	case len(parts) == 3 && parts[0] == id.VaultPrefix[:len(id.VaultPrefix)-1]:
		return parts[2] // vault/{account}/{asset} (original download)
	}
	return ""
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
	// Images resolve immediately (imgproxy transforms the vault original on the
	// fly — no rendition row needed). PUBLIC images are still imgproxy-SIGNED (exp
	// nil: stable + cacheable) because imgproxy checks all URLs once keyed; the
	// signature is tamper-protection on the transform params, not access control.
	if asset.Kind == plate.Image {
		u, ok := s.signedImageURL(string(intent), asset.Vault.Key, nil)
		if !ok {
			// No imgproxy signing / source configured → cannot serve an image.
			reason := plate.ReasonCodeUnsupportedFormat
			return plate.DeliveryResolution{Intent: intent, Delivery: nil, Reason: &reason}
		}
		return plate.DeliveryResolution{
			Intent:   intent,
			Delivery: &plate.Delivery{Url: u, Mode: plate.Public},
		}
	}
	// Documents pass through R2 directly (no transform) — the public delivery URL.
	if asset.Kind == plate.Document {
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
	case plate.Thumbnail, plate.Grid, plate.Lightbox, plate.Poster, plate.Loop, plate.Detail, plate.Original,
		plate.Zoom1, plate.Zoom2, plate.Zoom3: // image deep-zoom ladder (Phase 3 A2)
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
