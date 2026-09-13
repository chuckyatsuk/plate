package service

// Exports (Tier 1: the export capability) — the OWNER's long-lived counterpart
// to a grant: a first-class, revocable record over a frozen set of assets that
// yields signed download URLs for their ORIGINAL bytes (an archive, a media
// manifest, a handover). It exists so a consumer's long-lived export links have
// a Plate-native shape instead of reaching around Plate to storage directly —
// the capability that gates removing R2-direct from Files (roadmap Tier 1 → 3c).
//
// Three deliberate differences from the neighbouring byte routes:
//   - Owner-auth, own scope (`assets:export`). A grant can never mint an export
//     URL and an export URL can never serve a non-original rendition — the
//     signatures are cryptographically distinct (exportSigContext), the same
//     discipline that separates owner-original from granted.
//   - Long TTL with a hard cap (ExportMaxTTL). "Long-lived" must never quietly
//     mean "forever"; past the cap is a 400 at issue, not a config knob that can
//     silently create an unbounded window.
//   - Revocation is IMMEDIATE at the byte edge. Unlike grants (whose short-TTL
//     verdict cache is an explicit hot-path trade for 197-tile pages), an export
//     download is low-volume raw-bytes fetching, so every fetch re-checks the
//     row live — no cache, no eventual-consistency window. The storage-presigned
//     hop behind the redirect stays seconds-short either way.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// ExportMaxTTL hard-caps how far out an export may expire. The contract states
// the cap (30 days); a request past it is refused at issue so a long-lived
// capability is always bounded. Revocation covers everything shorter.
const ExportMaxTTL = 30 * 24 * time.Hour

// exportSigContext is the value signed into an export URL where a granted URL
// carries its grant id and an owner original carries ownerOriginalSentinel. The
// NUL framing keeps it outside the id alphabet, so the three capability kinds
// can never verify one another's URLs (the key is shared; the context is what
// separates the domains).
func exportSigContext(exportID string) string {
	return "\x00export\x00" + exportID
}

// exportDownloads derives the per-asset signed download URLs for a live export.
// Derived, never stored: the URL is a pure function of (export id, asset set,
// expiry) over the signing key, so a read can always rebuild it and a dead
// export never has a stored URL to leak. Returns nil when no signer is
// configured (the create handler refuses before a row exists; get simply omits).
func (s *Service) exportDownloads(e plate.Export) []plate.ExportDownload {
	if s.signer == nil {
		return nil
	}
	out := make([]plate.ExportDownload, 0, len(e.Assets))
	for _, assetID := range e.Assets {
		// The signed path names the VAULT key — an export is the owner's route to
		// original bytes, same tier as intent=original, never a rendition.
		vaultKey := id.VaultKey(string(e.Account), assetID)
		base := s.urls.DownloadBase + "/v1/download/" + vaultKey +
			"?export=" + url.QueryEscape(e.Id) +
			"&intent=" + url.QueryEscape(string(plate.Original))
		out = append(out, plate.ExportDownload{
			Asset:   assetID,
			Url:     s.signer.sign(base, string(plate.Original), exportSigContext(e.Id), e.Expires),
			Expires: e.Expires,
		})
	}
	return out
}

// exportLive reports whether the export can serve downloads right now — not
// revoked and not expired. Kept next to the derivation so "live" cannot drift
// between the read path and the download edge's SQL verdict.
func exportLive(e plate.Export, now time.Time) bool {
	return e.RevokedAt == nil && now.Before(e.Expires)
}

// withDownloads attaches the derived download URLs when the export is live and
// signing is configured; a revoked or expired export is returned bare, so
// reading it can never resurrect the capability.
func (s *Service) withDownloads(e plate.Export) plate.Export {
	if exportLive(e, time.Now()) {
		if d := s.exportDownloads(e); d != nil {
			e.Downloads = &d
		}
	}
	return e
}

func (s *Service) handleCreateExport(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:export") {
		return
	}
	// Fail closed BEFORE creating anything: an export without a signer could
	// never produce a working URL, and a row that silently can't deliver is the
	// dishonest shape (same discipline as granted-mode's 503).
	if s.signer == nil {
		writeError(w, http.StatusServiceUnavailable, "unconfigured", "exports require PLATE_DELIVERY_SIGNING_KEY")
		return
	}
	var req plate.ExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Assets) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid export request")
		return
	}
	now := time.Now()
	if !req.Expires.After(now) {
		writeError(w, http.StatusBadRequest, "bad_request", "expires must be in the future")
		return
	}
	if req.Expires.After(now.Add(ExportMaxTTL)) {
		writeError(w, http.StatusBadRequest, "bad_request", "expires exceeds the 30-day export cap")
		return
	}
	// CreateExport verifies EVERY asset belongs to the caller; an export over a
	// foreign asset is refused wholesale (ErrForeignAsset → 403), like grants.
	export, err := s.store.CreateExport(r.Context(), account(r), req)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, s.withDownloads(export))
}

func (s *Service) handleGetExport(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:export") {
		return
	}
	export, err := s.store.GetExport(r.Context(), account(r), r.PathValue("exportId"))
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, s.withDownloads(export))
}

func (s *Service) handleRevokeExport(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:export") {
		return
	}
	export, err := s.store.RevokeExport(r.Context(), account(r), r.PathValue("exportId"))
	if mapStoreErr(w, err) {
		return
	}
	// Revoked: returned bare — withDownloads would refuse anyway, but the intent
	// deserves to be legible at the call site.
	writeJSON(w, http.StatusOK, export)
}
