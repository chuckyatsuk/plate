package service

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// handleCreateUpload brokers a direct upload (spec §5.1): it mints a presigned
// PUT the browser uses to write ONE object direct to R2. Plate never streams the
// bytes.
//
// Its isolation property is different from the read endpoints: there is no target
// resource — the upload is created under the CALLER's account. The key it mints
// MUST be prefixed by the caller's account claim, `{account}/{asset-id}`, never
// by any account named in the request. Plate owns key generation outright
// (spec §3.3); the caller does not choose the key. This is the "per-account
// bucket/key prefixes" half of the Q4 isolation requirement, and the reason one
// account cannot write into another's bucket path.
func (s *Service) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:write") {
		return
	}
	acct := account(r) // the ONLY source of the account — the token claim.

	var req plate.UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ContentType == "" || req.SizeBytes < 1 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid upload request")
		return
	}

	// Mint the id and the key from the caller's account. Any account a caller
	// tries to smuggle in the body is structurally ignored: the key is built from
	// acct, full stop. UploadRequest has no account field precisely so this cannot
	// be expressed — but even if it could, we would ignore it here.
	assetID := id.New()
	key := id.VaultKey(acct, assetID) // {account}/{asset-id}

	ticket := plate.UploadTicket{
		UploadId: assetID,
		// Phase 1 constructs the presigned PUT URL as a string bound to the key;
		// no bytes flow through Plate. The real R2 presign lands with the write
		// path (Phase 2); the key-prefix invariant proven here does not change.
		Url:    s.urls.R2PublicBase + "/" + key,
		Method: plate.UploadTicketMethod("PUT"),
		Headers: []plate.Header{
			{Name: "Content-Type", Value: req.ContentType},
		},
		Expires: time.Now().Add(time.Hour), // generous for a studio's slow line (spec Q3.C)
	}
	writeJSON(w, http.StatusCreated, ticket)
}

// handleFinalizeUpload registers the vault object after a successful PUT (spec
// §5.1). The write path proper (checksum, probe, promote) is Phase 2; Phase 1
// implements only the account-isolation boundary the conformance test requires:
// an upload id is minted as the asset id under the caller's account, so
// finalizing an id owned by ANOTHER account must be denied. We treat the
// uploadId as an asset id and require it to belong to the caller — a B-owned id
// is not finalizable by A.
func (s *Service) handleFinalizeUpload(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:write") {
		return
	}
	acct := account(r)
	uploadID := r.PathValue("uploadId")

	var req plate.FinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Checksum == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid finalize request")
		return
	}

	// Account-isolation guard: the upload/asset id must belong to the caller.
	// A B-owned id is denied (leak-safe 404), never finalized cross-account.
	owned, err := s.store.AssetOwnedBy(r.Context(), acct, uploadID)
	if mapStoreErr(w, err) {
		return
	}
	if !owned {
		denyNotFound(w)
		return
	}
	// The full finalize (probe, promote, ceiling refusal) is Phase 2. Return the
	// account-scoped asset as it stands.
	asset, err := s.store.GetAsset(r.Context(), acct, uploadID)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, asset)
}
