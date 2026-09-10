package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
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
	if s.storage == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "storage backend not configured")
		return
	}
	acct := account(r) // the ONLY source of the account — the token claim.

	var req plate.UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ContentType == "" || req.SizeBytes < 1 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid upload request")
		return
	}
	// Enforce the deployment's size ceiling BEFORE presigning (spec Q3.C).
	if s.uploadMaxBytes > 0 && req.SizeBytes > s.uploadMaxBytes {
		writeError(w, http.StatusBadRequest, "too_large", "declared size exceeds the upload ceiling")
		return
	}

	// Mint the id and the key from the caller's account. Any account a caller
	// tries to smuggle is structurally ignored: the key is built from acct, full
	// stop. UploadRequest has no account field precisely so it cannot be
	// expressed — and the presigned PUT is bound to THIS key, so a PUT to another
	// prefix is rejected by the signature (proven in storage_presign_test).
	assetID := id.New()
	key := id.VaultKey(acct, assetID) // {account}/{asset-id}

	put, err := s.storage.PresignPut(r.Context(), storage.PutConstraints{
		Key:           key,
		ContentType:   req.ContentType,
		ContentLength: req.SizeBytes, // exact declared size, bound into the signature
		Expiry:        s.uploadTTL,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not presign upload")
		return
	}

	// Record the pending upload so finalize can recover it and the reconciliation
	// sweep can reclaim it if the browser never finalizes (spec §5.1).
	filename := ""
	if req.Filename != nil {
		filename = *req.Filename
	}
	if err := s.store.CreateUpload(r.Context(), acct, store.Upload{
		ID:          assetID,
		Account:     acct,
		Key:         key,
		ContentType: req.ContentType,
		SizeBytes:   req.SizeBytes,
		Filename:    filename,
	}); err != nil {
		if errors.Is(err, store.ErrUnknownAccount) {
			// The token's account has no row yet — provision it with
			// `plate accounts create <id>`. A client/config error, not a 500.
			writeError(w, http.StatusForbidden, "unknown_account", "this account is not provisioned; an operator must create it before uploads are accepted")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "could not record upload")
		return
	}

	headers := make([]plate.Header, 0, len(put.Headers))
	for k, v := range put.Headers {
		headers = append(headers, plate.Header{Name: k, Value: v})
	}
	writeJSON(w, http.StatusCreated, plate.UploadTicket{
		UploadId: assetID,
		Url:      put.URL,
		Method:   plate.UploadTicketMethod("PUT"),
		Headers:  headers,
		Expires:  put.Expires,
	})
}

// imageProbePrefixBytes is how much of an object's head the image probe reads via
// a ranged GET — enough for JPEG/PNG/GIF headers, so a 300MB TIFF is never fully
// downloaded into the request (review ruling 1).
const imageProbePrefixBytes = 64 * 1024

// handleFinalizeUpload registers the vault object after a successful PUT (spec
// §5.1, §5.3 refined per review ruling 1). Fail-closed means the vault never
// accepts an object it cannot ACCOUNT FOR — existence + identity, confirmed here
// synchronously — NOT that every delivery property is known synchronously.
// Probing for delivery properties lives where the media runtime is:
//
//   - IMAGES: probed here, header-only via a ranged GET (stdlib, no ffprobe) →
//     asset created probe_status=ready.
//   - A/V: NOT probed here (the API has no ffprobe, and pulling a multi-GB master
//     into a sub-100ms request is the exact failure §5.1's broker avoids). The
//     asset is created probe_status=pending and a transcode job is enqueued; the
//     worker probes as its first step and backfills the metadata.
//   - DOCUMENTS: no probe needed → probe_status=ready.
//
// Checksum (review ruling 2): the client's claim is NEVER stored as verified. We
// verify against the object's ETag when it is a simple (single-part) MD5; else we
// leave it unverified and let the worker confirm it while it streams the bytes.
//
// The account-isolation boundary: finalize recovers the pending upload
// account-scoped, so a B-owned upload id is not finalizable by A (leak-safe 404).
func (s *Service) handleFinalizeUpload(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:write") {
		return
	}
	// Storage is required to finalize; its absence is a deployment misconfig caught
	// at startup (see LoadStorage/validateForWrite), not a per-request feature gap.
	if s.storage == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "storage backend not configured")
		return
	}
	acct := account(r)
	uploadID := r.PathValue("uploadId")

	var req plate.FinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Checksum == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid finalize request")
		return
	}

	// Recover the pending upload, account-scoped. A B-owned id is ErrNotFound →
	// leak-safe 404. This is the isolation boundary for finalize.
	up, err := s.store.GetUpload(r.Context(), acct, uploadID)
	if mapStoreErr(w, err) {
		return
	}

	// Confirm the object actually landed and read its true size (spec §5.3).
	info, err := s.storage.Head(r.Context(), up.Key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not verify uploaded object")
		return
	}
	if !info.Exists {
		// The PUT never completed — nothing to finalize. 409 per the contract.
		writeError(w, http.StatusConflict, "not_uploaded", "no uploaded object found for this upload")
		return
	}

	kind := kindFromContentType(up.ContentType)

	vr := store.VaultRecord{Kind: kind, SizeBytes: info.Size}

	// Checksum: verify against the ETag when it is a simple MD5 (single-part PUT).
	// Never store the raw client claim as verified (review ruling 2).
	if verified, ok := verifyChecksumFromETag(req.Checksum, info.ETag); ok {
		vr.Checksum = verified
		vr.ChecksumVerified = true
	}
	// else: leave Checksum empty + ChecksumVerified false; the worker confirms it
	// while streaming (A/V), or a later pass does for images. The field never holds
	// an unverified value.

	switch kind {
	case plate.Image:
		// Header-only probe via ranged GET — no full download.
		pr, perr := s.probeImageHead(r.Context(), up.Key)
		if perr != nil {
			// Fail closed: an image we cannot read is not promoted.
			writeError(w, http.StatusConflict, "unprobeable", "uploaded image could not be verified")
			return
		}
		vr.Width, vr.Height = ptrI32(pr.Width), ptrI32(pr.Height)
		if pr.Container != "" {
			c := pr.Container
			vr.Container = &c
		}
		vr.ProbeStatus = "ready"

	case plate.Document:
		// No media metadata to probe; existence is enough.
		vr.ProbeStatus = "ready"

	default: // video / audio — defer probing to the worker.
		vr.ProbeStatus = "pending"
	}

	asset, err := s.store.FinalizeUpload(r.Context(), acct, uploadID, vr)
	if mapStoreErr(w, err) {
		return
	}

	// A/V: enqueue the worker to probe + transcode. Enqueue the detail intent as
	// the default derivation; other intents are requested explicitly later.
	if kind == plate.Video || kind == plate.Audio {
		if _, err := s.store.EnqueueJob(r.Context(), acct, uploadID, plate.Detail); err != nil {
			// The asset exists; a failed enqueue is recoverable (re-request the
			// rendition). Do not fail the finalize.
			writeError(w, http.StatusInternalServerError, "internal", "asset created but enqueue failed")
			return
		}
	}

	writeJSON(w, http.StatusCreated, asset)
}

// probeImageHead reads just the header of an image via a ranged GET and returns
// its dimensions — the API's image probe that never downloads the whole object.
func (s *Service) probeImageHead(ctx context.Context, key string) (probe.Result, error) {
	body, err := s.storage.GetRange(ctx, key, 0, imageProbePrefixBytes)
	if err != nil {
		return probe.Result{}, err
	}
	defer body.Close()
	// Image probing is pure stdlib (no ffprobe), so a prober built without an
	// ffprobe path works even on the probe-less API image.
	pr := s.prober
	if pr == nil {
		pr = probe.New("")
	}
	return pr.ProbeImageReader(body)
}

func ptrI32(n int) *int32 {
	if n <= 0 {
		return nil
	}
	v := int32(n)
	return &v
}

// verifyChecksumFromETag compares a client-declared sha256:… claim... actually the
// ETag is an MD5 for single-part PUTs, which is a DIFFERENT digest than sha256, so
// it cannot confirm a sha256 claim. What it CAN do: when the client declares an
// md5:… checksum, confirm it against the ETag. A multipart ETag (contains "-") is
// not a plain MD5 and cannot be compared. Returns (verifiedValue, true) only on a
// real match. For sha256 claims, verification is deferred to the worker (which
// streams the bytes anyway) — we return ok=false here rather than fake it.
func verifyChecksumFromETag(clientClaim, etag string) (string, bool) {
	etag = strings.Trim(etag, "\"")
	if etag == "" || strings.Contains(etag, "-") {
		return "", false // absent or multipart — cannot compare
	}
	claim := strings.TrimPrefix(clientClaim, "md5:")
	if claim != clientClaim && strings.EqualFold(claim, etag) {
		// Client declared md5:… and it matches the object's ETag.
		return "md5:" + strings.ToLower(etag), true
	}
	return "", false
}

// kindFromContentType maps a declared MIME type to a MediaKind. The routing
// allowlist (delivery.go) is the closed-enum authority for delivery; this is the
// ingest-side classification of what was uploaded.
func kindFromContentType(ct string) plate.MediaKind {
	switch {
	case strings.HasPrefix(ct, "image/"):
		return plate.Image
	case strings.HasPrefix(ct, "video/"):
		return plate.Video
	case strings.HasPrefix(ct, "audio/"):
		return plate.Audio
	default:
		return plate.Document
	}
}
