package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
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
		writeError(w, http.StatusNotImplemented, "not_implemented", "this deployment has no storage backend configured")
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

// handleFinalizeUpload registers the vault object after a successful PUT (spec
// §5.1, §5.3): it HEADs the stored object (confirm it landed, read true size),
// PROBES it (ffprobe/stdlib) to record true dimensions/duration/codec/container,
// and creates the asset — all account-scoped. Fail closed: an object that is
// absent or unprobeable is refused (the asset is not created); a ceiling breach
// still creates the asset but the offending intent will refuse at delivery (spec
// §5.3 — refusal is about DELIVERY, not STORAGE).
//
// The account-isolation boundary: finalize recovers the pending upload
// account-scoped, so a B-owned upload id is not finalizable by A (leak-safe 404).
func (s *Service) handleFinalizeUpload(w http.ResponseWriter, r *http.Request) {
	if !scopeCheck(w, r, "assets:write") {
		return
	}
	if s.storage == nil || s.prober == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "this deployment cannot finalize uploads")
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
		// The PUT never completed — nothing to finalize. 409 per the contract
		// (the uploaded object failed verification).
		writeError(w, http.StatusConflict, "not_uploaded", "no uploaded object found for this upload")
		return
	}

	// Probe the object for its true properties (spec §5.3). Route by declared
	// content type: images use the stdlib prober (no cgo), A/V uses ffprobe. Fail
	// closed — an unprobeable object is not promoted.
	vr, err := s.probeObject(r.Context(), up, info)
	if err != nil {
		writeError(w, http.StatusConflict, "unprobeable", "uploaded object could not be verified")
		return
	}
	vr.Checksum = req.Checksum
	vr.SizeBytes = info.Size

	asset, err := s.store.FinalizeUpload(r.Context(), acct, uploadID, vr)
	if mapStoreErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, asset)
}

// probeObject downloads the object and probes it. For images it uses the stdlib
// (decode config); for A/V it writes a temp file and runs ffprobe. Returns the
// VaultRecord fields the probe can determine (checksum/size are filled by the
// caller from the HEAD + the client checksum).
func (s *Service) probeObject(ctx context.Context, up store.Upload, info storage.ObjectInfo) (store.VaultRecord, error) {
	kind := kindFromContentType(up.ContentType)

	body, err := s.storage.Get(ctx, up.Key)
	if err != nil {
		return store.VaultRecord{}, err
	}
	defer body.Close()

	// Spool to a temp file — both the image decoder and ffprobe want a file/seeker,
	// and the worker's scratch dir is the right home for this in production.
	tmp, err := os.CreateTemp("", "plate-finalize-*")
	if err != nil {
		return store.VaultRecord{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.Copy(tmp, body); err != nil {
		return store.VaultRecord{}, err
	}

	var res probeResult
	switch kind {
	case plate.Image:
		pr, perr := s.prober.ProbeImage(tmp.Name())
		if perr != nil {
			return store.VaultRecord{}, perr
		}
		res = probeResult{kind: pr.Kind, w: pr.Width, h: pr.Height, container: pr.Container}
	default: // video/audio/document → probe as A/V (documents carry no probe metadata; ffprobe tolerates)
		pr, perr := s.prober.ProbeAV(ctx, tmp.Name())
		if perr != nil {
			// A document (e.g. PDF) is not probeable by ffprobe; that is not a
			// verification failure — record it as a document with no media metadata.
			if kind == plate.Document {
				return store.VaultRecord{Kind: plate.Document}, nil
			}
			return store.VaultRecord{}, perr
		}
		res = probeResult{kind: pr.Kind, w: pr.Width, h: pr.Height, dur: pr.DurationS, codec: pr.Codec, container: pr.Container}
	}

	vr := store.VaultRecord{Kind: res.kind}
	if res.w > 0 {
		w := int32(res.w)
		vr.Width = &w
	}
	if res.h > 0 {
		h := int32(res.h)
		vr.Height = &h
	}
	if res.dur > 0 {
		d := res.dur
		vr.DurationS = &d
	}
	if res.codec != "" {
		c := res.codec
		vr.Codec = &c
	}
	if res.container != "" {
		ct := res.container
		vr.Container = &ct
	}
	return vr, nil
}

type probeResult struct {
	kind      plate.MediaKind
	w, h      int
	dur       float64
	codec     string
	container string
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
