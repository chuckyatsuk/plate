package plate_test

// Authored renditions (Tier 2 V4.1), proven END TO END in the real service: a
// caller uploads a FILE as an asset's `detail` rendition, and it is stream-copy
// remuxed into a ready rendition that resolves to a real URL — no transcode. And a
// file that breaks the authored ceilings is REFUSED with the naming reason, poster
// still deliverable. Through the actual HTTP handler + worker (real ffmpeg) +
// Postgres + storage, not a stub.
//
// This is the wiring the unit tests can't reach: createUpload's `rendition` binding
// → the STAGING key → finalize enqueues a mode='remux' job → the worker's remux
// branch probes, enforces the ceilings, and stream-copies. It closes the gap the V4
// acceptance run opened (a single derived detail crossed the queue-lag ceiling;
// authoring removes the transcode entirely).

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
)

// authorRendition runs createUpload(rendition binding) → PUT the file to the
// staging key → finalize, returning the remux job id (finalize answers 202 for an
// authored rendition, not 201). The tests that assert createUpload's own guards
// (409, 404) drive createUpload directly rather than through this helper.
func (e *e2e) authorRendition(assetID, intent, path, contentType string) (jobID string) {
	e.t.Helper()
	data, err := readFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	create := map[string]any{
		"content_type": contentType,
		"size_bytes":   len(data),
		"rendition":    map[string]any{"asset_id": assetID, "intent": intent},
	}
	resp := e.req("POST", "/v1/uploads", mustJSON(create))
	if resp.Code != 201 {
		e.t.Fatalf("createUpload(authored %s): HTTP %d: %s", intent, resp.Code, resp.Body.String())
	}
	var ticket struct {
		UploadID string `json:"upload_id"`
		URL      string `json:"url"`
	}
	mustDecode(e.t, resp.Body.Bytes(), &ticket)

	putURL := rewriteHost(ticket.URL, e.stor.Endpoint)
	putReq, _ := http.NewRequest("PUT", putURL, bytes.NewReader(data))
	putReq.Header.Set("Content-Type", contentType)
	putReq.ContentLength = int64(len(data))
	pr, err := http.DefaultClient.Do(putReq)
	if err != nil {
		e.t.Fatalf("PUT authored file: %v", err)
	}
	io.Copy(io.Discard, pr.Body)
	pr.Body.Close()
	if pr.StatusCode < 200 || pr.StatusCode >= 300 {
		e.t.Fatalf("PUT authored file to storage: HTTP %d", pr.StatusCode)
	}

	// finalize — an authored rendition answers 202 (async remux), returning the job.
	fresp := e.req("POST", "/v1/uploads/"+ticket.UploadID+"/finalize", mustJSON(map[string]any{"checksum": "md5:unverified-in-test"}))
	if fresp.Code != 202 {
		e.t.Fatalf("finalize(authored): HTTP %d: %s", fresp.Code, fresp.Body.String())
	}
	var job struct {
		ID string `json:"id"`
	}
	mustDecode(e.t, fresp.Body.Bytes(), &job)
	return job.ID
}

// A studio's own detail file is authored, remuxed, and resolves to a real URL — no
// transcode. The asset is created skip_derivations (nothing auto-enqueued), so the
// only rendition is the one we authored.
func TestE2E_AuthoredDetail_RemuxesToReadyRendition(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()

	// A short H.264/AAC source vaulted WITHOUT derivation (the V4.1 backfill shape:
	// the original is archival, the renditions are authored).
	orig := harness.SynthVideo(t, filepath.Join(dir, "orig.mp4"), harness.Seconds(6), true)
	assetID := e.uploadAndFinalizeOpts(orig, "video/mp4", "md5:unverified-in-test", true)

	// Author the detail from a real H.264/AAC file (within every ceiling).
	authored := harness.SynthVideo(t, filepath.Join(dir, "authored_detail.mp4"), harness.Seconds(6), true)
	e.authorRendition(assetID, "detail", authored, "video/mp4")

	// The remux job runs (stream-copy, seconds).
	e.drainWorker()

	// detail now resolves to a real delivery URL — a ready rendition, no transcode.
	res := e.resolve(assetID, "detail")
	if res.Delivery == nil {
		reason := ""
		if res.Reason != nil {
			reason = *res.Reason
		}
		t.Fatalf("authored detail did not resolve to a URL; reason=%q", reason)
	}
	if res.Delivery.URL == "" {
		t.Fatal("authored detail resolved with an empty URL")
	}
}

// A file that breaks an authored ceiling is REFUSED with the naming reason — the
// honest terminal state, not a transcode and not a crash. Here: a loop authored
// from an over-30s source → authored_loop_too_long.
func TestE2E_AuthoredLoop_OverDuration_RefusedWithReason(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()

	orig := harness.SynthVideo(t, filepath.Join(dir, "orig.mp4"), harness.Seconds(6), true)
	assetID := e.uploadAndFinalizeOpts(orig, "video/mp4", "md5:unverified-in-test", true)

	// A 40-second silent clip authored as the LOOP — over the 30s viewer cap.
	longLoop := harness.SynthVideo(t, filepath.Join(dir, "long_loop.mp4"), harness.Seconds(40), false)
	e.authorRendition(assetID, "loop", longLoop, "video/mp4")

	e.drainWorker()

	res := e.resolve(assetID, "loop")
	if res.Delivery != nil {
		t.Fatalf("an over-30s authored loop should be refused, got a delivery URL")
	}
	if res.Reason == nil || *res.Reason != string(plate.ReasonCodeAuthoredLoopTooLong) {
		got := "<nil>"
		if res.Reason != nil {
			got = *res.Reason
		}
		t.Fatalf("wrong refusal reason: got %q, want %q", got, plate.ReasonCodeAuthoredLoopTooLong)
	}
}

// createUpload rejects authoring over an existing READY rendition (409) — replace
// is an explicit delete-then-author.
func TestE2E_AuthoredOverReady_Rejected409(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()

	orig := harness.SynthVideo(t, filepath.Join(dir, "orig.mp4"), harness.Seconds(6), true)
	assetID := e.uploadAndFinalizeOpts(orig, "video/mp4", "md5:unverified-in-test", true)

	// First author + remux → detail is ready.
	authored := harness.SynthVideo(t, filepath.Join(dir, "d1.mp4"), harness.Seconds(6), true)
	e.authorRendition(assetID, "detail", authored, "video/mp4")
	e.drainWorker()

	// A second authored detail must be refused at createUpload with 409.
	data, err := readFile(authored)
	if err != nil {
		t.Fatal(err)
	}
	create := map[string]any{
		"content_type": "video/mp4",
		"size_bytes":   len(data),
		"rendition":    map[string]any{"asset_id": assetID, "intent": "detail"},
	}
	resp := e.req("POST", "/v1/uploads", mustJSON(create))
	if resp.Code != http.StatusConflict {
		t.Fatalf("authoring over a ready rendition: HTTP %d, want 409\n%s", resp.Code, resp.Body.String())
	}
}

// createUpload rejects an authored binding to an asset the caller does not own
// (leak-safe 404), so an authored upload cannot target another account's asset.
func TestE2E_AuthoredUnknownAsset_NotFound(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	authored := harness.SynthVideo(t, filepath.Join(dir, "d.mp4"), harness.Seconds(3), true)
	data, err := readFile(authored)
	if err != nil {
		t.Fatal(err)
	}
	create := map[string]any{
		"content_type": "video/mp4",
		"size_bytes":   len(data),
		"rendition":    map[string]any{"asset_id": "01ASSETDOESNOTEXIST00000000", "intent": "detail"},
	}
	resp := e.req("POST", "/v1/uploads", mustJSON(create))
	if resp.Code != http.StatusNotFound {
		t.Fatalf("authoring against an unowned asset: HTTP %d, want 404\n%s", resp.Code, resp.Body.String())
	}
}
