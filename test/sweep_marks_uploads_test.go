package plate_test

// Follow-up to the monitoring slice: the reconcile sweep deletes an orphan
// upload's object but must MARK the row (swept_at), or ReclaimableUploads —
// which filters only on (finalized_at IS NULL, created) — re-selects the same
// orphan every pass and "cleans" it forever (R2 DeleteObject on a missing key
// succeeds silently). These tests hold the fix against the running store:
//   1. a second sweep cleans 0 (the orphan was marked, not re-deleted);
//   2. finalize on a swept upload is a terminal 410, not a resurrected asset
//      pointing at bytes the sweep already deleted.
// Real MinIO + Postgres via the e2e harness, so the object delete and the
// swept-at guard are exercised end to end, not mocked.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

// uploadNoFinalize creates an upload and PUTs its bytes to storage but does NOT
// finalize — the tab-closed orphan the sweep exists to reclaim. Returns the
// upload id (which is also its future asset id and the tail of its vault key).
func (e *e2e) uploadNoFinalize(path, contentType string) (uploadID, url string) {
	e.t.Helper()
	data, err := readFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.req("POST", "/v1/uploads", mustJSON(map[string]any{
		"content_type": contentType, "size_bytes": len(data),
	}))
	if resp.Code != 201 {
		e.t.Fatalf("createUpload: HTTP %d: %s", resp.Code, resp.Body.String())
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
		e.t.Fatalf("PUT: %v", err)
	}
	io.Copy(io.Discard, pr.Body)
	pr.Body.Close()
	if pr.StatusCode < 200 || pr.StatusCode >= 300 {
		e.t.Fatalf("PUT to storage: HTTP %d", pr.StatusCode)
	}
	return ticket.UploadID, ticket.URL
}

// A second sweep must clean nothing: the orphan is marked swept after the first
// pass and drops out of ReclaimableUploads. Before the fix this returned the
// same count on every pass forever.
func TestE2E_Sweep_CleansOrphanExactlyOnce(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()

	e.uploadNoFinalize(harness.SynthImage(t, dir, "orphan.png", 320, 240), "image/png")

	// Negative grace ("no window") → the just-created orphan is eligible now.
	rec := worker.NewReconciler(e.st, e.stor.Storage, slog.Default(), -time.Second, 100)

	first, err := rec.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if first != 1 {
		t.Fatalf("first sweep cleaned %d; expected exactly the one orphan", first)
	}

	second, err := rec.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if second != 0 {
		t.Fatalf("second sweep cleaned %d; expected 0 — the orphan was re-selected because its row was not marked swept (the every-15-min forever-cleaning bug)", second)
	}
}

// Finalize on a swept upload must be a terminal 410, never create an asset: the
// sweep already deleted the vault bytes, so an asset from it would point at
// nothing.
func TestE2E_FinalizeAfterSweep_IsGone(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()

	uploadID, _ := e.uploadNoFinalize(harness.SynthImage(t, dir, "swept.png", 320, 240), "image/png")

	rec := worker.NewReconciler(e.st, e.stor.Storage, slog.Default(), -time.Second, 100)
	if n, err := rec.SweepOnce(ctx); err != nil || n != 1 {
		t.Fatalf("sweep should have cleaned the orphan (cleaned=%d err=%v)", n, err)
	}

	// The real finalize endpoint must now refuse with 410 Gone.
	resp := e.req("POST", "/v1/uploads/"+uploadID+"/finalize", mustJSON(map[string]any{"checksum": "md5:unverified-in-test"}))
	if resp.Code != http.StatusGone {
		t.Fatalf("finalize after sweep should be 410 Gone; got %d: %s — a swept upload must not resurrect into an asset pointing at deleted bytes", resp.Code, resp.Body.String())
	}
}
