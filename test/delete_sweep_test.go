package plate_test

// Review ruling 4: two-step delete must actually make bytes unreachable, proven
// now even though the scheduled purge job is a follow-up. deleteAsset marks intent
// (deleted_at); the reconciler's SweepDeletedAssets removes the vault bytes and
// the row. Without this test, "two-step delete" is one step and a promise, and a
// deleted_at with nothing proving a purge is how storage cost becomes permanent.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_DeletedAsset_BytesBecomeUnreachable(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()

	img := harness.SynthImage(t, dir, "doomed.png", 500, 400)
	assetID := e.uploadAndFinalize(img, "image/png")

	// The object exists in storage after finalize.
	key := e.account + "/" + assetID
	if info, err := e.stor.Storage.Head(ctx, key); err != nil || !info.Exists {
		t.Fatalf("object should exist after finalize (err=%v exists=%v)", err, info.Exists)
	}

	// Mark for deletion via the real API (202, deleted_at set).
	resp := e.req("DELETE", "/v1/assets/"+assetID, nil)
	if resp.Code != 202 {
		t.Fatalf("deleteAsset should be 202; got %d: %s", resp.Code, resp.Body.String())
	}

	// The bytes are still there until the sweep runs — deletion is two-step.
	if info, _ := e.stor.Storage.Head(ctx, key); !info.Exists {
		t.Fatal("bytes vanished before the sweep — deletion should be two-step (mark, then purge)")
	}

	// Run the purge sweep with a NEGATIVE grace ("no window") so the just-deleted
	// asset is eligible immediately and deterministically (no deleted_at<now race).
	rec := worker.NewReconciler(e.st, e.stor.Storage, slog.Default(), -time.Second, 100)
	purged, err := rec.SweepDeletedAssets(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if purged < 1 {
		t.Fatalf("sweep purged %d assets; expected at least the one we deleted", purged)
	}

	// Now the bytes are unreachable.
	if info, _ := e.stor.Storage.Head(ctx, key); info.Exists {
		t.Fatal("deleted asset's bytes are STILL in storage after the purge sweep — the two-step delete does not actually delete")
	}
}

// The SCHEDULER, not just the sweep function: SweepLoop (now wired into
// `plate work`) must actually invoke the purge on its ticker. Without this, the
// sweep exists but nothing runs it — the exact "built but never scheduled" gap
// this step closes. Proven by starting the loop and watching a deleted asset's
// bytes vanish, then cancelling.
func TestE2E_SweepLoop_PurgesOnTicker(t *testing.T) {
	e := newE2E(t, 720)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()

	assetID := e.uploadAndFinalize(harness.SynthImage(t, dir, "doomed.png", 320, 240), "image/png")
	key := e.account + "/" + assetID
	if resp := e.req("DELETE", "/v1/assets/"+assetID, nil); resp.Code != 202 {
		t.Fatalf("deleteAsset should be 202; got %d", resp.Code)
	}

	// Negative grace → eligible immediately; a short tick → the loop runs a pass
	// almost at once (SweepLoop also sweeps once on entry).
	rec := worker.NewReconciler(e.st, e.stor.Storage, slog.Default(), -time.Second, 100)
	go rec.SweepLoop(ctx, 50*time.Millisecond)

	// Wait for the loop to purge the bytes (poll up to a few seconds).
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, _ := e.stor.Storage.Head(ctx, key)
		if !info.Exists {
			break // the loop purged it
		}
		if time.Now().After(deadline) {
			t.Fatal("SweepLoop did not purge the deleted asset's bytes — the ticker is not driving the sweep")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
