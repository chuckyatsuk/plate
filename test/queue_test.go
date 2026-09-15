package plate_test

// The job queue mechanics (spec Q4: Postgres SELECT ... FOR UPDATE SKIP LOCKED),
// proven against REAL SQL on the ephemeral Postgres — the claim/complete/retry/
// stale-lease-reclaim behaviour the worker depends on. Same discipline as the
// isolation suite: the queue's correctness lives in the SQL, so it is tested
// against the SQL, not a stand-in.

import (
	"context"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/store"
)

// seedAssetForQueue inserts a FRESH account-owned asset (a new ULID each call, so
// tests don't collide with each other or across -count=N reruns against the
// shared ephemeral store) and returns its id.
func seedAssetForQueue(t *testing.T, st *store.Postgres) string {
	t.Helper()
	assetID := id.New()
	_, err := st.Pool().Exec(context.Background(), `
		INSERT INTO assets (id, account, kind, vault_key, vault_checksum, vault_size_bytes)
		VALUES ($1, $2, 'video', $3, 'sha256:q', 4096)`,
		assetID, reconcileAccount, reconcileAccount+"/"+assetID)
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return assetID
}

func TestQueue_ClaimRunsOnceThenEmpty(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()
	assetID := seedAssetForQueue(t, st)

	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Detail); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// First claim gets the job.
	c1, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("first claim should succeed: %v", err)
	}
	if c1.Intent != plate.Detail || c1.VaultKey == "" {
		t.Fatalf("claimed job missing fields: %+v", c1)
	}

	// Second claim finds nothing runnable (the first is running, lease fresh).
	if _, err := st.ClaimNextJob(ctx, 15*time.Minute); err != store.ErrNoJob {
		t.Fatalf("second claim should be ErrNoJob (job is leased), got %v", err)
	}
}

func TestQueue_CompleteWritesReadyRendition(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()
	assetID := seedAssetForQueue(t, st)

	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Detail); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	c, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	w, h := int32(1920), int32(1080)
	audio := true
	if err := st.CompleteJob(ctx, c.ID, store.RenditionRecord{
		Key: c.VaultKey + "/detail", Mode: string(plate.Public),
		Width: &w, Height: &h, HasAudio: &audio,
	}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// The asset now has a ready detail rendition.
	asset, err := st.GetAsset(ctx, reconcileAccount, assetID)
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	var found bool
	for _, r := range asset.Renditions {
		if r.Intent == plate.Detail {
			found = true
			if r.Status != plate.RenditionStatus("ready") {
				t.Fatalf("detail rendition status = %q, want ready", r.Status)
			}
		}
	}
	if !found {
		t.Fatal("no detail rendition after CompleteJob")
	}

	// The job is no longer claimable (succeeded).
	if _, err := st.ClaimNextJob(ctx, 15*time.Minute); err != store.ErrNoJob {
		t.Fatalf("a succeeded job should not be reclaimable, got %v", err)
	}
}

// A running job whose lease has expired (its worker died) must be reclaimable —
// the mechanism behind "survives being killed mid-job" (spec Q4).
func TestQueue_StaleLeaseIsReclaimed(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()
	assetID := seedAssetForQueue(t, st)

	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Detail); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	first, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// A NEGATIVE lease TTL makes the staleness cutoff a moment in the FUTURE, so a
	// just-set heartbeat is unambiguously stale — deterministic, no dependence on
	// wall-clock delta (a zero TTL races when both now() land in the same ms).
	reclaimed, err := st.ClaimNextJob(ctx, -time.Second)
	if err != nil {
		t.Fatalf("stale-lease reclaim should succeed: %v", err)
	}
	if reclaimed.ID != first.ID {
		t.Fatalf("reclaimed a different job: got %s, want %s", reclaimed.ID, first.ID)
	}
	if reclaimed.Attempts <= first.Attempts {
		t.Fatalf("reclaim should bump attempts: first=%d reclaimed=%d", first.Attempts, reclaimed.Attempts)
	}
}

// SHORT work is claimed before an older long transcode (Tier 2 V4.1). A poster
// enqueued AFTER a detail must still run first — the claim order keys on intent
// priority, not just created — so the still never waits behind a multi-minute
// detail (the V3 poster problem). Proven against the real claim SQL.
func TestQueue_ShortIntentsClaimedFirst(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()
	assetID := seedAssetForQueue(t, st)

	// Detail enqueued FIRST (older created), poster SECOND. By created-only order
	// the detail would win; short-first must flip that.
	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Detail); err != nil {
		t.Fatalf("enqueue detail: %v", err)
	}
	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Poster); err != nil {
		t.Fatalf("enqueue poster: %v", err)
	}

	first, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if first.Intent != plate.Poster {
		t.Fatalf("short-first: expected poster claimed before the older detail, got %q", first.Intent)
	}
	// The detail is next.
	second, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if second.Intent != plate.Detail {
		t.Fatalf("expected detail second, got %q", second.Intent)
	}
}

// A remux job (mode='remux', Tier 2 V4.1) is SHORT even when its intent is 'detail'
// — an authored detail's remux carries intent 'detail' but must claim ahead of an
// older DERIVED detail. Since the remux enqueue path lands in PR1, this seeds the
// remux job directly via SQL to prove the claim order keys on MODE, not intent.
func TestQueue_RemuxClaimedBeforeDerivedDetail(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()

	// A derived detail, enqueued first (older).
	derivedAsset := seedAssetForQueue(t, st)
	if _, err := st.EnqueueJob(ctx, reconcileAccount, derivedAsset, plate.Detail); err != nil {
		t.Fatalf("enqueue derived detail: %v", err)
	}

	// A remux detail on another asset, inserted directly (queued, mode='remux'),
	// created LATER than the derived detail so created-order would rank it second.
	remuxAsset := seedAssetForQueue(t, st)
	remuxJobID := id.New()
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO jobs (id, account, asset, intent, status, mode, created)
		VALUES ($1, $2, $3, 'detail', 'queued', 'remux', now() + interval '1 second')`,
		remuxJobID, reconcileAccount, remuxAsset); err != nil {
		t.Fatalf("insert remux job: %v", err)
	}

	// The remux (mode='remux', tier 0) must claim before the older derived detail
	// (tier 2), despite being created later.
	first, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if first.Asset != remuxAsset {
		t.Fatalf("remux (mode=remux) should claim before the older derived detail; got asset %s want %s", first.Asset, remuxAsset)
	}
}

// A job that fails past maxAttempts is marked failed with a closed-enum reason
// the delivery path can surface; below the ceiling it re-queues.
func TestQueue_FailRetriesThenFails(t *testing.T) {
	st := freshStore(t)
	ctx := context.Background()
	assetID := seedAssetForQueue(t, st)

	if _, err := st.EnqueueJob(ctx, reconcileAccount, assetID, plate.Detail); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	c, err := st.ClaimNextJob(ctx, 15*time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// maxAttempts=1 and this is attempt 1 → not below the ceiling → marked failed.
	if err := st.FailJob(ctx, c.ID, 1, plate.ReasonCodeFailed, "boom"); err != nil {
		t.Fatalf("fail: %v", err)
	}

	job, err := st.GetJob(ctx, reconcileAccount, c.ID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.Status != plate.JobStatus("failed") {
		t.Fatalf("job status = %q, want failed", job.Status)
	}
	if job.Reason == nil || *job.Reason != plate.ReasonCodeFailed {
		t.Fatalf("failed job should carry reason=failed, got %v", job.Reason)
	}
}
