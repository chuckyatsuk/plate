package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// Reconciler cleans up orphaned brokered uploads (spec §5.1, accepted cost): a
// browser that PUTs an object then never finalizes leaves bytes in R2 with no
// asset record. The sweep finds uploads older than a grace window that were never
// finalized and deletes their objects. It consumes store.ReclaimableUploads —
// the exact query the PR-(a) test already holds as a requirement.
//
// This is a scheduled job, not the hot path: run it periodically (a cron, or a
// ticker inside `plate work`). It is safe to run concurrently with ingest because
// it only touches uploads past the grace window — well after any legitimate PUT
// would have finalized.
type Reconciler struct {
	store   *store.Postgres
	storage storage.Storage
	log     *slog.Logger

	grace     time.Duration // how long after creation an unfinalized upload is an orphan
	batchSize int32
}

// NewReconciler builds a Reconciler. grace defaults to a few hours (a studio's
// slow connection must have finished long before), batchSize to 100.
func NewReconciler(st *store.Postgres, stor storage.Storage, log *slog.Logger, grace time.Duration, batchSize int32) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	// grace == 0 means "use the safe default". A NEGATIVE grace is an explicit "no
	// window" (cutoff in the future → everything eligible), used by tests to purge
	// immediately without a sub-second race on deleted_at < now().
	if grace == 0 {
		grace = 6 * time.Hour
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Reconciler{store: st, storage: stor, log: log, grace: grace, batchSize: batchSize}
}

// SweepOnce runs a single reconciliation pass: delete the objects of unfinalized
// uploads older than the grace window. Returns the number of orphans cleaned.
// (Deleting the upload ROW is left to a follow-up once object deletion is
// confirmed; an orphan re-listed after its object is already gone is a cheap
// no-op delete, so the pass is idempotent.)
func (r *Reconciler) SweepOnce(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-r.grace)
	orphans, err := r.store.ReclaimableUploads(ctx, cutoff, r.batchSize)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	for _, u := range orphans {
		if err := r.storage.Delete(ctx, u.Key); err != nil {
			// Log and continue — one bad key must not stall the sweep.
			r.log.Warn("reconcile: delete orphan object failed", "key", u.Key, "err", err)
			continue
		}
		r.log.Info("reconcile: cleaned orphan upload", "upload", u.ID, "key", u.Key)
		cleaned++
	}
	return cleaned, nil
}

// SweepDeletedAssets is the second step of the two-step delete (review ruling 4,
// spec Q2): deleteAsset marked intent (deleted_at); this removes the vault bytes
// and then the asset row. Idempotent — a re-deleted object is a cheap no-op.
// Returns the number of assets purged.
func (r *Reconciler) SweepDeletedAssets(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-r.grace)
	deleted, err := r.store.ReclaimableDeletedAssets(ctx, cutoff, r.batchSize)
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, d := range deleted {
		// Delete the vault original. (Rendition objects share the vault key prefix;
		// a fuller sweep would list+delete them too — tracked as a follow-up.)
		if err := r.storage.Delete(ctx, d.VaultKey); err != nil {
			r.log.Warn("reconcile: delete deleted-asset bytes failed", "key", d.VaultKey, "err", err)
			continue
		}
		if err := r.store.PurgeDeletedAsset(ctx, d.ID); err != nil {
			r.log.Warn("reconcile: purge asset row failed", "asset", d.ID, "err", err)
			continue
		}
		r.log.Info("reconcile: purged deleted asset", "asset", d.ID, "key", d.VaultKey)
		purged++
	}
	return purged, nil
}

// SweepLoop runs both reconciliation passes on a ticker until ctx is cancelled —
// the scheduler the sweeps were always meant to have (§5.1, §Q2: "a cron, or a
// ticker inside plate work"). It runs INSIDE the worker process rather than as a
// separate Fly cron machine: the worker already holds the store + storage, and
// the sweeps are periodic housekeeping, not latency-sensitive. A pass that errors
// is logged and retried next tick — one bad sweep never stops the loop, the same
// discipline as the job loop. It runs one pass immediately on start so a
// freshly-deployed worker does not wait a full interval before its first sweep.
func (r *Reconciler) SweepLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 15 * time.Minute
	}
	r.log.Info("reconcile: sweep loop started", "every", every, "grace", r.grace)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.sweepBoth(ctx)
		select {
		case <-ctx.Done():
			r.log.Info("reconcile: sweep loop stopping")
			return
		case <-t.C:
		}
	}
}

// sweepBoth runs one pass of each sweep, logging counts. Errors are logged, not
// returned — the loop must survive a transient store/storage hiccup.
func (r *Reconciler) sweepBoth(ctx context.Context) {
	if n, err := r.SweepOnce(ctx); err != nil {
		r.log.Warn("reconcile: orphan-upload sweep failed", "err", err)
	} else if n > 0 {
		r.log.Info("reconcile: orphan-upload sweep done", "cleaned", n)
	}
	if n, err := r.SweepDeletedAssets(ctx); err != nil {
		r.log.Warn("reconcile: deleted-asset sweep failed", "err", err)
	} else if n > 0 {
		r.log.Info("reconcile: deleted-asset sweep done", "purged", n)
	}
}
