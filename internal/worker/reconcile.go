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
	if grace <= 0 {
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
