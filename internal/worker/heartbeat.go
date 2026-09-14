package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/chuckyatsuk/plate/internal/store"
)

// HeartbeatLoop is the worker's liveness signal (Tier 1 monitoring). Every
// `every` it upserts this worker's row in worker_heartbeats — independent of
// whether a job is running, so an idle worker still proves it is alive — and
// carries the newest completed sweep time so /readyz can tell "alive" from
// "alive and doing its housekeeping". Failures are logged, never fatal: a
// blip in the heartbeat must not kill the worker (that would be the outage).
//
// lastSweep is read on each beat (the Reconciler's LastSweep), nil until the
// first pass completes.
func HeartbeatLoop(ctx context.Context, st *store.Postgres, log *slog.Logger, workerID, version string, every time.Duration, lastSweep func() *time.Time) {
	if every <= 0 {
		every = 30 * time.Second
	}
	log.Info("worker heartbeat started", "worker_id", workerID, "version", version, "every", every)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := st.UpsertWorkerHeartbeat(ctx, workerID, version, lastSweep()); err != nil {
			log.Warn("worker heartbeat failed", "err", err)
		}
		select {
		case <-ctx.Done():
			log.Info("worker heartbeat stopping")
			return
		case <-t.C:
		}
	}
}
