package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// WorkerLiveness is what /readyz learns about the worker fleet from
// worker_heartbeats: whether ANY worker has ever beaten, when the newest beat
// was, and when the newest reconcile sweep completed.
type WorkerLiveness struct {
	Seen      bool
	WorkerID  string
	Version   string
	LastSeen  time.Time
	LastSweep *time.Time
}

// QueueLag is the job-queue backlog as /readyz reports it: how many jobs are
// waiting and how old the oldest one is. A worker that is alive but stuck
// shows up here (its heartbeat is fine, the queue is not).
type QueueLag struct {
	Queued       int
	OldestQueued *time.Time
}

// Ping is the cheapest possible database reachability check (a round trip on
// a pooled connection). It is what turns /readyz from a stub into a signal.
func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// WorkerLiveness returns the newest worker heartbeat, or Seen=false when no
// worker has ever reported (a fresh deployment, or a worker that never came up).
func (p *Postgres) WorkerLiveness(ctx context.Context) (WorkerLiveness, error) {
	var wl WorkerLiveness
	err := p.pool.QueryRow(ctx, `
		SELECT worker_id, version, last_seen, last_sweep
		FROM worker_heartbeats
		ORDER BY last_seen DESC
		LIMIT 1`).Scan(&wl.WorkerID, &wl.Version, &wl.LastSeen, &wl.LastSweep)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return WorkerLiveness{}, nil
		}
		return WorkerLiveness{}, err
	}
	wl.Seen = true
	return wl, nil
}

// QueueLag counts queued jobs and finds the oldest. Running jobs are not lag —
// they are being worked (their own lease heartbeat covers a stall).
func (p *Postgres) QueueLag(ctx context.Context) (QueueLag, error) {
	var ql QueueLag
	err := p.pool.QueryRow(ctx, `
		SELECT count(*), min(created) FROM jobs WHERE status = 'queued'`).Scan(&ql.Queued, &ql.OldestQueued)
	if err != nil {
		return QueueLag{}, err
	}
	return ql, nil
}

// UpsertWorkerHeartbeat is the worker's side: "I am alive, this is my build,
// and this is when I last finished a sweep". Called on a ticker from the run
// loop, independent of whether any job is running.
func (p *Postgres) UpsertWorkerHeartbeat(ctx context.Context, workerID, version string, lastSweep *time.Time) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO worker_heartbeats (worker_id, version, last_seen, last_sweep)
		VALUES ($1, $2, now(), $3)
		ON CONFLICT (worker_id) DO UPDATE SET
			last_seen  = now(),
			version    = EXCLUDED.version,
			last_sweep = COALESCE(EXCLUDED.last_sweep, worker_heartbeats.last_sweep)`,
		workerID, version, lastSweep)
	return err
}
