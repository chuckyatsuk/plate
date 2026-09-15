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
// waiting, how old the oldest one is (information), and when the worker last made
// PROGRESS on any job. A backlog is only an incident when nothing is progressing —
// a single long transcode keeps LastProgress fresh (it heartbeats its lease) while
// the oldest-queued age climbs, and that is healthy, not stuck.
type QueueLag struct {
	Queued       int
	OldestQueued *time.Time
	// LastProgress is max(greatest(locked_at, heartbeat_at, updated)) across recent
	// jobs — the last time a worker claimed, beat, completed, or failed anything.
	// Nil when no job has ever run. A queue that is non-empty while this is stale is
	// the real "stuck worker" signal, replacing the wall-clock lag ceiling.
	LastProgress *time.Time
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

// QueueLag counts queued jobs, finds the oldest (information), and reads the most
// recent job PROGRESS. Progress is max(greatest(locked_at, heartbeat_at, updated))
// over jobs — every event a worker makes writes one of those (claim sets locked +
// heartbeat, the beat refreshes heartbeat, complete/fail set updated). A live
// worker mid-transcode keeps it fresh, so a long job never reads as a stall; a dead
// or hung worker stops advancing it, which is the honest "stuck" signal.
func (p *Postgres) QueueLag(ctx context.Context) (QueueLag, error) {
	var ql QueueLag
	err := p.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status = 'queued'),
			min(created) FILTER (WHERE status = 'queued'),
			max(greatest(locked_at, heartbeat_at, updated))
		FROM jobs`).Scan(&ql.Queued, &ql.OldestQueued, &ql.LastProgress)
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
