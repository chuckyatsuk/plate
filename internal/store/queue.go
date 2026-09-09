package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/jackc/pgx/v5"
)

// This file is the job queue (spec Q4): Postgres SELECT ... FOR UPDATE SKIP
// LOCKED, no Redis/SQS. The queue is transactional with the asset/rendition
// state — a job and its rendition row commit together, so there is never a "job
// succeeded but the record didn't update" split. SKIP LOCKED lets N workers
// claim disjoint jobs without blocking each other.

// ClaimedJob is a job a worker has claimed to run, with the fields the worker
// needs to do the work (the asset's vault key) plus the job identity.
type ClaimedJob struct {
	ID       string
	Account  string
	Asset    string
	Intent   plate.Intent
	VaultKey string // the asset's {account}/{asset-id} storage key — the transcode source
	Attempts int32
}

// ErrNoJob is returned by ClaimNextJob when the queue has nothing runnable.
var ErrNoJob = errors.New("store: no job available")

// EnqueueJob inserts a queued A/V derivation job for an owned asset. Account-
// scoped: the job carries the caller's account, and the asset must belong to it
// (verified by the caller before enqueue). Idempotent per (asset, intent):
// re-enqueueing an existing non-failed job returns it rather than duplicating.
func (p *Postgres) EnqueueJob(ctx context.Context, account, assetID string, intent plate.Intent) (plate.Job, error) {
	// Reuse an existing job for this (asset, intent) unless it failed — a retry of
	// a failed one re-queues it.
	var (
		j        plate.Job
		existing bool
	)
	err := p.pool.QueryRow(ctx, `
		SELECT id, asset, intent, status, retries
		FROM jobs
		WHERE account = $1 AND asset = $2 AND intent = $3
		ORDER BY created DESC LIMIT 1`, account, assetID, string(intent)).
		Scan(&j.Id, &j.Asset, &j.Intent, &j.Status, &j.Retries)
	switch {
	case err == nil:
		existing = true
	case errors.Is(err, pgx.ErrNoRows):
		existing = false
	default:
		return plate.Job{}, err
	}

	if existing && j.Status != plate.JobStatus("failed") {
		return j, nil // queued/running/succeeded — return as-is (idempotent)
	}

	jobID := id.New()
	row := p.pool.QueryRow(ctx, `
		INSERT INTO jobs (id, account, asset, intent, status)
		VALUES ($1, $2, $3, $4, 'queued')
		RETURNING id, asset, intent, status, retries, created, updated`,
		jobID, account, assetID, string(intent))
	return scanJobBasic(row)
}

// ClaimNextJob atomically claims the oldest queued job (or a job whose lease has
// expired — a worker that died mid-job). It marks the job running, stamps the
// lease, bumps attempts, and returns it with the asset's vault key. ErrNoJob when
// nothing is runnable. SKIP LOCKED means concurrent workers never collide.
//
// leaseTTL defines a stale lease: a running job whose heartbeat is older than
// leaseTTL is reclaimable (its worker is presumed dead). This is the mechanism
// behind "a worker that survives being killed mid-job" (spec Q4) — the job is
// not lost, it is re-claimed.
func (p *Postgres) ClaimNextJob(ctx context.Context, leaseTTL time.Duration) (ClaimedJob, error) {
	staleBefore := time.Now().Add(-leaseTTL)
	row := p.pool.QueryRow(ctx, `
		UPDATE jobs SET
			status       = 'running',
			locked_at    = now(),
			heartbeat_at = now(),
			retries      = retries + 1,
			updated      = now()
		WHERE id = (
			SELECT id FROM jobs
			WHERE status = 'queued'
			   OR (status = 'running' AND heartbeat_at < $1)
			ORDER BY created
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, account, asset, intent, retries`,
		staleBefore)

	var cj ClaimedJob
	if err := row.Scan(&cj.ID, &cj.Account, &cj.Asset, &cj.Intent, &cj.Attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ClaimedJob{}, ErrNoJob
		}
		return ClaimedJob{}, err
	}

	// Fetch the asset's vault key (the transcode source), scoped to the job's
	// account. A job can only ever reference its own account's asset.
	if err := p.pool.QueryRow(ctx, `
		SELECT vault_key FROM assets WHERE account = $1 AND id = $2`,
		cj.Account, cj.Asset).Scan(&cj.VaultKey); err != nil {
		return ClaimedJob{}, fmt.Errorf("store: claimed job %s: load vault key: %w", cj.ID, err)
	}
	return cj, nil
}

// Heartbeat refreshes a running job's lease so a long transcode is not reclaimed
// as stale mid-run.
func (p *Postgres) Heartbeat(ctx context.Context, jobID string, progress float64) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE jobs SET heartbeat_at = now(), progress = $2, updated = now()
		WHERE id = $1 AND status = 'running'`, jobID, progress)
	return err
}

// CompleteJob marks a job succeeded AND upserts its ready rendition in ONE
// transaction (spec Q4: the job and rendition commit together). The rendition
// points at the produced object key with its delivery mode.
func (p *Postgres) CompleteJob(ctx context.Context, jobID string, rend RenditionRecord) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Confirm the job is still ours to complete (its lease didn't get reclaimed).
	var asset string
	var intent string
	if err := tx.QueryRow(ctx, `
		SELECT asset, intent FROM jobs WHERE id = $1 AND status = 'running'`,
		jobID).Scan(&asset, &intent); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: job %s not running (lease lost?)", jobID)
		}
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO renditions (asset, intent, status, width, height, duration_s, has_audio, key, mode)
		VALUES ($1, $2, 'ready', $3, $4, $5, $6, $7, $8)
		ON CONFLICT (asset, intent) DO UPDATE SET
			status = 'ready', width = EXCLUDED.width, height = EXCLUDED.height,
			duration_s = EXCLUDED.duration_s, has_audio = EXCLUDED.has_audio,
			key = EXCLUDED.key, mode = EXCLUDED.mode, reason = NULL`,
		asset, intent, rend.Width, rend.Height, rend.DurationS, rend.HasAudio, rend.Key, rend.Mode); err != nil {
		return fmt.Errorf("store: upsert rendition: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE jobs SET status = 'succeeded', progress = 1, updated = now() WHERE id = $1`,
		jobID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// FailJob records a job failure. If attempts remain below maxAttempts it is
// re-queued (recoverable — the vault original still exists, spec §5.2); otherwise
// it is marked failed with a closed-enum reason the delivery path surfaces.
func (p *Postgres) FailJob(ctx context.Context, jobID string, maxAttempts int32, reason plate.ReasonCode, errMsg string) error {
	var attempts int32
	if err := p.pool.QueryRow(ctx, `SELECT retries FROM jobs WHERE id = $1`, jobID).Scan(&attempts); err != nil {
		return err
	}
	if attempts < maxAttempts {
		// Re-queue for another attempt; clear the lease.
		_, err := p.pool.Exec(ctx, `
			UPDATE jobs SET status = 'queued', locked_at = NULL, heartbeat_at = NULL,
				last_error = $2, updated = now()
			WHERE id = $1`, jobID, errMsg)
		return err
	}
	_, err := p.pool.Exec(ctx, `
		UPDATE jobs SET status = 'failed', reason = $2, last_error = $3, updated = now()
		WHERE id = $1`, jobID, string(reason), errMsg)
	return err
}

// RenditionRecord is what CompleteJob writes for the produced rendition.
type RenditionRecord struct {
	Key       string
	Mode      string
	Width     *int32
	Height    *int32
	DurationS *float64
	HasAudio  *bool
}

func scanJobBasic(row pgx.Row) (plate.Job, error) {
	var (
		j       plate.Job
		created time.Time
		updated time.Time
	)
	if err := row.Scan(&j.Id, &j.Asset, &j.Intent, &j.Status, &j.Retries, &created, &updated); err != nil {
		return plate.Job{}, err
	}
	j.Created = &created
	j.Updated = &updated
	return j, nil
}
