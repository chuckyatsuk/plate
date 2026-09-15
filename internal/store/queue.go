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
	// Mode is 'derive' (transcode the vault original) or 'remux' (stream-copy an
	// authored file — Tier 2 V4.1). Empty is treated as 'derive' by the worker.
	Mode string
	// SourceKey is a remux job's source: the staging key the authored file landed
	// at. Empty for a derive job (which reads VaultKey). The worker reads SourceKey
	// when set, VaultKey otherwise.
	SourceKey string
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

// EnqueueRemuxJob inserts a queued REMUX job for an AUTHORED rendition (Tier 2
// V4.1): mode='remux', source_key = the staging key the authored file landed at.
// The worker stream-copies that file into the intent's delivery object instead of
// transcoding the vault original. Account-scoped; the asset must belong to the
// caller (verified before enqueue). Idempotent per (asset, intent) like EnqueueJob:
// a re-authored intent whose prior job is non-failed returns it, and its
// source_key is updated to the new staging file so the re-run reads the fresh
// upload (an authored intent whose old job is queued/running but whose file was
// re-uploaded must remux the NEW bytes).
func (p *Postgres) EnqueueRemuxJob(ctx context.Context, account, assetID string, intent plate.Intent, sourceKey string) (plate.Job, error) {
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
		// Re-point the existing non-failed job at the freshly-uploaded staging file
		// and ensure it is a remux — the author just replaced the source bytes.
		if _, err := p.pool.Exec(ctx, `
			UPDATE jobs SET source_key = $1, mode = 'remux', updated = now()
			WHERE id = $2`, sourceKey, j.Id); err != nil {
			return plate.Job{}, err
		}
		j.Status = plate.JobStatus("queued")
		return j, nil
	}

	jobID := id.New()
	row := p.pool.QueryRow(ctx, `
		INSERT INTO jobs (id, account, asset, intent, status, mode, source_key)
		VALUES ($1, $2, $3, $4, 'queued', 'remux', $5)
		RETURNING id, asset, intent, status, retries, created, updated`,
		jobID, account, assetID, string(intent), sourceKey)
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
			-- SHORT work first, then oldest (Tier 2 V4.1). A remux (stream-copy of
			-- an authored file) and a poster are seconds; a loop is short; a derived
			-- detail is minutes. Claiming detail ahead of them is the poster problem
			-- (V3): the quick job waits behind a long transcode and the still/remux
			-- lands late. Tiers: remux + poster = 0, loop = 1, derived detail = 2.
			-- Keyed on MODE (not intent) for remux, because an authored detail's
			-- remux job carries intent 'detail' -- only the mode column tells them apart.
			ORDER BY (CASE
			              WHEN mode = 'remux'     THEN 0
			              WHEN intent = 'poster'  THEN 0
			              WHEN intent = 'loop'    THEN 1
			              ELSE 2
			          END), created
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, account, asset, intent, retries, mode, source_key`,
		staleBefore)

	var (
		cj        ClaimedJob
		sourceKey *string
	)
	if err := row.Scan(&cj.ID, &cj.Account, &cj.Asset, &cj.Intent, &cj.Attempts, &cj.Mode, &sourceKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ClaimedJob{}, ErrNoJob
		}
		return ClaimedJob{}, err
	}
	if sourceKey != nil {
		cj.SourceKey = *sourceKey
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

// CompleteJobNoRendition marks a job succeeded WITHOUT writing a rendition object
// — used when the worker's correct outcome is a refusal (e.g. a ceiling breach
// already recorded as a failed rendition row). The job did its work; there is
// simply no deliverable object.
func (p *Postgres) CompleteJobNoRendition(ctx context.Context, jobID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE jobs SET status = 'succeeded', progress = 1, updated = now() WHERE id = $1`, jobID)
	return err
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

// DeletedAsset is an asset marked for deletion whose bytes the purge sweep must
// remove — the vault key plus the asset id (review ruling 4). The scheduled purge
// is a follow-up job; this query lands now so "two-step delete" is one step and a
// PROVEN query, not one step and a promise.
type DeletedAsset struct {
	ID       string
	Account  string
	VaultKey string
}

// ReclaimableDeletedAssets returns assets marked deleted (deleted_at set) before
// the cutoff — the purge sweep's input. Ordered oldest-first, limited.
func (p *Postgres) ReclaimableDeletedAssets(ctx context.Context, olderThan time.Time, limit int32) ([]DeletedAsset, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, account, vault_key
		FROM assets
		WHERE deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at
		LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeletedAsset{}
	for rows.Next() {
		var d DeletedAsset
		if err := rows.Scan(&d.ID, &d.Account, &d.VaultKey); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PurgeDeletedAsset removes an asset row after its bytes are deleted (the second
// step of the two-step delete). Renditions cascade via the FK.
func (p *Postgres) PurgeDeletedAsset(ctx context.Context, assetID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM assets WHERE id = $1 AND deleted_at IS NOT NULL`, assetID)
	return err
}

// BackfillVaultProbe records probe metadata the WORKER measured for an A/V asset
// that was created probe_status=pending at finalize (review ruling 1), and marks
// it ready. Account-scoped via the asset id (the job carried the account).
func (p *Postgres) BackfillVaultProbe(ctx context.Context, assetID string, v VaultRecord) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE assets SET
			vault_width = $2, vault_height = $3, vault_duration_s = $4,
			vault_codec = $5, vault_container = $6,
			probe_status = 'ready'
		WHERE id = $1`,
		assetID, v.Width, v.Height, v.DurationS, v.Codec, v.Container)
	return err
}

// MarkProbeFailed flags an asset whose object could not be probed (corrupt or
// unsupported). Delivery then refuses with a closed-enum reason.
func (p *Postgres) MarkProbeFailed(ctx context.Context, assetID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE assets SET probe_status = 'failed' WHERE id = $1`, assetID)
	return err
}

// MarkChecksumVerified records that the stored object's checksum was confirmed
// (server-side, ETag, or worker hash) and stores the verified value. Never called
// with an unverified client claim (review ruling 2).
func (p *Postgres) MarkChecksumVerified(ctx context.Context, assetID, checksum string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE assets SET vault_checksum = $2, checksum_verified = true WHERE id = $1`,
		assetID, checksum)
	return err
}

// FailedRenditionForCeiling writes a failed rendition row for an intent the
// worker refused because a ceiling was breached (e.g. detail over the duration
// ceiling), carrying the closed-enum reason. Delivery surfaces it as
// delivery:null + reason (§4.3 honest refusal). One row per (asset,intent).
func (p *Postgres) FailedRenditionForCeiling(ctx context.Context, assetID string, intent plate.Intent, reason plate.ReasonCode) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO renditions (asset, intent, status, reason)
		VALUES ($1, $2, 'failed', $3)
		ON CONFLICT (asset, intent) DO UPDATE SET status = 'failed', reason = EXCLUDED.reason`,
		assetID, string(intent), string(reason))
	return err
}

// MarkNotDerived records that an intent will not be derived automatically,
// because the upload declined derivation (skip_derivations). Terminal for the
// AUTOMATIC path: nothing enqueues it, and delivery answers delivery:null +
// reason `not_derived` rather than `pending` — the distinction that stops a
// caller polling forever for something no job will produce.
//
// `reason` is deliberately left NULL: the status already says everything, and a
// reason paired with it would carry no information the status lacks.
//
// DO NOT overwrite a row that already exists. A real rendition (ready, or a
// failed refusal carrying its reason) is a FACT about work that happened; this
// mark is only the absence of work. ON CONFLICT DO NOTHING keeps an explicit
// later derivation — which is allowed to override a not_derived row — from
// being clobbered if a finalize were ever replayed.
func (p *Postgres) MarkNotDerived(ctx context.Context, assetID string, intent plate.Intent) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO renditions (asset, intent, status)
		VALUES ($1, $2, 'not_derived')
		ON CONFLICT (asset, intent) DO NOTHING`,
		assetID, string(intent))
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
