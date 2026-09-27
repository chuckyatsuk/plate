package store

// Server-side SHA-256 of every vault object (Exit support, P3). The worker is
// the only writer: it hashes A/V originals while a derive job downloads them,
// and a sweep hashes everything else — new images and documents, and the
// backlog of assets that predate this — one streamed object at a time. These
// are system operations (the worker holds no token), keyed by asset id like
// BackfillVaultProbe.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ChecksumPrefix is the algorithm tag on a server-computed vault checksum.
const ChecksumPrefix = "sha256:"

// ErrNoChecksumPending is returned by ClaimChecksumCandidate when no live asset
// lacks a verified SHA-256 (or every one that does is backing off after a
// failed attempt, or has a derive job that will hash it).
var ErrNoChecksumPending = errors.New("store: no asset awaits a checksum")

// ErrChecksumMismatch is returned by MarkChecksumVerified when the asset
// already holds a VERIFIED sha256 that differs from the one just computed. A
// vault object is immutable, so this means the stored bytes changed (or a read
// was corrupt): the recorded value is kept and the caller must surface it.
var ErrChecksumMismatch = errors.New("store: computed sha256 differs from the recorded verified sha256")

// ChecksumCandidate is one asset the sweep has claimed for hashing.
type ChecksumCandidate struct {
	ID        string
	Account   string
	VaultKey  string
	SizeBytes int64
}

// pendingChecksumSQL is THE predicate for "this asset still needs a
// server-side SHA-256": not deleted (its bytes are leaving; nothing may serve
// them), and not already holding a verified sha256. An md5-verified asset is
// still pending — md5 is the ETag check a client can opt into, not the digest
// Plate records for every object. Shared by the claim and the backlog report so
// "pending" means one thing.
const pendingChecksumSQL = `a.deleted_at IS NULL
	AND NOT (a.checksum_verified AND a.vault_checksum LIKE 'sha256:%')`

// ClaimChecksumCandidate claims ONE asset for hashing and stamps its
// checksum_checked_at, so a concurrent worker skips it (SKIP LOCKED) and, if the
// attempt fails, it is not retried before retryBefore. Order: never-tried
// first, then newest first — a fresh upload is hashed promptly while a backlog
// drains behind it. An asset with a queued or running derive job is left to
// that job, which downloads (and hashes) the same bytes anyway.
func (p *Postgres) ClaimChecksumCandidate(ctx context.Context, retryBefore time.Time) (ChecksumCandidate, error) {
	var c ChecksumCandidate
	err := p.pool.QueryRow(ctx, `
		UPDATE assets SET checksum_checked_at = now()
		WHERE id = (
			SELECT a.id FROM assets a
			WHERE `+pendingChecksumSQL+`
			  AND (a.checksum_checked_at IS NULL OR a.checksum_checked_at < $1)
			  AND NOT EXISTS (SELECT 1 FROM jobs j
			                  WHERE j.asset = a.id AND j.mode = 'derive'
			                    AND j.status IN ('queued', 'running'))
			ORDER BY a.checksum_checked_at NULLS FIRST, a.created DESC, a.id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, account, vault_key, vault_size_bytes`, retryBefore).
		Scan(&c.ID, &c.Account, &c.VaultKey, &c.SizeBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return ChecksumCandidate{}, ErrNoChecksumPending
	}
	if err != nil {
		return ChecksumCandidate{}, fmt.Errorf("store: claim checksum candidate: %w", err)
	}
	return c, nil
}

// ReleaseChecksumClaim clears a claim whose read was interrupted (shutdown,
// an operator's Ctrl-C) rather than failed, so the next pass takes the asset
// straight away instead of after the failure back-off.
func (p *Postgres) ReleaseChecksumClaim(ctx context.Context, assetID string) error {
	_, err := p.pool.Exec(ctx, `UPDATE assets SET checksum_checked_at = NULL WHERE id = $1`, assetID)
	return err
}

// MarkChecksumVerified records a SHA-256 the worker computed from the stored
// object itself ("sha256:<hex>"), as the verified vault checksum. Never called
// with a client claim (review ruling 2). It supersedes an md5 recorded at
// finalize (same object, stronger digest). Idempotent for the same value; a
// DIFFERENT verified sha256 already on the row is never overwritten —
// ErrChecksumMismatch. A missing asset (purged meanwhile) is a no-op.
func (p *Postgres) MarkChecksumVerified(ctx context.Context, assetID, checksum string) error {
	if len(checksum) != len(ChecksumPrefix)+64 || checksum[:len(ChecksumPrefix)] != ChecksumPrefix {
		return fmt.Errorf("store: checksum %q is not sha256:<64 hex>", checksum)
	}
	var updated, exists bool
	err := p.pool.QueryRow(ctx, `
		WITH upd AS (
			UPDATE assets SET vault_checksum = $2, checksum_verified = true
			WHERE id = $1
			  AND NOT (checksum_verified AND vault_checksum LIKE 'sha256:%' AND vault_checksum <> $2)
			RETURNING 1
		)
		SELECT EXISTS (SELECT 1 FROM upd), EXISTS (SELECT 1 FROM assets WHERE id = $1)`,
		assetID, checksum).Scan(&updated, &exists)
	if err != nil {
		return fmt.Errorf("store: mark checksum verified: %w", err)
	}
	if !updated && exists {
		return ErrChecksumMismatch
	}
	return nil
}

// ChecksumBacklog is the operator's view of the sha256 backfill.
type ChecksumBacklog struct {
	Live         int64 // assets not deleted
	Verified     int64 // live assets holding a verified sha256
	Pending      int64 // live assets still without one
	PendingBytes int64 // their total vault size — what a backfill must read
	Attempted    int64 // pending assets already tried at least once (a failed read backs off)
}

// ChecksumBacklogStatus reports how far the sha256 backfill has got, across
// every account (an operator report; it returns counts, never ids).
func (p *Postgres) ChecksumBacklogStatus(ctx context.Context) (ChecksumBacklog, error) {
	var b ChecksumBacklog
	err := p.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE a.deleted_at IS NULL),
		       count(*) FILTER (WHERE a.deleted_at IS NULL AND NOT (`+pendingChecksumSQL+`)),
		       count(*) FILTER (WHERE `+pendingChecksumSQL+`),
		       COALESCE(sum(a.vault_size_bytes) FILTER (WHERE `+pendingChecksumSQL+`), 0),
		       count(*) FILTER (WHERE `+pendingChecksumSQL+` AND a.checksum_checked_at IS NOT NULL)
		FROM assets a`).Scan(&b.Live, &b.Verified, &b.Pending, &b.PendingBytes, &b.Attempted)
	if err != nil {
		return ChecksumBacklog{}, fmt.Errorf("store: checksum backlog: %w", err)
	}
	return b, nil
}
