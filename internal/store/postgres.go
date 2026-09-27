package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the one real Store implementation. Every query predicates on the
// caller's account (spec Q3.A) — that predicate IS the account-isolation
// boundary, which is why the conformance test runs against this code and not a
// stand-in.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open connects a pgxpool to connString. The caller owns the lifecycle (Close).
func Open(ctx context.Context, connString string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("store: pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the pool.
func (p *Postgres) Close() { p.pool.Close() }

// Pool exposes the underlying pool for test seeding. Tests seed A and B's data
// through it; the service NEVER bypasses the account-scoped methods below.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

var _ Store = (*Postgres)(nil)

func (p *Postgres) GetAsset(ctx context.Context, account, assetID string) (plate.Asset, error) {
	// The predicate that carries the whole isolation guarantee: account AND id.
	// A B-owned asset requested by A matches zero rows → ErrNotFound, which the
	// service renders as a 404 that names nothing about B.
	row := p.pool.QueryRow(ctx, assetSelect+`
		FROM assets a`+assetJoin+`
		WHERE a.account = $1 AND a.id = $2`, account, assetID)
	a, err := scanAsset(ctx, p.pool, row)
	if err != nil {
		return plate.Asset{}, err
	}
	return a, nil
}

func (p *Postgres) ListAssets(ctx context.Context, account, cursor string, limit int32) (plate.AssetPage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Cursor is the last id of the previous page (ids are lexicographically
	// ordered ULIDs). Scoped to account — there is no cross-account listing.
	rows, err := p.pool.Query(ctx, assetSelect+`
		FROM assets a`+assetJoin+`
		WHERE a.account = $1 AND ($2 = '' OR a.id > $2)
		ORDER BY a.id
		LIMIT $3`, account, cursor, limit+1)
	if err != nil {
		return plate.AssetPage{}, err
	}
	defer rows.Close()

	var page plate.AssetPage
	page.Items = []plate.Asset{}
	for rows.Next() {
		a, err := scanAssetRow(rows)
		if err != nil {
			return plate.AssetPage{}, err
		}
		page.Items = append(page.Items, a)
	}
	if err := rows.Err(); err != nil {
		return plate.AssetPage{}, err
	}
	// If we fetched limit+1, there is a next page; trim and set the cursor.
	if int32(len(page.Items)) > limit {
		last := page.Items[limit-1].Id
		page.Items = page.Items[:limit]
		page.NextCursor = &last
	}
	// Load renditions for the page's assets.
	for i := range page.Items {
		rs, err := p.renditionsFor(ctx, page.Items[i].Id)
		if err != nil {
			return plate.AssetPage{}, err
		}
		page.Items[i].Renditions = rs
	}
	return page, nil
}

func (p *Postgres) MarkAssetDeleted(ctx context.Context, account, assetID string) (plate.Asset, error) {
	// The UPDATE runs in a CTE so the returned row goes through the same
	// projection (and upload join) as every other asset read.
	row := p.pool.QueryRow(ctx, `
		WITH a AS (
			UPDATE assets
			SET deleted_at = now()
			WHERE account = $1 AND id = $2
			RETURNING *
		)`+assetSelect+`
		FROM a`+assetJoin, account, assetID)
	return scanAsset(ctx, p.pool, row)
}

func (p *Postgres) GetJob(ctx context.Context, account, jobID string) (plate.Job, error) {
	var (
		j        plate.Job
		progress *float64
		reason   *string
		created  time.Time
		updated  time.Time
	)
	err := p.pool.QueryRow(ctx, `
		SELECT id, asset, intent, status, progress, retries, reason, created, updated
		FROM jobs
		WHERE account = $1 AND id = $2`, account, jobID).
		Scan(&j.Id, &j.Asset, &j.Intent, &j.Status, &progress, &j.Retries, &reason, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Job{}, ErrNotFound
	}
	if err != nil {
		return plate.Job{}, err
	}
	j.Progress = progress
	if reason != nil {
		rc := plate.ReasonCode(*reason)
		j.Reason = &rc
	}
	j.Created = &created
	j.Updated = &updated
	return j, nil
}

func (p *Postgres) GetGrant(ctx context.Context, account, grantID string) (plate.Grant, error) {
	return p.scanGrant(ctx, `
		SELECT id, account, assets, recipient, created, expires, revoked_at
		FROM grants
		WHERE account = $1 AND id = $2`, account, grantID)
}

func (p *Postgres) RevokeGrant(ctx context.Context, account, grantID string) (plate.Grant, error) {
	return p.scanGrant(ctx, `
		UPDATE grants
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE account = $1 AND id = $2
		RETURNING id, account, assets, recipient, created, expires, revoked_at`, account, grantID)
}

// assetClass is how one requested id relates to the caller's account when a
// capability (a grant or an export) is issued over a set of ids.
type assetClass int

const (
	// classRefused: another account's asset, or an id that never existed.
	// Indistinguishable by design — either refuses the whole set, no id named.
	classRefused assetClass = iota
	// classLive: an asset row owned by the caller, not deleted.
	classLive
	// classGone: owned but deleted (row still present until the sweep), OR
	// purged — see purgedSQL.
	classGone
)

type classifiedID struct {
	id    string
	class assetClass
}

// purgedSQL is THE test for "this id was once an asset of account $1 that the
// deleted-asset sweep has since purged": no asset row remains anywhere, yet the
// account's own finalized ORIGINAL upload with that id exists (finalize turns
// the upload id into the asset id, and upload rows are never removed). idExpr
// is the SQL expression for the id; the account must be bound as $1. Shared by
// the set classification (grants, exports) and AssetPurged (delivery), so the
// three can never disagree about what "purged" means.
func purgedSQL(idExpr string) string {
	return `(NOT EXISTS (SELECT 1 FROM assets x WHERE x.id = ` + idExpr + `)
		 AND EXISTS (SELECT 1 FROM uploads u
		             WHERE u.account = $1 AND u.id = ` + idExpr + `
		               AND u.finalized_at IS NOT NULL
		               AND u.rendition_asset IS NULL))`
}

// classifyAssetSet classifies every DISTINCT requested id against the caller's
// account in one snapshot, ordered by id. This is the write-side isolation
// check for every capability issued over a set: a set naming another account's
// asset must be refused wholesale (spec Q3, "one grant per SET") without
// revealing which id was foreign. Distinct ids, so a set that names the same
// asset twice is not mistaken for one naming a foreign asset.
func (p *Postgres) classifyAssetSet(ctx context.Context, account string, ids []string) ([]classifiedID, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT r.id,
		       a.id IS NOT NULL         AS owned,
		       a.deleted_at IS NOT NULL AS deleted,
		       `+purgedSQL("r.id")+`   AS purged
		FROM (SELECT DISTINCT unnest($2::text[]) AS id) r
		LEFT JOIN assets a ON a.id = r.id AND a.account = $1
		ORDER BY r.id`, account, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []classifiedID
	for rows.Next() {
		var (
			c                      classifiedID
			owned, deleted, purged bool
		)
		if err := rows.Scan(&c.id, &owned, &deleted, &purged); err != nil {
			return nil, err
		}
		switch {
		case owned && deleted, purged:
			c.class = classGone
		case owned:
			c.class = classLive
		default:
			c.class = classRefused
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateGrant(ctx context.Context, account string, req plate.GrantRequest) (plate.Grant, error) {
	// Live and gone ids are both the caller's: the grant covers the full
	// requested set, and the gone ones (deleted or purged) are reported so the
	// caller knows they will resolve `deleted`. Any refused id refuses the set.
	classes, err := p.classifyAssetSet(ctx, account, req.Assets)
	if err != nil {
		return plate.Grant{}, err
	}
	var gone []string
	for _, c := range classes {
		switch c.class {
		case classRefused:
			return plate.Grant{}, ErrForeignAsset
		case classGone:
			gone = append(gone, c.id)
		}
	}

	gid := id.New()
	created := time.Now().UTC()
	row := p.pool.QueryRow(ctx, `
		INSERT INTO grants (id, account, assets, recipient, created, expires)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, account, assets, recipient, created, expires, revoked_at`,
		gid, account, req.Assets, req.Recipient, created, req.Expires)
	g, err := scanGrantRow(row)
	if err != nil {
		return plate.Grant{}, err
	}
	if len(gone) > 0 {
		g.GoneAssets = &gone
	}
	return g, nil
}

// AssetPurged: see the interface doc. Same purged test as the set
// classification (purgedSQL).
func (p *Postgres) AssetPurged(ctx context.Context, account, assetID string) (bool, error) {
	var purged bool
	err := p.pool.QueryRow(ctx, `SELECT `+purgedSQL("$2"), account, assetID).Scan(&purged)
	return purged, err
}

// ResolveGrantForDelivery resolves a grant BY ID for the delivery hot path. It
// is intentionally not account-scoped (see the interface doc): a grant carries
// its own account and is itself the capability. One row read returns everything
// the verdict needs — existence, whether the frozen set covers the asset,
// revocation, expiry, and the owning account — computed in SQL so "live" is one
// consistent snapshot (now() evaluated once) rather than a read-then-compare
// race. A missing grant is ErrNotFound (leak-safe: the handler renders both
// "no such grant" and "not covered" as the same not-found to the recipient).
func (p *Postgres) ResolveGrantForDelivery(ctx context.Context, grantID, assetID string) (GrantVerdict, error) {
	var v GrantVerdict
	v.Found = true
	err := p.pool.QueryRow(ctx, `
		SELECT account,
		       $2 = ANY(assets)          AS covers,
		       revoked_at IS NOT NULL    AS revoked,
		       expires <= now()          AS expired
		FROM grants
		WHERE id = $1`, grantID, assetID).
		Scan(&v.Account, &v.Covers, &v.Revoked, &v.Expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return GrantVerdict{Found: false}, nil
	}
	if err != nil {
		return GrantVerdict{}, err
	}
	return v, nil
}

// ── exports (Tier 1: the export capability) ─────────────────────────────────

func (p *Postgres) GetExport(ctx context.Context, account, exportID string) (plate.Export, error) {
	return scanExportRow(p.pool.QueryRow(ctx, `
		SELECT id, account, assets, note, created, expires, revoked_at
		FROM exports
		WHERE account = $1 AND id = $2`, account, exportID))
}

func (p *Postgres) RevokeExport(ctx context.Context, account, exportID string) (plate.Export, error) {
	return scanExportRow(p.pool.QueryRow(ctx, `
		UPDATE exports
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE account = $1 AND id = $2
		RETURNING id, account, assets, note, created, expires, revoked_at`, account, exportID))
}

func (p *Postgres) CreateExport(ctx context.Context, account string, req plate.ExportRequest) (plate.Export, error) {
	// Same classification as CreateGrant (classifyAssetSet): a foreign or
	// never-existed id refuses the whole set with the same indistinguishable
	// ErrForeignAsset. Unlike a grant, an export is a route to ORIGINAL BYTES, so
	// a gone asset is not carried in the frozen set at all: there are no bytes
	// to hand out (purged) or the owner has said they must not leave (deleted).
	// Gone ids are reported in GoneAssets instead. The frozen set is the live
	// ids, each once, in request order.
	classes, err := p.classifyAssetSet(ctx, account, req.Assets)
	if err != nil {
		return plate.Export{}, err
	}
	class := make(map[string]assetClass, len(classes))
	for _, c := range classes {
		if c.class == classRefused {
			return plate.Export{}, ErrForeignAsset
		}
		class[c.id] = c.class
	}
	var live, gone []string
	seen := make(map[string]bool, len(req.Assets))
	for _, aid := range req.Assets {
		if seen[aid] {
			continue
		}
		seen[aid] = true
		if class[aid] == classLive {
			live = append(live, aid)
		} else {
			gone = append(gone, aid)
		}
	}
	if len(live) == 0 {
		// Every requested id is the caller's and every one is gone: there is
		// nothing an export could serve, and an empty frozen set is not an
		// export. A named refusal, not a 403 — these are the caller's own ids.
		return plate.Export{}, ErrAssetsGone
	}

	eid := id.New()
	created := time.Now().UTC()
	e, err := scanExportRow(p.pool.QueryRow(ctx, `
		INSERT INTO exports (id, account, assets, note, created, expires)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, account, assets, note, created, expires, revoked_at`,
		eid, account, live, req.Note, created, req.Expires))
	if err != nil {
		return plate.Export{}, err
	}
	if len(gone) > 0 {
		e.GoneAssets = &gone
	}
	return e, nil
}

// ResolveExportForDelivery resolves an export BY ID for the download byte edge.
// Same one-row, one-snapshot shape as ResolveGrantForDelivery (see that doc for
// why it is deliberately not account-scoped) — but it runs on EVERY fetch with
// no cache in front, so a revocation is effective on the very next download.
func (p *Postgres) ResolveExportForDelivery(ctx context.Context, exportID, assetID string) (ExportVerdict, error) {
	var v ExportVerdict
	v.Found = true
	err := p.pool.QueryRow(ctx, `
		SELECT account,
		       $2 = ANY(assets)          AS covers,
		       revoked_at IS NOT NULL    AS revoked,
		       expires <= now()          AS expired
		FROM exports
		WHERE id = $1`, exportID, assetID).
		Scan(&v.Account, &v.Covers, &v.Revoked, &v.Expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExportVerdict{Found: false}, nil
	}
	if err != nil {
		return ExportVerdict{}, err
	}
	return v, nil
}

func scanExportRow(row pgx.Row) (plate.Export, error) {
	var (
		e         plate.Export
		note      *string
		revokedAt *time.Time
	)
	err := row.Scan(&e.Id, &e.Account, &e.Assets, &note, &e.Created, &e.Expires, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Export{}, ErrNotFound
	}
	if err != nil {
		return plate.Export{}, err
	}
	e.Note = note
	e.RevokedAt = revokedAt
	return e, nil
}

// CreateAccount provisions an account row — the CONTROL-PLANE operation that must
// happen before an account can own uploads (uploads.account REFERENCES
// accounts.id, so a token whose account has no row 409s at first upload). It is
// deliberately NOT on the Store interface: account lifecycle is an operator
// action (the `plate accounts create` subcommand), not part of the account-scoped
// data-plane surface the isolation-conformance test drives — putting it there
// would speculatively add a cross-account provisioning verb to that enum (spec Q2,
// designer 2026-09-10). Idempotent: re-provisioning the same id updates its
// storage bucket/prefix rather than erroring.
func (p *Postgres) CreateAccount(ctx context.Context, accountID, bucket, prefix string) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO accounts (id, storage_bucket, storage_prefix)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET storage_bucket = EXCLUDED.storage_bucket,
		                               storage_prefix = EXCLUDED.storage_prefix`,
		accountID, bucket, prefix)
	if err != nil {
		return fmt.Errorf("store: create account %q: %w", accountID, err)
	}
	return nil
}

// ProvisionAccount is the self-provisioning verb's store half (see the
// interface doc). Unlike CreateAccount (the operator CLI's upsert, which
// overwrites bucket/prefix), it NEVER modifies an existing row: DO NOTHING on
// conflict, then read the row back. Two concurrent first calls both succeed;
// exactly one reports created=true.
func (p *Postgres) ProvisionAccount(ctx context.Context, account string) (plate.Account, bool, error) {
	var a plate.Account
	err := p.pool.QueryRow(ctx, `
		INSERT INTO accounts (id) VALUES ($1)
		ON CONFLICT (id) DO NOTHING
		RETURNING id, created`, account).Scan(&a.Id, &a.Created)
	if err == nil {
		return a, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return plate.Account{}, false, fmt.Errorf("store: provision account: %w", err)
	}
	// Conflict: the row already exists. Read it back unchanged.
	if err := p.pool.QueryRow(ctx, `SELECT id, created FROM accounts WHERE id = $1`, account).
		Scan(&a.Id, &a.Created); err != nil {
		return plate.Account{}, false, fmt.Errorf("store: provision account (read back): %w", err)
	}
	return a, false, nil
}

func (p *Postgres) AssetOwnedBy(ctx context.Context, account, assetID string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM assets WHERE account = $1 AND id = $2)`,
		account, assetID).Scan(&exists)
	return exists, err
}

// ── write path (Phase 2) ────────────────────────────────────────────────────

func (p *Postgres) CreateUpload(ctx context.Context, account string, u Upload) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO uploads (id, account, key, content_type, size_bytes, filename, skip_derivations, rendition_asset, rendition_intent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		u.ID, account, u.Key, u.ContentType, u.SizeBytes, nullStr(u.Filename), u.SkipDerivations,
		nullStr(u.RenditionAsset), nullStr(u.RenditionIntent))
	if err != nil {
		// A foreign-key violation on uploads.account means the account was never
		// provisioned (`plate accounts create`) — a client/config error, not a
		// server fault. Surface it as ErrUnknownAccount so the handler answers a
		// legible 4xx instead of a bare 500 (the "first upload against a missing
		// account" trap, spec Q2).
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			return ErrUnknownAccount
		}
		return fmt.Errorf("store: create upload: %w", err)
	}
	return nil
}

func (p *Postgres) GetUpload(ctx context.Context, account, uploadID string) (Upload, error) {
	var (
		u        Upload
		filename *string
		rAsset   *string
		rIntent  *string
	)
	err := p.pool.QueryRow(ctx, `
		SELECT id, account, key, content_type, size_bytes, filename, swept_at, skip_derivations, rendition_asset, rendition_intent
		FROM uploads
		WHERE account = $1 AND id = $2`, account, uploadID).
		Scan(&u.ID, &u.Account, &u.Key, &u.ContentType, &u.SizeBytes, &filename, &u.SweptAt, &u.SkipDerivations, &rAsset, &rIntent)
	if errors.Is(err, pgx.ErrNoRows) {
		return Upload{}, ErrNotFound
	}
	if err != nil {
		return Upload{}, err
	}
	if filename != nil {
		u.Filename = *filename
	}
	if rAsset != nil {
		u.RenditionAsset = *rAsset
	}
	if rIntent != nil {
		u.RenditionIntent = *rIntent
	}
	return u, nil
}

func (p *Postgres) FinalizeUpload(ctx context.Context, account, uploadID string, v VaultRecord) (plate.Asset, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return plate.Asset{}, err
	}
	defer tx.Rollback(ctx)

	// Recover the account-scoped upload; a B-owned upload id is not finalizable by
	// A (ErrNotFound). FOR UPDATE so a concurrent finalize can't double-create.
	var (
		key      string
		ctype    string
		filename *string
		finAt    *time.Time
		sweptAt  *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT key, content_type, filename, finalized_at, swept_at
		FROM uploads WHERE account = $1 AND id = $2 FOR UPDATE`,
		account, uploadID).Scan(&key, &ctype, &filename, &finAt, &sweptAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Asset{}, ErrNotFound
	}
	if err != nil {
		return plate.Asset{}, err
	}

	// Reclaimed orphan: the sweep already deleted this upload's vault bytes, so
	// there is nothing to finalize into an asset. Refuse (410) rather than create
	// an asset pointing at a deleted object. Checked before the finalized_at
	// idempotency branch because a swept upload was never finalized.
	if sweptAt != nil {
		return plate.Asset{}, ErrUploadGone
	}

	// Idempotent: if already finalized, return the existing asset rather than
	// creating a second (a retried finalize is not an error).
	if finAt != nil {
		a, gerr := p.getAssetTx(ctx, tx, account, uploadID)
		if gerr != nil {
			return plate.Asset{}, gerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return plate.Asset{}, cerr
		}
		return a, nil
	}

	// Create the asset + vault object (the upload id becomes the asset id — Plate
	// owns key generation, §3.3). The vault object is ALWAYS created; a ceiling
	// breach is a DELIVERY refusal, not a storage refusal (spec §5.3).
	probeStatus := v.ProbeStatus
	if probeStatus == "" {
		probeStatus = "ready"
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO assets (id, account, kind, filename,
		    vault_key, vault_checksum, vault_size_bytes,
		    vault_width, vault_height, vault_duration_s, vault_codec, vault_container,
		    probe_status, checksum_verified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		uploadID, account, string(v.Kind), filename,
		key, v.Checksum, v.SizeBytes,
		v.Width, v.Height, v.DurationS, v.Codec, v.Container,
		probeStatus, v.ChecksumVerified)
	if err != nil {
		return plate.Asset{}, fmt.Errorf("store: create asset on finalize: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		UPDATE uploads SET finalized_at = now() WHERE account = $1 AND id = $2`,
		account, uploadID); err != nil {
		return plate.Asset{}, err
	}

	a, err := p.getAssetTx(ctx, tx, account, uploadID)
	if err != nil {
		return plate.Asset{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return plate.Asset{}, err
	}
	return a, nil
}

func (p *Postgres) ReclaimableUploads(ctx context.Context, olderThan time.Time, limit int32) ([]Upload, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, account, key, content_type, size_bytes, filename
		FROM uploads
		WHERE finalized_at IS NULL AND swept_at IS NULL AND created < $1
		ORDER BY created
		LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Upload{}
	for rows.Next() {
		var (
			u        Upload
			filename *string
		)
		if err := rows.Scan(&u.ID, &u.Account, &u.Key, &u.ContentType, &u.SizeBytes, &filename); err != nil {
			return nil, err
		}
		if filename != nil {
			u.Filename = *filename
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// MarkUploadSwept stamps swept_at on a reclaimed orphan so it is not re-selected
// by ReclaimableUploads. Not account-scoped: the reconcile sweep is a system job
// that already selected this id from ReclaimableUploads. Idempotent (a second
// mark is a harmless no-op update).
func (p *Postgres) MarkUploadSwept(ctx context.Context, uploadID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE uploads SET swept_at = now() WHERE id = $1`, uploadID)
	return err
}

// getAssetTx reads an account-scoped asset within a transaction (used by
// finalize so the created asset is read in the same tx).
func (p *Postgres) getAssetTx(ctx context.Context, tx pgx.Tx, account, assetID string) (plate.Asset, error) {
	row := tx.QueryRow(ctx, assetSelect+`
		FROM assets a`+assetJoin+`
		WHERE a.account = $1 AND a.id = $2`, account, assetID)
	a, err := scanAssetRow(row)
	if err != nil {
		return plate.Asset{}, err
	}
	// A freshly-finalized asset has no renditions yet.
	a.Renditions = []plate.Rendition{}
	return a, nil
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ── scanning helpers ────────────────────────────────────────────────────────

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAsset(ctx context.Context, pool *pgxpool.Pool, row pgx.Row) (plate.Asset, error) {
	a, err := scanAssetRow(row)
	if err != nil {
		return plate.Asset{}, err
	}
	// Attach renditions (a second scoped read by asset id, which we already
	// confirmed belongs to the account).
	rs, err := renditionsForPool(ctx, pool, a.Id)
	if err != nil {
		return plate.Asset{}, err
	}
	a.Renditions = rs
	return a, nil
}

// assetSelect is the ONE projection every asset read uses, over an `a` that is
// the assets table (or a CTE of its rows) joined by assetJoin. Keeping it in one
// place is what stops a field (content_type, checksum_verified) from appearing
// on one read path and silently missing from another.
const assetSelect = `
		SELECT a.id, a.account, a.kind, a.filename,
		       a.vault_key, a.vault_checksum, a.checksum_verified, a.vault_size_bytes,
		       a.vault_width, a.vault_height, a.vault_duration_s, a.vault_codec, a.vault_container,
		       a.created, a.deleted_at, u.content_type`

// assetJoin attaches the asset's own ORIGINAL upload row, the only place Plate
// records the declared content type (finalize turns the upload id into the
// asset id). The declared type is bound into the presigned PUT's signature, so
// it is the stored object's Content-Type, not a later claim. Same account as the
// asset, so the join cannot widen scope; an asset with no upload row (seeded
// directly, never brokered) simply has no content_type.
const assetJoin = `
		LEFT JOIN uploads u ON u.id = a.id AND u.account = a.account AND u.rendition_asset IS NULL`

func scanAssetRow(row rowScanner) (plate.Asset, error) {
	var (
		a         plate.Asset
		filename  *string
		vkey      string
		vchecksum string
		vverified bool
		vsize     int64
		vwidth    *int32
		vheight   *int32
		vdur      *float64
		vcodec    *string
		vcont     *string
		deletedAt *time.Time
		ctype     *string
	)
	err := row.Scan(&a.Id, &a.Account, &a.Kind, &filename,
		&vkey, &vchecksum, &vverified, &vsize, &vwidth, &vheight, &vdur, &vcodec, &vcont,
		&a.Created, &deletedAt, &ctype)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Asset{}, ErrNotFound
	}
	if err != nil {
		return plate.Asset{}, err
	}
	a.Filename = filename
	a.DeletedAt = deletedAt
	a.ContentType = ctype
	a.Vault = plate.VaultObject{
		Key:              vkey,
		Checksum:         vchecksum,
		ChecksumVerified: vverified,
		SizeBytes:        vsize,
		Width:            vwidth,
		Height:           vheight,
		DurationS:        vdur,
		Codec:            vcodec,
		Container:        vcont,
	}
	a.Renditions = []plate.Rendition{}
	return a, nil
}

func (p *Postgres) renditionsFor(ctx context.Context, assetID string) ([]plate.Rendition, error) {
	return renditionsForPool(ctx, p.pool, assetID)
}

// RenditionStatusFor returns the current status of one (asset, intent) rendition,
// or ("", false) if no row exists. Used by the authored-rendition path (Tier 2
// V4.1) to reject authoring over an existing `ready` rendition (409): replacing a
// ready rendition is an explicit delete-then-author, not a silent overwrite. A
// non-ready row (pending/failed/not_derived) does NOT block — authoring an intent
// that failed or was declined is exactly the on-demand request that is allowed.
func (p *Postgres) RenditionStatusFor(ctx context.Context, assetID string, intent plate.Intent) (plate.RenditionStatus, bool, error) {
	var status string
	err := p.pool.QueryRow(ctx, `
		SELECT status FROM renditions WHERE asset = $1 AND intent = $2`,
		assetID, string(intent)).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return plate.RenditionStatus(status), true, nil
}

func renditionsForPool(ctx context.Context, pool *pgxpool.Pool, assetID string) ([]plate.Rendition, error) {
	rows, err := pool.Query(ctx, `
		SELECT intent, status, width, height, duration_s, has_audio, reason
		FROM renditions WHERE asset = $1 ORDER BY intent`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []plate.Rendition{}
	for rows.Next() {
		var (
			r      plate.Rendition
			reason *string
		)
		if err := rows.Scan(&r.Intent, &r.Status, &r.Width, &r.Height, &r.DurationS, &r.HasAudio, &reason); err != nil {
			return nil, err
		}
		if reason != nil {
			rc := plate.ReasonCode(*reason)
			r.Reason = &rc
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) scanGrant(ctx context.Context, query string, args ...any) (plate.Grant, error) {
	return scanGrantRow(p.pool.QueryRow(ctx, query, args...))
}

func scanGrantRow(row pgx.Row) (plate.Grant, error) {
	var (
		g         plate.Grant
		recipient *string
		revokedAt *time.Time
	)
	err := row.Scan(&g.Id, &g.Account, &g.Assets, &recipient, &g.Created, &g.Expires, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Grant{}, ErrNotFound
	}
	if err != nil {
		return plate.Grant{}, err
	}
	g.Recipient = recipient
	g.RevokedAt = revokedAt
	return g, nil
}
