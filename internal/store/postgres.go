package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chuckyatsuk/plate/internal/id"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/jackc/pgx/v5"
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
	row := p.pool.QueryRow(ctx, `
		SELECT id, account, kind, filename,
		       vault_key, vault_checksum, vault_size_bytes,
		       vault_width, vault_height, vault_duration_s, vault_codec, vault_container,
		       created, deleted_at
		FROM assets
		WHERE account = $1 AND id = $2`, account, assetID)
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
	rows, err := p.pool.Query(ctx, `
		SELECT id, account, kind, filename,
		       vault_key, vault_checksum, vault_size_bytes,
		       vault_width, vault_height, vault_duration_s, vault_codec, vault_container,
		       created, deleted_at
		FROM assets
		WHERE account = $1 AND ($2 = '' OR id > $2)
		ORDER BY id
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
	row := p.pool.QueryRow(ctx, `
		UPDATE assets
		SET deleted_at = now()
		WHERE account = $1 AND id = $2
		RETURNING id, account, kind, filename,
		          vault_key, vault_checksum, vault_size_bytes,
		          vault_width, vault_height, vault_duration_s, vault_codec, vault_container,
		          created, deleted_at`, account, assetID)
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

func (p *Postgres) CreateGrant(ctx context.Context, account string, req plate.GrantRequest) (plate.Grant, error) {
	// Verify EVERY asset in the set belongs to the caller. This is the write-side
	// isolation check: a grant over another account's assets must be refused
	// wholesale (spec Q3, "one grant per SET"), and we must not reveal which
	// asset was foreign. Count owned assets among the requested ids; if the count
	// differs, at least one is foreign or missing → refuse.
	var owned int
	err := p.pool.QueryRow(ctx, `
		SELECT count(*) FROM assets
		WHERE account = $1 AND id = ANY($2)`, account, req.Assets).Scan(&owned)
	if err != nil {
		return plate.Grant{}, err
	}
	if owned != len(req.Assets) {
		return plate.Grant{}, ErrForeignAsset
	}

	gid := id.New()
	created := time.Now().UTC()
	row := p.pool.QueryRow(ctx, `
		INSERT INTO grants (id, account, assets, recipient, created, expires)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, account, assets, recipient, created, expires, revoked_at`,
		gid, account, req.Assets, req.Recipient, created, req.Expires)
	return scanGrantRow(row)
}

func (p *Postgres) AssetOwnedBy(ctx context.Context, account, assetID string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM assets WHERE account = $1 AND id = $2)`,
		account, assetID).Scan(&exists)
	return exists, err
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

func scanAssetRow(row rowScanner) (plate.Asset, error) {
	var (
		a         plate.Asset
		filename  *string
		vkey      string
		vchecksum string
		vsize     int64
		vwidth    *int32
		vheight   *int32
		vdur      *float64
		vcodec    *string
		vcont     *string
		deletedAt *time.Time
	)
	err := row.Scan(&a.Id, &a.Account, &a.Kind, &filename,
		&vkey, &vchecksum, &vsize, &vwidth, &vheight, &vdur, &vcodec, &vcont,
		&a.Created, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return plate.Asset{}, ErrNotFound
	}
	if err != nil {
		return plate.Asset{}, err
	}
	a.Filename = filename
	a.DeletedAt = deletedAt
	a.Vault = plate.VaultObject{
		Key:       vkey,
		Checksum:  vchecksum,
		SizeBytes: vsize,
		Width:     vwidth,
		Height:    vheight,
		DurationS: vdur,
		Codec:     vcodec,
		Container: vcont,
	}
	a.Renditions = []plate.Rendition{}
	return a, nil
}

func (p *Postgres) renditionsFor(ctx context.Context, assetID string) ([]plate.Rendition, error) {
	return renditionsForPool(ctx, p.pool, assetID)
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
