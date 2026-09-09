-- Plate — write-path schema (Phase 2). Runs after 0001 in BOTH the compose
-- Postgres and the ephemeral test container (same goose migrations, no drift).

-- +goose Up

-- Uploads: a brokered PUT that has been presigned but not yet finalized (spec
-- §5.1). Plate never streams the bytes; it records the intent to upload so the
-- reconciliation sweep can find and clean up ORPHANS — a browser that PUTs then
-- closes the tab leaves an object with no asset (spec §5.1, accepted cost). The
-- row is account-scoped like everything else: the key is {account}/{asset-id},
-- and the account is the caller's token claim, never a request parameter (Q3.A).
CREATE TABLE uploads (
    id            TEXT PRIMARY KEY,          -- = the future asset id (Plate owns key gen, §3.3)
    account       TEXT NOT NULL REFERENCES accounts(id),
    key           TEXT NOT NULL,             -- {account}/{asset-id}, the presigned target
    content_type  TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,           -- the exact declared size the PUT is bound to (Q3.C)
    filename      TEXT,
    created       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when finalize succeeds and the asset row is created; a NULL finalized_at
    -- past a grace window is the orphan the sweep reclaims.
    finalized_at  TIMESTAMPTZ
);

CREATE INDEX uploads_account_idx ON uploads (account, id);
-- The sweep queries unfinalized uploads by age.
CREATE INDEX uploads_unfinalized_idx ON uploads (finalized_at, created);

-- Renditions gain the R2 object key and delivery mode so a ready rendition points
-- at real bytes (Phase 1 had status-only rows). Nullable: a pending/failed
-- rendition has no object yet.
ALTER TABLE renditions ADD COLUMN key  TEXT;   -- {account}/{asset-id}/{intent}
ALTER TABLE renditions ADD COLUMN mode TEXT;   -- public|signed|granted (spec Q3.B)

-- Jobs gain the claim/lease/retry columns the worker's SKIP LOCKED loop needs
-- (spec §5.2, Q4). No worker runs in PR-(a), but the schema lands here so the
-- write-path and worker PRs share one migration history.
ALTER TABLE jobs ADD COLUMN locked_at    TIMESTAMPTZ;  -- when a worker claimed it (lease start)
ALTER TABLE jobs ADD COLUMN heartbeat_at TIMESTAMPTZ;  -- last progress beat; a stale lease is reclaimable
ALTER TABLE jobs ADD COLUMN last_error   TEXT;         -- human-readable last failure (reason stays the enum)
-- attempts already covered by retries in 0001; keep that as the count.

-- The queued-jobs index the claim query hits: WHERE status='queued' ORDER BY created.
CREATE INDEX jobs_claim_idx ON jobs (status, created);

-- +goose Down
DROP INDEX IF EXISTS jobs_claim_idx;
ALTER TABLE jobs DROP COLUMN IF EXISTS last_error;
ALTER TABLE jobs DROP COLUMN IF EXISTS heartbeat_at;
ALTER TABLE jobs DROP COLUMN IF EXISTS locked_at;
ALTER TABLE renditions DROP COLUMN IF EXISTS mode;
ALTER TABLE renditions DROP COLUMN IF EXISTS key;
DROP INDEX IF EXISTS uploads_unfinalized_idx;
DROP INDEX IF EXISTS uploads_account_idx;
DROP TABLE IF EXISTS uploads;
