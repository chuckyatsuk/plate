-- Plate — read-path schema (Phase 1).
--
-- This is the SINGLE source of truth for the schema. The SAME file runs in the
-- shipped docker-compose Postgres (so `docker compose up` works for a stranger)
-- and in the ephemeral test container the isolation conformance test starts.
-- Running the real migrations in test — never a hand-written test schema — is
-- what keeps the two from drifting (the recurring bug class this project
-- exists to escape, spec §6).
--
-- The load-bearing invariant here is account scoping (spec §3.2, Q3.A): every
-- account-scoped row carries `account`, and every query the service makes
-- predicates on it. Cross-account isolation is enforced in the WHERE clause,
-- which is exactly where the bug lives — so it is proven against real SQL.

-- +goose Up

-- Accounts are a first-class table (spec Q2): an OPAQUE foreign reference (an id
-- plus storage config) with NO users, roles, or permissions. Identity is a
-- separate concern. Storage config is what lets ONE deployment serve many
-- accounts with per-account bucket/key prefixes (spec Q4).
CREATE TABLE accounts (
    id              TEXT PRIMARY KEY,
    -- Per-account storage prefix, e.g. the bucket path a minted key sits under.
    -- Keys are `{account}/{asset-id}` (spec §3.2); this is the per-account
    -- prefix that makes A's bytes structurally unreachable from B's key space.
    storage_bucket  TEXT NOT NULL DEFAULT '',
    storage_prefix  TEXT NOT NULL DEFAULT '',
    created         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One asset = one uploaded file: exactly one immutable vault object, plus zero
-- or more renditions (spec §3.1). The vault columns live inline here; note there
-- is deliberately NO vault delivery-URL column — the absence is the design.
CREATE TABLE assets (
    id              TEXT PRIMARY KEY,
    account         TEXT NOT NULL REFERENCES accounts(id),
    kind            TEXT NOT NULL,      -- MediaKind: image|video|audio|document
    filename        TEXT,

    -- Vault object (immutable original). Storage key is `{account}/{asset-id}`;
    -- server-to-server use only, never handed to a browser (spec §3.1).
    vault_key       TEXT NOT NULL,
    vault_checksum  TEXT NOT NULL,
    vault_size_bytes BIGINT NOT NULL,
    vault_width     INTEGER,
    vault_height    INTEGER,
    vault_duration_s DOUBLE PRECISION,
    vault_codec     TEXT,
    vault_container TEXT,

    created         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

-- The query the whole isolation guarantee rests on is `WHERE account=$1 AND
-- id=$2`; index it so scope is both correct and cheap.
CREATE INDEX assets_account_idx ON assets (account, id);

-- Renditions: bounded, browser-reachable derivatives — the only tier a browser
-- can reach (spec §3.1). One row per (asset, intent).
CREATE TABLE renditions (
    asset       TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    intent      TEXT NOT NULL,      -- Intent enum
    status      TEXT NOT NULL,      -- ready|pending|failed
    width       INTEGER,
    height      INTEGER,
    duration_s  DOUBLE PRECISION,
    has_audio   BOOLEAN,
    reason      TEXT,               -- ReasonCode, present only when status=failed
    PRIMARY KEY (asset, intent)
);

-- Jobs: durable state for a queued derivation (spec §5.2). No worker in Phase 1,
-- but the table exists so the isolation conformance test can seed a B-owned job
-- and prove getJob is account-scoped like every other endpoint (spec Q4: "at
-- EVERY endpoint").
CREATE TABLE jobs (
    id          TEXT PRIMARY KEY,
    account     TEXT NOT NULL REFERENCES accounts(id),
    asset       TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    intent      TEXT NOT NULL,
    status      TEXT NOT NULL,      -- queued|running|succeeded|failed
    progress    DOUBLE PRECISION,
    retries     INTEGER NOT NULL DEFAULT 0,
    reason      TEXT,
    created     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX jobs_account_idx ON jobs (account, id);

-- Grants: first-class access records (spec Q3). No grants in Phase 1 delivery,
-- but the table exists so the isolation conformance test proves createGrant /
-- getGrant / revokeGrant are account-scoped. One grant per SET, frozen at issue.
CREATE TABLE grants (
    id          TEXT PRIMARY KEY,
    account     TEXT NOT NULL REFERENCES accounts(id),
    assets      TEXT[] NOT NULL,        -- the frozen SET of asset ids
    recipient   TEXT,
    created     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires     TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX grants_account_idx ON grants (account, id);

-- +goose Down
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS renditions;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS accounts;
