-- Plate — exports (Tier 1: the export capability).
--
-- An export is the OWNER's long-lived counterpart to a grant: a first-class,
-- revocable record over a frozen SET of assets that yields signed download URLs
-- for their ORIGINAL bytes (an archive, a media manifest, a handover). The row
-- is the capability: the download edge re-checks it on EVERY fetch (no cache —
-- exports are low-volume, unlike granted tiles), so revocation is immediate at
-- the byte edge. Deliberately mirrors the grants shape so the isolation and
-- revocation disciplines carry over unchanged.

-- +goose Up
CREATE TABLE exports (
    id          TEXT PRIMARY KEY,
    account     TEXT NOT NULL REFERENCES accounts(id),
    assets      TEXT[] NOT NULL,        -- the frozen SET of asset ids
    note        TEXT,                   -- opaque caller label; Plate does not interpret it
    created     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires     TIMESTAMPTZ NOT NULL,   -- long-TTL but hard-capped at issue (never unbounded)
    revoked_at  TIMESTAMPTZ
);

-- The isolation queries are `WHERE account = $1 AND id = $2`, same as grants.
CREATE INDEX exports_account_idx ON exports (account, id);

-- +goose Down
DROP TABLE IF EXISTS exports;
