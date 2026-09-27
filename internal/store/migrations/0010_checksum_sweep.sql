-- Plate — server-side SHA-256 of every vault object (Exit support, P3).
--
-- Until now the vault checksum was verified only when a client declared md5:…
-- and it matched a single-part ETag; everything else stayed empty, and nothing
-- ever hashed the stored bytes. The worker now streams every vault object once,
-- computes SHA-256, and records it as the verified checksum (vault_checksum =
-- 'sha256:<hex>', checksum_verified = true). A/V originals are hashed while the
-- derive job downloads them anyway; everything else (and the backlog of existing
-- assets) is hashed by the worker's checksum sweep, one object at a time,
-- rate-limited, streaming (never buffered).
--
-- checksum_checked_at is the sweep's claim + retry stamp: set when the sweep
-- takes an asset, so concurrent workers skip it and an object that could not be
-- read (missing, truncated) is retried only after a back-off instead of on every
-- pass. The column itself is the backfill's progress record, which is what makes
-- the backfill resumable: a pass can stop at any point and the next one picks up
-- whatever still lacks a verified sha256.
--
-- Additive and nullable: existing rows read "never checked", and code that
-- predates this migration never reads it (safe to roll the image back).

-- +goose Up
ALTER TABLE assets ADD COLUMN checksum_checked_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE assets DROP COLUMN IF EXISTS checksum_checked_at;
