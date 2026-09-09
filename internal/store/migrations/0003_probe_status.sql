-- Plate — deferred A/V probing (Phase 2 hardening, review ruling 1).
--
-- §5.3 refined: fail-closed means the vault never accepts an object it cannot
-- account for (existence + identity, verified synchronously at finalize) — it
-- does NOT mean every delivery property is known synchronously. Probing for
-- delivery properties (dimensions, duration, codec) happens where the media
-- runtime lives: images in the API (stdlib, header-only), A/V in the WORKER
-- (ffprobe). The API image deliberately has no ffprobe, and pulling a multi-GB
-- vault master into a sub-100ms API request is the exact "900MB through a
-- serverless request" failure §5.1's broker exists to avoid.
--
-- probe_status tracks where an asset is in that flow:
--   ready   — probed; vault metadata is populated (images at finalize; A/V once
--             the worker has probed).
--   pending — A/V asset created at finalize, probe happens in the worker.
--   failed  — the object could not be probed (corrupt/unsupported); delivery
--             refuses with a closed-enum reason.

-- +goose Up

ALTER TABLE assets ADD COLUMN probe_status TEXT NOT NULL DEFAULT 'ready';

-- Existing rows (created synchronously in the pre-deferral world) are 'ready' by
-- the default, which is correct — they were probed at finalize.

-- checksum verification state (review ruling 2): a field named checksum must
-- never hold an unverified value. verified_checksum is populated only once the
-- stored object's checksum is confirmed (server-side at PUT via
-- x-amz-checksum-sha256, by ETag compare, or by the worker hashing during pull).
-- The client's unverified claim is NOT stored here.
ALTER TABLE assets ADD COLUMN checksum_verified BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE assets DROP COLUMN IF EXISTS checksum_verified;
ALTER TABLE assets DROP COLUMN IF EXISTS probe_status;
