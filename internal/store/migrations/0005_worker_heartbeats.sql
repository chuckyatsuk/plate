-- Plate — worker heartbeats (Tier 1: monitoring).
--
-- The worker has no HTTP surface, so its liveness was invisible: a dead worker
-- (zero machines, a crash loop, a stuck loop) stops the A/V queue AND the
-- reconciliation sweeps with no signal anywhere. This table is that signal.
-- Each worker process upserts its own row every PLATE_WORKER_HEARTBEAT_EVERY
-- (default 30s) and stamps last_sweep after each reconcile pass; the API's
-- /readyz reads the newest row and reports `degraded` when it is stale. One
-- row per worker id (the Fly machine id, else hostname), so N workers = N rows
-- and readiness is "at least one worker is alive".

-- +goose Up
CREATE TABLE worker_heartbeats (
    worker_id  TEXT PRIMARY KEY,
    last_seen  TIMESTAMPTZ NOT NULL,
    last_sweep TIMESTAMPTZ,            -- newest completed reconcile pass (NULL until the first)
    version    TEXT NOT NULL DEFAULT '', -- image ref / build id, for "which build is beating"
    started    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE worker_heartbeats;
