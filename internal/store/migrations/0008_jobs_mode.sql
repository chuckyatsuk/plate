-- jobs.mode: how a job produces its rendition — 'derive' (transcode) or 'remux'
-- (stream-copy an authored file, faststart, no re-encode; Tier 2 V4.1).
--
-- A remux is NOT an intent. `remux` is not a member of the closed Intent enum, and
-- an authored detail's remux job carries intent 'detail' — indistinguishable from a
-- DERIVED detail's transcode by intent alone. The worker branches on this column
-- (derive → DetailArgs/LoopArgs + the 12-min derived-detail ceiling; remux →
-- RemuxCopyArgs after the authored ceilings pass), and the claim order keys on it so
-- a short remux is not stuck behind a long transcode (the poster problem).
--
-- NOT NULL DEFAULT 'derive' so every existing row — and every job an older enqueue
-- path inserts — reads as a transcode, which is exactly what they are. Additive and
-- backward-compatible: nothing that predates V4.1 knows or sets the column, and it
-- keeps behaving as before. The authored path (PR1) sets mode = 'remux' at enqueue.
--
-- Plain TEXT with a CHECK, mirroring how `renditions.status` carries a closed set
-- without a Postgres enum type — a new mode is a one-line CHECK edit, not a type
-- migration.

-- +goose Up
ALTER TABLE jobs ADD COLUMN mode TEXT NOT NULL DEFAULT 'derive'
    CHECK (mode IN ('derive', 'remux'));

-- +goose Down
ALTER TABLE jobs DROP COLUMN mode;
