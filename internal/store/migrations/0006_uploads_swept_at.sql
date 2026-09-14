-- Plate — mark swept orphan uploads (monitoring follow-up).
--
-- The reconcile sweep deleted an orphan upload's R2 object but never touched its
-- row, and ReclaimableUploads selects purely on (finalized_at IS NULL, created).
-- So every swept orphan was re-selected on the NEXT pass and "cleaned" again
-- (R2 DeleteObject on a missing key succeeds silently) — forever. The sweep log
-- said cleaned=N every 15 minutes and the orphan backlog was unmeasurable.
--
-- swept_at records that the object was deleted. ReclaimableUploads now excludes
-- swept rows, so an orphan is cleaned exactly once. The row is KEPT (not deleted):
-- it is the record that an upload was started and abandoned, and it is what stops
-- FinalizeUpload from resurrecting an asset whose vault bytes are already gone.

-- +goose Up
ALTER TABLE uploads ADD COLUMN swept_at TIMESTAMPTZ;
-- The sweep now filters on (finalized_at, swept_at, created); widen the index to
-- match so it stays index-only.
DROP INDEX uploads_unfinalized_idx;
CREATE INDEX uploads_unfinalized_idx ON uploads (finalized_at, swept_at, created);

-- +goose Down
DROP INDEX uploads_unfinalized_idx;
CREATE INDEX uploads_unfinalized_idx ON uploads (finalized_at, created);
ALTER TABLE uploads DROP COLUMN swept_at;
