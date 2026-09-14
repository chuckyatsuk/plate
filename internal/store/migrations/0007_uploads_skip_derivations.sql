-- skip_derivations: the caller's opt-out of the automatic derivation at ingest.
--
-- It is declared at CREATE UPLOAD but acted on at FINALIZE — two different
-- requests — so it has to be remembered on the upload row in between. The
-- finalize request body carries a checksum and nothing else, and widening it
-- would put the same decision in two places where they could disagree; the
-- declaration belongs with the upload it describes.
--
-- NOT NULL DEFAULT false so every existing row reads as "derive normally",
-- which is exactly what those uploads did. Additive and backward-compatible:
-- an older caller that never sends the flag is indistinguishable from today.
--
-- No change to `renditions`: its `status` column is plain TEXT with no CHECK
-- constraint, so the new `not_derived` member needs no migration there.

-- +goose Up
ALTER TABLE uploads ADD COLUMN skip_derivations BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE uploads DROP COLUMN skip_derivations;
