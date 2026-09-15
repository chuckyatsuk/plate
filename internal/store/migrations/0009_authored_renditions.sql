-- Authored renditions (Tier 2 V4.1): a caller uploads a FILE as the rendition for
-- a named intent on an existing asset, instead of Plate deriving it. The file is
-- stream-copy remuxed (faststart, no re-encode) and, on passing the authored
-- ceilings, stored as a ready rendition. Zero transcode.
--
-- Two bindings ride between createUpload and finalize/claim, same pattern as
-- skip_derivations (0007) rides the upload row:
--
--   uploads.rendition_asset + uploads.rendition_intent — when BOTH are set, this
--     upload is an authored rendition FOR that (asset, intent), not a new asset's
--     original. NULL for an ordinary original upload (the existing path, unchanged).
--
--   jobs.source_key — a derive job's source is the asset's own vault_key; a REMUX
--     job's source is the newly-uploaded authored file, which lives at its own
--     staging key. The worker reads source_key when set, falling back to the
--     asset's vault_key (NULL) for a derive job. So a remux job carries where to
--     read from; a transcode keeps reading the vault original as before.
--
-- All nullable / additive: an ordinary upload leaves the rendition_* columns NULL
-- and a derive job leaves source_key NULL, both behaving exactly as before.

-- +goose Up
ALTER TABLE uploads ADD COLUMN rendition_asset  TEXT;   -- target asset for an authored rendition
ALTER TABLE uploads ADD COLUMN rendition_intent TEXT;   -- target intent (detail|loop|poster)
ALTER TABLE jobs    ADD COLUMN source_key       TEXT;   -- remux source (staging key); NULL = use vault_key

-- +goose Down
ALTER TABLE jobs    DROP COLUMN source_key;
ALTER TABLE uploads DROP COLUMN rendition_intent;
ALTER TABLE uploads DROP COLUMN rendition_asset;
