-- Persist the base OCI image's resolved content digest on the template so the
-- bring-your-image one-shot path (POST /v1/sandboxes/from-image) can cache by
-- (team_id, digest): the first create on a digest pays the build, every
-- subsequent create on the same digest restores the existing snapshot.
--
-- The digest is already computed by the builder during pull
-- (builder.BuildRootfsResult.ResolvedDigest, e.g. "sha256:abc...") and surfaced
-- to the build supervisor at finalize time; this column is where FinalizeBuild
-- records it durably.
--
-- Nullable: legacy templates (built before this column existed) stay NULL and
-- are simply invisible to the digest cache — they keep working via the
-- name-based from_template path exactly as before.
ALTER TABLE template ADD COLUMN resolved_digest text;

-- Partial index supporting the cache lookup: a ready, non-deleted template for a
-- given (team_id, resolved_digest). Partial so NULL-digest legacy rows don't
-- bloat it and only the rows the cache can actually return are indexed.
CREATE INDEX template_team_resolved_digest_idx
  ON template (team_id, resolved_digest)
  WHERE resolved_digest IS NOT NULL AND deleted_at IS NULL;
