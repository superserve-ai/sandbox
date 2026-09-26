-- The hourly purge claim looks for unpurged generations of deleted sandboxes,
-- oldest deletion first. Neither side had an index for that: the generation
-- indexes lead with the sandbox, and the sandbox status index excludes
-- destroyed rows.
--
-- On a populated database both indexes must be pre-built CONCURRENTLY, by
-- hand: the migration runner wraps every file in a transaction, where
-- CONCURRENTLY cannot run, and a plain build blocks writes to the table for
-- the duration of the scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_deleted_destroyed
--     ON sandbox (destroyed_at) WHERE status = 'deleted';
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_backup_generation_unpurged
--     ON backup_generation (bucket, sandbox_id) WHERE purged_at IS NULL;
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify each, and on false DROP INDEX + retry:
--   SELECT indexrelid::regclass, indisvalid FROM pg_index
--   WHERE indexrelid IN ('idx_sandbox_deleted_destroyed'::regclass,
--                        'idx_backup_generation_unpurged'::regclass);
--
-- Pre-built, the statements below are no-ops that record the schema; on a
-- fresh or small database they build instantly. The timeouts make a skipped
-- pre-build fail the push loudly with a bounded stall instead of blocking
-- writes for an unbounded build.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid IN (to_regclass('public.idx_sandbox_deleted_destroyed'),
                         to_regclass('public.idx_backup_generation_unpurged'))
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'a purge index exists but is INVALID (interrupted concurrent build); DROP it, re-run the concurrent pre-build, then retry this push';
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_sandbox_deleted_destroyed
  ON sandbox (destroyed_at) WHERE status = 'deleted';

CREATE INDEX IF NOT EXISTS idx_backup_generation_unpurged
  ON backup_generation (bucket, sandbox_id) WHERE purged_at IS NULL;

COMMIT;
