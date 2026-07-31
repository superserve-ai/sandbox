-- CountActiveSandboxesAtBasePath runs at every destroy to decide whether the
-- per-build artifact dir is safe to GC, and ListPinnedBuildPaths walks the
-- same predicate for the reconciler; neither has an index on base_path, so
-- both sequential-scan the sandbox table. Partial index: only live rows with
-- a base_path are ever matched (equality lookups imply NOT NULL).
--
-- On a populated database this index must be pre-built CONCURRENTLY, by hand:
-- the migration runner wraps every file in a transaction, where CONCURRENTLY
-- cannot run, and a plain build blocks all sandbox writes for the duration of
-- the table scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_base_path_active
--     ON sandbox(base_path)
--     WHERE base_path IS NOT NULL AND destroyed_at IS NULL;
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_sandbox_base_path_active'::regclass;
--
-- Pre-built, the statement below is a no-op that records the schema; on a
-- fresh or small database it builds instantly. The timeouts make a skipped
-- pre-build fail the push loudly with a bounded stall instead of blocking
-- sandbox writes for an unbounded build.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

-- IF NOT EXISTS matches by name only: an interrupted concurrent pre-build
-- leaves an INVALID index that would be silently kept, recording this
-- migration as applied while both queries still sequential-scan. Fail the
-- push instead; the fix is DROP INDEX + re-run the pre-build above.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_sandbox_base_path_active')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'idx_sandbox_base_path_active exists but is INVALID (interrupted concurrent build); DROP INDEX idx_sandbox_base_path_active, re-run the concurrent pre-build, then retry this push';
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_sandbox_base_path_active
  ON sandbox(base_path)
  WHERE base_path IS NOT NULL AND destroyed_at IS NULL;

COMMIT;
