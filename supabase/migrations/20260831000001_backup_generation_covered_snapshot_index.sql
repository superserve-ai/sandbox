-- Serves GetSnapshotForResume's covered-generation lookup: find the
-- generation (if any) verified to cover ONE specific snapshot row,
-- ordered by reported_at so the most recent verification wins ties. The
-- existing backup_generation_sandbox_completed index is keyed on
-- (sandbox_id, completed_at) and would force a scan of every generation
-- a long-paused sandbox has ever had reported, growing with pause count
-- on a path resume now runs synchronously; this index instead goes
-- straight to the rows that can match the covered_snapshot_id/generation
-- pair, which is what the query actually filters and sorts on.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by
-- hand: the migration runner wraps every file in a transaction, where
-- CONCURRENTLY cannot run, and a plain build blocks all backup_generation
-- writes (every host's backup reports) for the duration of the table
-- scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_backup_generation_covered_snapshot
--     ON backup_generation (covered_snapshot_id, covered_snapshot_generation, reported_at DESC)
--     WHERE covered_snapshot_id IS NOT NULL;
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_backup_generation_covered_snapshot'::regclass;
--
-- Pre-built, the statement below is a no-op that records the schema; on a
-- fresh or small database it builds instantly. The timeouts make a skipped
-- pre-build fail the push loudly with a bounded stall instead of blocking
-- backup report writes for an unbounded build.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

-- IF NOT EXISTS matches by name only: an interrupted concurrent pre-build
-- leaves an INVALID index that would be silently kept, recording this
-- migration as applied while the resume lookup still scans every
-- generation. Fail the push instead; the fix is DROP INDEX + re-run the
-- concurrent pre-build above. A valid index whose definition differs from
-- the expected one is warned about rather than failed, so it is loud in
-- the push log without bricking the deploy.
DO $$
DECLARE
  actual_def text;
  expected_def text := 'CREATE INDEX idx_backup_generation_covered_snapshot ON public.backup_generation USING btree (covered_snapshot_id, covered_snapshot_generation, reported_at DESC) WHERE (covered_snapshot_id IS NOT NULL)';
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_backup_generation_covered_snapshot')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'idx_backup_generation_covered_snapshot exists but is INVALID (interrupted concurrent build); DROP INDEX idx_backup_generation_covered_snapshot, re-run the concurrent pre-build, then retry this push';
  END IF;

  SELECT pg_get_indexdef(oid) INTO actual_def
  FROM pg_class
  WHERE oid = to_regclass('public.idx_backup_generation_covered_snapshot');

  IF actual_def IS NOT NULL AND actual_def <> expected_def THEN
    RAISE WARNING 'idx_backup_generation_covered_snapshot exists with an unexpected definition; got %, expected %', actual_def, expected_def;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_backup_generation_covered_snapshot
  ON backup_generation (covered_snapshot_id, covered_snapshot_generation, reported_at DESC)
  WHERE covered_snapshot_id IS NOT NULL;

COMMIT;
