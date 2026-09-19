-- When a resume finds the pause artifacts gone from the host, the control
-- plane looks up the backup generation recorded as covering exactly that
-- pause (snapshot row and generation counter) and asks the host to restore
-- it. This index serves that lookup; nothing on the ordinary resume path
-- touches it.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by hand:
-- the migration runner wraps every file in a transaction, where CONCURRENTLY
-- cannot run, and a plain build blocks backup report writes for the duration
-- of the table scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_backup_generation_covered_pause
--     ON backup_generation (covered_snapshot_id, covered_snapshot_generation, completed_at DESC)
--     INCLUDE (generation);
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_backup_generation_covered_pause'::regclass;
--
-- Pre-built, the statement below is a no-op that records the schema; on a
-- fresh or small database it builds instantly. The timeouts make a skipped
-- pre-build fail the push loudly with a bounded stall instead of blocking
-- backup writes for an unbounded build.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_backup_generation_covered_pause')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'idx_backup_generation_covered_pause exists but is INVALID (interrupted concurrent build); DROP INDEX idx_backup_generation_covered_pause, re-run the concurrent pre-build, then retry this push';
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_backup_generation_covered_pause
  ON backup_generation (covered_snapshot_id, covered_snapshot_generation, completed_at DESC)
  INCLUDE (generation);

COMMIT;
