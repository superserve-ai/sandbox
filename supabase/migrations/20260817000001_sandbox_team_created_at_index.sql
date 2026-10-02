-- The team sandbox list defaults to created_at ordering, and its static
-- ORDER BY queries (ListSandboxesByTeamCreated{Desc,Asc}) can only skip the
-- sort if the planner has a matching index to walk. Without one, every list
-- call sorts the entire live set for the team — for large teams that spills
-- past work_mem to disk on the hot path. Partial index: only live rows
-- (destroyed_at IS NULL) are ever listed. DESC on created_at matches the
-- default sort direction; the planner walks it backward for ASC.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by hand:
-- the migration runner wraps every file in a transaction, where CONCURRENTLY
-- cannot run, and a plain build blocks all sandbox writes for the duration of
-- the table scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_team_created_active
--     ON sandbox(team_id, created_at DESC)
--     WHERE destroyed_at IS NULL;
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_sandbox_team_created_active'::regclass;
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
-- migration as applied while the list queries still sort the whole set. Fail
-- the push instead; the fix is DROP INDEX + re-run the concurrent pre-build
-- above. A valid index whose definition differs from the expected one (a
-- same-named index built by hand with the wrong columns or predicate) is
-- warned about rather than failed, so it is loud in the push log without
-- bricking the deploy.
DO $$
DECLARE
  actual_def text;
  expected_def text := 'CREATE INDEX idx_sandbox_team_created_active ON public.sandbox USING btree (team_id, created_at DESC) WHERE (destroyed_at IS NULL)';
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_sandbox_team_created_active')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'idx_sandbox_team_created_active exists but is INVALID (interrupted concurrent build); DROP INDEX idx_sandbox_team_created_active, re-run the concurrent pre-build, then retry this push';
  END IF;

  SELECT pg_get_indexdef(oid) INTO actual_def
  FROM pg_class
  WHERE oid = to_regclass('public.idx_sandbox_team_created_active');

  IF actual_def IS NOT NULL AND actual_def <> expected_def THEN
    RAISE WARNING 'idx_sandbox_team_created_active exists with an unexpected definition; got %, expected %', actual_def, expected_def;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_sandbox_team_created_active
  ON sandbox(team_id, created_at DESC)
  WHERE destroyed_at IS NULL;

COMMIT;
