-- On a populated database, pre-build this index CONCURRENTLY by hand before
-- applying the migration. The migration runner wraps files in a transaction,
-- where CONCURRENTLY cannot run, and a plain build blocks sandbox writes:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_compute_pause_candidates
--     ON sandbox (team_id, id)
--     WHERE destroyed_at IS NULL AND status IN ('active', 'starting', 'resuming');
--
--   -- A failed concurrent build can leave an INVALID index. Verify:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_sandbox_compute_pause_candidates'::regclass;
--
--   -- Only if indisvalid is false, drop it and retry the concurrent build:
--   DROP INDEX CONCURRENTLY IF EXISTS idx_sandbox_compute_pause_candidates;
--
-- With a valid pre-build of the documented definition, creation below is a no-op. On a fresh database
-- it builds the index; the timeouts bound a skipped pre-build on a large one.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

CREATE INDEX IF NOT EXISTS idx_sandbox_compute_pause_candidates
ON public.sandbox (team_id, id)
WHERE destroyed_at IS NULL AND status IN ('active', 'starting', 'resuming');

DO $$
BEGIN
-- Let PostgreSQL normalize the expected predicate using the real column types.
-- This empty temporary table never scans or indexes the populated sandbox table.
CREATE TEMP TABLE compute_pause_index_shape ON COMMIT DROP AS
SELECT team_id, id, destroyed_at, status FROM public.sandbox WITH NO DATA;
CREATE INDEX compute_pause_index_expected ON compute_pause_index_shape (team_id, id)
WHERE destroyed_at IS NULL AND status IN ('active', 'starting', 'resuming');

  IF NOT EXISTS (
    SELECT 1
    FROM pg_index actual
    JOIN pg_class actual_class ON actual_class.oid = actual.indexrelid
    CROSS JOIN pg_index expected
    JOIN pg_class expected_class ON expected_class.oid = expected.indexrelid
    WHERE actual.indexrelid = 'public.idx_sandbox_compute_pause_candidates'::regclass
      AND expected.indexrelid = 'pg_temp.compute_pause_index_expected'::regclass
      AND actual.indrelid = 'public.sandbox'::regclass
      AND actual.indisvalid AND actual.indisready AND actual.indislive
      AND NOT actual.indisunique
      AND actual.indnatts = 2 AND actual.indnkeyatts = 2
      AND actual_class.relam = expected_class.relam
      AND actual.indclass = expected.indclass
      AND actual.indcollation = expected.indcollation
      AND actual.indoption = expected.indoption
      AND pg_get_indexdef(actual.indexrelid, 1, true) = 'team_id'
      AND pg_get_indexdef(actual.indexrelid, 2, true) = 'id'
      AND pg_get_expr(actual.indpred, actual.indrelid)
          = pg_get_expr(expected.indpred, expected.indrelid)
  ) THEN
    RAISE EXCEPTION 'idx_sandbox_compute_pause_candidates is invalid or has an unexpected definition; DROP INDEX CONCURRENTLY, re-run the documented concurrent pre-build, then retry this migration';
  END IF;
END $$;

COMMIT;
