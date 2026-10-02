-- The VMD reconciler lists every non-destroyed sandbox on its host every 30s
-- to detect drift, but reads only id/status/snapshot_id per row. This covering
-- partial index lets that scan run index-only — no heap fetch, no snapshot
-- join — so the pass stays cheap even on hosts with very large live-sandbox
-- counts (where the previous full-row + LEFT JOIN scan dominated DB load).
--
-- On a high-churn sandbox table the scan is not literally zero-heap: an
-- index-only scan still visits the heap for pages the visibility map does not
-- yet mark all-visible, i.e. recently modified rows, until autovacuum catches
-- up. It remains a large win — the steady-state bulk of rows is all-visible and
-- served from the index alone — just not a guarantee of no heap access.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by hand:
-- the migration runner wraps every file in a transaction, where CONCURRENTLY
-- cannot run, and a plain build blocks all sandbox writes for the duration of
-- the table scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_host_reconcile
--     ON sandbox(host_id) INCLUDE (id, status, snapshot_id)
--     WHERE destroyed_at IS NULL;
--
--   -- A failed concurrent build leaves an INVALID index that IF NOT EXISTS
--   -- would silently keep. Verify, and on false DROP INDEX + retry:
--   SELECT indisvalid FROM pg_index
--   WHERE indexrelid = 'idx_sandbox_host_reconcile'::regclass;
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
-- migration as applied while the reconciler scan still hits the heap. Fail the
-- push instead; the fix is DROP INDEX + re-run the pre-build above.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index
    WHERE indexrelid = to_regclass('public.idx_sandbox_host_reconcile')
      AND NOT indisvalid
  ) THEN
    RAISE EXCEPTION 'idx_sandbox_host_reconcile exists but is INVALID (interrupted concurrent build); DROP INDEX idx_sandbox_host_reconcile, re-run the concurrent pre-build, then retry this push';
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_sandbox_host_reconcile
  ON sandbox(host_id) INCLUDE (id, status, snapshot_id)
  WHERE destroyed_at IS NULL;

COMMIT;
