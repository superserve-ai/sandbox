-- Drop three sandbox indexes that newer ones already cover. Every relation a
-- statement locks past its 16 fast-path slots goes through the shared lock
-- table, and sandbox alone (table + 15 indexes) fills all 16, so each insert
-- and status update pays shared-lock traffic for every relation after it.
-- Under a create burst that traffic is the dominant wait. Fewer indexes,
-- fewer shared-table entries per write.
--
--   idx_sandbox_host         same key and predicate as idx_sandbox_host_reconcile,
--                            which also carries id, status, snapshot_id.
--   idx_sandbox_host_active  ListActiveHostsByLoad and ListHostsAdmin; served by
--                            idx_sandbox_host_reconcile's included status column.
--   idx_sandbox_status       the periodic reaper and billing scans; two have their
--                            own partial indexes, the rest read most live rows.
--
-- A plain DROP INDEX takes an exclusive lock on sandbox: it waits for every
-- in-flight statement on the table and queues new ones behind it. On a busy
-- database drop them CONCURRENTLY by hand before merging; the statements
-- below then find nothing and only record the schema. The lock timeout makes
-- a skipped pre-drop fail the push with a bounded stall instead of blocking
-- sandbox writes behind a long-running list query:
--
--   DROP INDEX CONCURRENTLY IF EXISTS idx_sandbox_host;
--   DROP INDEX CONCURRENTLY IF EXISTS idx_sandbox_host_active;
--   DROP INDEX CONCURRENTLY IF EXISTS idx_sandbox_status;

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10s';

DROP INDEX IF EXISTS idx_sandbox_host;
DROP INDEX IF EXISTS idx_sandbox_host_active;
DROP INDEX IF EXISTS idx_sandbox_status;

COMMIT;
