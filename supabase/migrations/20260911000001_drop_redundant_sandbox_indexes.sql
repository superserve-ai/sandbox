-- Three sandbox indexes newer ones already cover: idx_sandbox_host is
-- idx_sandbox_host_reconcile without the included columns, idx_sandbox_host_active
-- is served by that index's included status column, and idx_sandbox_status only
-- backs periodic scans that have their own partial index or read most live rows.
-- Every index is one more relation each write must lock.
--
-- A plain DROP INDEX takes an exclusive lock on sandbox. On a populated
-- database drop them CONCURRENTLY by hand first; the statements below then
-- only record the schema, and the timeouts bound the stall if that was skipped:
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
