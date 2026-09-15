-- ListActiveHostsByLoad now counts 'migrating' rows (an operator's boots on
-- a host are load the scheduler must see), so the partial index that kept
-- that JOIN index-only no longer matches its predicate. This one does; the
-- old index stays until the query's callers have all moved.
--
-- On a populated database this index must be pre-built CONCURRENTLY, by
-- hand: the migration runner wraps every file in a transaction, where
-- CONCURRENTLY cannot run, and a plain build blocks sandbox writes for the
-- duration of the table scan. Run before merging:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_host_live
--     ON sandbox(host_id)
--     WHERE status IN ('active', 'starting', 'migrating') AND destroyed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sandbox_host_live
    ON sandbox(host_id)
    WHERE status IN ('active', 'starting', 'migrating') AND destroyed_at IS NULL;
