-- Matches the ListActiveHostsByLoad JOIN predicate so the per-host
-- count is index-only.
CREATE INDEX IF NOT EXISTS idx_sandbox_host_active
    ON sandbox(host_id)
    WHERE status IN ('active', 'starting') AND destroyed_at IS NULL;
