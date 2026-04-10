-- Add an optional hard lifetime cap to sandboxes. When set, the reaper
-- destroys the sandbox this many seconds after created_at regardless of
-- state (active / paused / idle). NULL means no timeout — the sandbox lives
-- until explicitly paused or deleted.
--
-- The cap is measured from created_at, not last_activity_at, so paused
-- sandboxes are not exempt from expiration. This matches the user intent:
-- "delete this sandbox in N seconds regardless of what I do with it."
ALTER TABLE sandbox ADD COLUMN timeout_seconds int;

COMMENT ON COLUMN sandbox.timeout_seconds IS
    'Hard lifetime cap in seconds from created_at. NULL = no cap. The reaper '
    'destroys the sandbox when now() > created_at + (timeout_seconds || '' seconds'')::interval, '
    'regardless of state (active, paused, idle).';

-- Index to make the reaper query efficient. Partial index keeps it small
-- because most sandboxes will not set a timeout.
CREATE INDEX idx_sandbox_timeout_reap
    ON sandbox (created_at)
    WHERE timeout_seconds IS NOT NULL AND destroyed_at IS NULL;
