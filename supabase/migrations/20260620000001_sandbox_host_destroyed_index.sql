-- Supports the VMD disk reconciler's recently-destroyed lookup
-- (ListRecentlyDestroyedSandboxIDsByHost):
--   host_id = $1 AND destroyed_at IS NOT NULL AND destroyed_at > $2.
-- The existing idx_sandbox_host is partial on destroyed_at IS NULL and does
-- not cover destroyed rows, so without this the lookup scans the deleted
-- portion of sandbox every pass on hosts with accumulated history.
CREATE INDEX IF NOT EXISTS idx_sandbox_host_destroyed
ON sandbox (host_id, destroyed_at)
WHERE destroyed_at IS NOT NULL;
