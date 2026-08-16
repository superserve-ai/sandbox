-- The VMD reconciler lists every non-destroyed sandbox on its host every 30s
-- to detect drift, but only reads id/status/snapshot_id per row. This covering
-- partial index lets that scan run index-only — no heap fetch, no snapshot
-- join — so the pass stays cheap even on hosts with very large live-sandbox
-- counts (where the previous full-row + LEFT JOIN scan dominated DB load).
CREATE INDEX IF NOT EXISTS idx_sandbox_host_reconcile
ON sandbox (host_id) INCLUDE (id, status, snapshot_id)
WHERE destroyed_at IS NULL;
