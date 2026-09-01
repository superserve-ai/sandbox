-- Serves GetSnapshotForResume's covered-generation lookup: find the
-- generation (if any) verified to cover ONE specific snapshot row,
-- ordered by reported_at so the most recent verification wins ties. The
-- existing backup_generation_sandbox_completed index is keyed on
-- (sandbox_id, completed_at) and would force a scan of every generation
-- a long-paused sandbox has ever had reported, growing with pause count
-- on a path resume now runs synchronously; this index instead goes
-- straight to the rows that can match the covered_snapshot_id/generation
-- pair, which is what the query actually filters and sorts on.
CREATE INDEX IF NOT EXISTS backup_generation_covered_snapshot_idx
    ON backup_generation (covered_snapshot_id, covered_snapshot_generation, reported_at DESC)
    WHERE covered_snapshot_id IS NOT NULL;
