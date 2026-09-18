-- The resume claim looks up the backup generation covering the exact pause
-- being resumed; this is that lookup's index.
CREATE INDEX IF NOT EXISTS idx_backup_generation_covered_pause
    ON backup_generation (covered_snapshot_id, covered_snapshot_generation, completed_at DESC)
    INCLUDE (generation);
