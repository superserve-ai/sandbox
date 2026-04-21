-- Drop last_activity_at column and its index. The column was used by the
-- (now removed) auto-wake middleware and idle-sandbox listing — with those
-- gone, nothing reads the column.

DROP INDEX IF EXISTS idx_sandbox_last_activity;
ALTER TABLE sandbox DROP COLUMN IF EXISTS last_activity_at;
