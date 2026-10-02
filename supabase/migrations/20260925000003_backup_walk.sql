-- One row per backup bucket records when its daily walk last started, so a
-- single control-plane replica takes the walk per interval instead of every
-- replica listing the bucket.
CREATE TABLE IF NOT EXISTS backup_walk (
    bucket     text PRIMARY KEY,
    started_at timestamptz NOT NULL
);
ALTER TABLE backup_walk ENABLE ROW LEVEL SECURITY;
