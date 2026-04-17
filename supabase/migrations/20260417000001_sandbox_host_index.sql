CREATE INDEX idx_sandbox_host ON sandbox(host_id) WHERE destroyed_at IS NULL;
