CREATE INDEX IF NOT EXISTS sandbox_storage_interval_sandbox_team_started_at_idx
    ON sandbox_storage_interval (sandbox_id, team_id, started_at);
