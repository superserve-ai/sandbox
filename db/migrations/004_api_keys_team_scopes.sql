-- 004_api_keys_team_scopes.sql
-- Add team_id, scopes, and last_used_at to api_keys for auth middleware.

ALTER TABLE api_keys
    ADD COLUMN team_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN scopes  text[] NOT NULL DEFAULT '{}',
    ADD COLUMN last_used_at timestamptz;

CREATE INDEX idx_api_keys_team_id ON api_keys(team_id);
