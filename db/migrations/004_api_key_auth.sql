-- 004_api_key_auth.sql
-- Add team_id, scopes, and last_used_at to api_keys for auth middleware.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS team_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL DEFAULT '{}';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at timestamptz;
