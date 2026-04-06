CREATE TABLE api_key (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      uuid NOT NULL REFERENCES team(id),
    key_hash     text NOT NULL UNIQUE,
    name         text NOT NULL,
    scopes       text[] NOT NULL DEFAULT '{}',
    created_by   uuid REFERENCES profile(id),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_key_team ON api_key(team_id);
CREATE INDEX idx_api_key_hash_active ON api_key(key_hash) WHERE revoked_at IS NULL;

