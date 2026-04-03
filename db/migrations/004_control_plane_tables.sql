-- 004_control_plane_tables.sql
-- Control plane v1 schema: team, api_key, sandbox, snapshot, activity.

CREATE TYPE sandbox_status AS ENUM ('starting', 'active', 'pausing', 'idle', 'deleted');

-- =============================================================================
-- Teams
-- =============================================================================

CREATE TABLE team (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- =============================================================================
-- API Keys
-- =============================================================================

CREATE TABLE api_key (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     uuid NOT NULL REFERENCES team(id),
    key_hash    text NOT NULL UNIQUE,
    name        text NOT NULL,
    scopes      text[] NOT NULL DEFAULT '{}',
    created_by  text,
    expires_at  timestamptz,
    revoked_at  timestamptz,
    last_used_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_key_team_id ON api_key(team_id);
CREATE INDEX idx_api_key_key_hash_active ON api_key(key_hash) WHERE revoked_at IS NULL;

-- =============================================================================
-- Sandboxes
-- =============================================================================

CREATE TABLE sandbox (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          uuid NOT NULL REFERENCES team(id),
    name             text NOT NULL,
    status           sandbox_status NOT NULL DEFAULT 'starting',
    vcpu_count       int NOT NULL,
    memory_mib       int NOT NULL,
    host_id          text,
    ip_address       inet,
    pid              int,
    snapshot_id      uuid,  -- FK added after snapshot table
    last_activity_at timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    destroyed_at     timestamptz,

    CONSTRAINT sandbox_vcpu_positive CHECK (vcpu_count > 0),
    CONSTRAINT sandbox_memory_positive CHECK (memory_mib > 0)
);

CREATE INDEX idx_sandbox_team_id ON sandbox(team_id);
CREATE INDEX idx_sandbox_status ON sandbox(status) WHERE destroyed_at IS NULL;
CREATE INDEX idx_sandbox_team_status ON sandbox(team_id, status) WHERE destroyed_at IS NULL;

-- =============================================================================
-- Snapshots
-- =============================================================================

CREATE TABLE snapshot (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id  uuid NOT NULL REFERENCES sandbox(id),
    team_id     uuid NOT NULL REFERENCES team(id),
    path        text NOT NULL,
    size_bytes  bigint NOT NULL DEFAULT 0,
    saved       boolean NOT NULL DEFAULT false,
    name        text,
    trigger     text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT snapshot_size_non_negative CHECK (size_bytes >= 0)
);

-- Now add the deferred FK from sandbox to snapshot
ALTER TABLE sandbox
    ADD CONSTRAINT fk_sandbox_snapshot
    FOREIGN KEY (snapshot_id) REFERENCES snapshot(id);

CREATE INDEX idx_snapshot_sandbox_id ON snapshot(sandbox_id, created_at DESC);
CREATE INDEX idx_snapshot_team_id ON snapshot(team_id);

-- =============================================================================
-- Activity log
-- =============================================================================

CREATE TABLE activity (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id   uuid NOT NULL REFERENCES sandbox(id),
    team_id      uuid NOT NULL REFERENCES team(id),
    actor_id     text,
    category     text NOT NULL,
    action       text NOT NULL,
    status       text NOT NULL,
    sandbox_name text,
    duration_ms  int,
    error        text,
    metadata     jsonb DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_activity_sandbox_id ON activity(sandbox_id, created_at DESC);
CREATE INDEX idx_activity_team_id ON activity(team_id, created_at DESC);
CREATE INDEX idx_activity_category ON activity(category);
