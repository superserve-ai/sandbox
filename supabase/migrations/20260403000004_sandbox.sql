CREATE TYPE sandbox_status AS ENUM (
    'starting', 'active', 'pausing', 'idle', 'deleted'
);

CREATE TABLE sandbox (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          uuid NOT NULL REFERENCES team(id),
    name             text NOT NULL,
    status           sandbox_status NOT NULL DEFAULT 'starting',
    vcpu_count       int NOT NULL DEFAULT 1,
    memory_mib       int NOT NULL DEFAULT 1024,
    host_id          text,
    ip_address       inet,
    pid              int,
    snapshot_id      uuid,  -- FK added in 005_snapshot.sql
    last_activity_at timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    destroyed_at     timestamptz,

    CONSTRAINT sandbox_vcpu_positive CHECK (vcpu_count > 0),
    CONSTRAINT sandbox_memory_positive CHECK (memory_mib > 0)
);

CREATE INDEX idx_sandbox_team ON sandbox(team_id);
CREATE INDEX idx_sandbox_status ON sandbox(status) WHERE destroyed_at IS NULL;
CREATE INDEX idx_sandbox_team_status ON sandbox(team_id, status) WHERE destroyed_at IS NULL;
CREATE INDEX idx_sandbox_last_activity ON sandbox(last_activity_at) WHERE status = 'active';

