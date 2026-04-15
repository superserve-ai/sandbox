-- Template builds: durable record of an in-flight or completed build.
-- The control plane's build supervisor polls rows in pending/building/
-- snapshotting and drives them to ready/failed/cancelled. Survives control
-- plane restarts; on restart the supervisor re-discovers in-flight builds
-- and resumes polling vmd. Builds do NOT resume after vmd crash — they get
-- marked failed and the user retries.

CREATE TYPE template_build_status AS ENUM (
    'pending', 'building', 'snapshotting', 'ready', 'failed', 'cancelled'
);

CREATE TABLE template_build (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id        uuid NOT NULL REFERENCES template(id) ON DELETE CASCADE,
    team_id            uuid NOT NULL REFERENCES team(id),
    status             template_build_status NOT NULL DEFAULT 'pending',
    build_spec_hash    text NOT NULL,
    vmd_host_id        text,
    vmd_build_vm_id    text,
    error_message      text,
    started_at         timestamptz,
    finalized_at       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_template_build_template ON template_build(template_id, created_at DESC);
CREATE INDEX idx_template_build_team_status ON template_build(team_id, status);
CREATE INDEX idx_template_build_active ON template_build(status, updated_at)
    WHERE status IN ('pending', 'building', 'snapshotting');

-- Idempotent submits: at most one in-flight build per (template, spec_hash).
-- A second POST /templates/:id/build with the same spec returns the existing
-- row instead of inserting a duplicate.
CREATE UNIQUE INDEX uniq_template_build_inflight
    ON template_build(template_id, build_spec_hash)
    WHERE status IN ('pending', 'building', 'snapshotting');

ALTER TABLE template_build ENABLE ROW LEVEL SECURITY;
