-- +goose Up
CREATE TABLE activity (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id   uuid NOT NULL REFERENCES sandbox(id),
    team_id      uuid NOT NULL REFERENCES team(id),
    actor_id     uuid REFERENCES profile(id),
    category     text NOT NULL,
    action       text NOT NULL,
    status       text,
    sandbox_name text,
    duration_ms  int,
    error        text,
    metadata     jsonb DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_activity_team_time ON activity(team_id, created_at DESC);
CREATE INDEX idx_activity_sandbox_time ON activity(sandbox_id, created_at DESC);
CREATE INDEX idx_activity_category ON activity(team_id, category, created_at DESC);
CREATE INDEX idx_activity_actor ON activity(actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_activity_errors ON activity(team_id, created_at DESC) WHERE status = 'error';

-- +goose Down
DROP TABLE IF EXISTS activity;
