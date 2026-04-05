-- +goose Up
CREATE TABLE snapshot (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id uuid NOT NULL REFERENCES sandbox(id),
    team_id    uuid NOT NULL REFERENCES team(id),
    path       text NOT NULL,
    size_bytes bigint NOT NULL DEFAULT 0,
    saved      boolean NOT NULL DEFAULT false,
    name       text,
    trigger    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT snapshot_size_non_negative CHECK (size_bytes >= 0)
);

ALTER TABLE sandbox
    ADD CONSTRAINT fk_sandbox_snapshot
    FOREIGN KEY (snapshot_id) REFERENCES snapshot(id);

CREATE INDEX idx_snapshot_sandbox ON snapshot(sandbox_id, created_at DESC);
CREATE INDEX idx_snapshot_team_saved ON snapshot(team_id, created_at DESC) WHERE saved = true;

-- +goose Down
ALTER TABLE sandbox DROP CONSTRAINT IF EXISTS fk_sandbox_snapshot;
DROP TABLE IF EXISTS snapshot;
