-- +goose Up
CREATE TABLE team (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE team_member (
    team_id    uuid NOT NULL REFERENCES team(id),
    profile_id uuid NOT NULL REFERENCES profile(id),
    role       text NOT NULL DEFAULT 'member',
    joined_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, profile_id)
);

CREATE INDEX idx_team_member_profile ON team_member(profile_id);

-- +goose Down
DROP TABLE IF EXISTS team_member;
DROP TABLE IF EXISTS team;
