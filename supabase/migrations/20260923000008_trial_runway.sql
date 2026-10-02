-- Live advisory state is independent of warning delivery and its deduplication.
CREATE TABLE team_trial_runway (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    lifecycle_key text NOT NULL,
    state text NOT NULL CHECK (state IN ('over_24h', 'under_24h', 'unknown')),
    observed_at timestamptz NOT NULL
);
ALTER TABLE team_trial_runway ENABLE ROW LEVEL SECURITY;
