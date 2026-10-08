-- Persist fairness across scheduler replicas and restarts without changing
-- which period is eligible first within a team.
CREATE TABLE billing_finalization_attempt (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    last_attempt_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.billing_finalization_attempt ENABLE ROW LEVEL SECURITY;
