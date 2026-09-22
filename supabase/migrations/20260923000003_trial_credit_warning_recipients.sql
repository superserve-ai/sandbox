BEGIN;

CREATE TABLE trial_credit_warning_delivery (
    team_id uuid NOT NULL REFERENCES trial_credit_warning_state(team_id) ON DELETE CASCADE,
    recipient text NOT NULL,
    sent_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, recipient)
);

ALTER TABLE trial_credit_warning_delivery ENABLE ROW LEVEL SECURITY;

COMMIT;
