BEGIN;

-- One-shot state for the pre-Stripe signup-trial low-credit notification.
CREATE TABLE trial_credit_warning_state (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending',
    claim_token uuid,
    claimed_at timestamptz,
    sent_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trial_credit_warning_state_status_check CHECK (status IN ('pending','claimed','sent','unknown'))
);

-- Keep retry/claim maintenance scans bounded if they are introduced later;
-- the partial index covers only rows that can participate in a claim.
CREATE INDEX idx_trial_credit_warning_state_claim
    ON trial_credit_warning_state(status, claimed_at, team_id)
    WHERE status IN ('pending', 'claimed');

ALTER TABLE trial_credit_warning_state ENABLE ROW LEVEL SECURITY;

COMMIT;
