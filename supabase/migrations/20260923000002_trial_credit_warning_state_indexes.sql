BEGIN;

-- Keep this migration self-contained for installations that did not receive
-- the initial warning migration. The notification queries require the table
-- before their claim/complete operations can run.
CREATE TABLE IF NOT EXISTS trial_credit_warning_state (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending',
    claim_token uuid,
    claimed_at timestamptz,
    sent_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT trial_credit_warning_state_status_check
        CHECK (status IN ('pending', 'claimed', 'sent', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_trial_credit_warning_state_claim
    ON trial_credit_warning_state(status, claimed_at, team_id)
    WHERE status IN ('pending', 'claimed');

-- Claims always carry a generation token; without it a stale worker could
-- accidentally operate on a replacement claim.
ALTER TABLE trial_credit_warning_state
    ADD CONSTRAINT trial_credit_warning_state_claim_token_check
    CHECK (status <> 'claimed' OR claim_token IS NOT NULL) NOT VALID;
ALTER TABLE trial_credit_warning_state
    VALIDATE CONSTRAINT trial_credit_warning_state_claim_token_check;

-- Claim completion and retry updates identify an in-flight warning by token.
-- Keep that lookup bounded without changing the notification state machine.
CREATE INDEX IF NOT EXISTS idx_trial_credit_warning_state_claim_token
    ON trial_credit_warning_state(claim_token)
    WHERE status = 'claimed';

COMMIT;
