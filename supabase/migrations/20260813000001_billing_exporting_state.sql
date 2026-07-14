-- Add an intermediate billing export state so we can freeze usage in a short
-- transaction, release locks, and complete Stripe submission outside the
-- transaction boundary.

ALTER TABLE team_billing_period
    DROP CONSTRAINT IF EXISTS team_billing_period_status_valid;

ALTER TABLE team_billing_period
    ADD CONSTRAINT team_billing_period_status_valid CHECK (
        status IN ('open', 'validating', 'blocked', 'approved', 'exporting', 'exported', 'finalized')
    );
