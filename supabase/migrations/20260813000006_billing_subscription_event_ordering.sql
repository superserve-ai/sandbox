-- Record the newest Stripe subscription event we have applied so older
-- subscription state changes can be ignored safely.

ALTER TABLE team_billing_account
    ADD COLUMN stripe_subscription_event_at timestamptz;
