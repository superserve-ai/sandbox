-- Billing Stripe correctness hardening.
--
-- Active billing export attempts must be unique per Stripe meter identifier so
-- concurrent export requests cannot submit duplicate meter events.
CREATE UNIQUE INDEX billing_usage_export_active_identifier_unique
    ON billing_usage_export (stripe_meter_event_identifier)
    WHERE status IN ('pending', 'sent', 'accepted');

-- Keep invoice state separate from subscription state. Subscription events
-- remain authoritative for stripe_subscription_status.
ALTER TABLE team_billing_account
    ADD COLUMN stripe_invoice_status text;

ALTER TABLE team_billing_account
    ADD CONSTRAINT team_billing_account_invoice_status_nonempty
        CHECK (stripe_invoice_status IS NULL OR btrim(stripe_invoice_status) <> '');
