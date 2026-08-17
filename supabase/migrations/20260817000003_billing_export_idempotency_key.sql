ALTER TABLE billing_usage_export
    ADD COLUMN stripe_idempotency_key text;

CREATE INDEX idx_billing_usage_export_idempotency_key
    ON billing_usage_export(stripe_idempotency_key)
    WHERE stripe_idempotency_key IS NOT NULL;
