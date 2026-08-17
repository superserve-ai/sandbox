ALTER TABLE billing_usage_export
    ADD COLUMN stripe_idempotency_key text;

UPDATE billing_usage_export
SET stripe_idempotency_key = stripe_meter_event_identifier
WHERE stripe_idempotency_key IS NULL
  AND status IN ('pending', 'failed', 'sent', 'accepted');

CREATE INDEX idx_billing_usage_export_idempotency_key
    ON billing_usage_export(stripe_idempotency_key)
    WHERE stripe_idempotency_key IS NOT NULL;
