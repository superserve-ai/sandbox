ALTER TABLE billing_usage_export
    ADD COLUMN stripe_idempotency_key text;

UPDATE billing_usage_export
SET stripe_idempotency_key = 'meter-event:' || encode(
    digest(
        concat_ws(
            E'\\x00',
            stripe_meter_event_identifier,
            stripe_event_name,
            COALESCE(stripe_customer_id, ''),
            to_char(value, 'FM999999999999999990.000000000000'),
            (extract(epoch FROM period_end AT TIME ZONE 'UTC')::bigint - 1)::text
        ),
        'sha256'
    ),
    'hex'
)
WHERE stripe_idempotency_key IS NULL
  AND status IN ('pending', 'failed', 'sent', 'accepted');

CREATE INDEX idx_billing_usage_export_idempotency_key
    ON billing_usage_export(stripe_idempotency_key)
    WHERE stripe_idempotency_key IS NOT NULL;
