-- The webhook receipt remains the grace clock; alert coordination is separate
-- from processing state and can be reclaimed after a worker exits.
CREATE TABLE stripe_checkout_association_alert (
    event_id text PRIMARY KEY REFERENCES stripe_webhook_event(event_id) ON DELETE CASCADE,
    lease_until timestamptz,
    next_check_at timestamptz NOT NULL,
    last_alert_at timestamptz
);

CREATE INDEX stripe_checkout_association_alert_next_check_idx
    ON stripe_checkout_association_alert(next_check_at);

CREATE INDEX stripe_webhook_association_pending_idx
    ON stripe_webhook_event(received_at, event_id)
    WHERE processed_at IS NULL
      AND last_error = 'Stripe checkout association is still being established'
      AND event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                         'customer.subscription.deleted', 'customer.subscription.paused',
                         'customer.subscription.resumed');

ALTER TABLE public.stripe_checkout_association_alert ENABLE ROW LEVEL SECURITY;
