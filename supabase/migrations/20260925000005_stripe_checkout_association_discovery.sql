CREATE INDEX stripe_webhook_association_ready_idx
    ON stripe_webhook_event ((GREATEST((received_at AT TIME ZONE 'UTC') + interval '5 minutes', updated_at AT TIME ZONE 'UTC')), event_id)
    WHERE processed_at IS NULL
      AND last_error = 'Stripe checkout association is still being established'
      AND event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                         'customer.subscription.deleted', 'customer.subscription.paused',
                         'customer.subscription.resumed');

CREATE INDEX stripe_checkout_association_alert_due_idx
    ON stripe_checkout_association_alert(next_check_at, event_id);

DROP INDEX stripe_webhook_association_pending_idx;
DROP INDEX stripe_checkout_association_alert_next_check_idx;

-- The alert row is committed with the pending transition. A scan cursor over
-- webhook timestamps cannot establish commit order for concurrent retries.
CREATE FUNCTION queue_stripe_checkout_association_alert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.processed_at IS NULL
           AND OLD.last_error = 'Stripe checkout association is still being established'
           AND OLD.event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                                  'customer.subscription.deleted', 'customer.subscription.paused',
                                  'customer.subscription.resumed') THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.processed_at IS NULL
       AND NEW.last_error = 'Stripe checkout association is still being established'
       AND NEW.event_type IN ('customer.subscription.created', 'customer.subscription.updated',
                              'customer.subscription.deleted', 'customer.subscription.paused',
                              'customer.subscription.resumed') THEN
        INSERT INTO stripe_checkout_association_alert(event_id, next_check_at)
        VALUES (NEW.event_id, NEW.received_at + interval '5 minutes')
        ON CONFLICT (event_id) DO UPDATE
        SET next_check_at = GREATEST(
            EXCLUDED.next_check_at,
            COALESCE(stripe_checkout_association_alert.lease_until, '-infinity'::timestamptz),
            COALESCE(stripe_checkout_association_alert.last_alert_at + interval '30 minutes', '-infinity'::timestamptz));
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER stripe_checkout_association_alert_eligible
AFTER INSERT OR UPDATE OF last_error, processed_at, event_type ON stripe_webhook_event
FOR EACH ROW EXECUTE FUNCTION queue_stripe_checkout_association_alert();
