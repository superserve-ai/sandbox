-- Activation enqueues enrollment transactionally; the worker also seeds existing
-- accounts. Retry state survives outages without running provider I/O in triggers.
CREATE TABLE billing_invoice_enrollment (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempt_count integer NOT NULL DEFAULT 0,
    completed_at timestamptz,
    last_error text
);
ALTER TABLE billing_invoice_enrollment ENABLE ROW LEVEL SECURITY;
CREATE INDEX billing_invoice_enrollment_pending ON billing_invoice_enrollment(next_attempt_at,team_id)
    WHERE completed_at IS NULL;

CREATE FUNCTION queue_billing_invoice_enrollment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.stripe_subscription_status='active' AND NEW.stripe_customer_id IS NOT NULL
       AND NEW.stripe_subscription_id IS NOT NULL THEN
        INSERT INTO billing_invoice_enrollment(team_id,customer_id,subscription_id) VALUES(NEW.team_id,NEW.stripe_customer_id,NEW.stripe_subscription_id)
        ON CONFLICT(team_id) DO UPDATE SET completed_at=NULL,next_attempt_at=clock_timestamp(),last_error=NULL,
          requested_at=CASE WHEN billing_invoice_enrollment.customer_id<>EXCLUDED.customer_id OR billing_invoice_enrollment.subscription_id<>EXCLUDED.subscription_id THEN clock_timestamp() ELSE billing_invoice_enrollment.requested_at END,
          started_at=CASE WHEN billing_invoice_enrollment.customer_id<>EXCLUDED.customer_id OR billing_invoice_enrollment.subscription_id<>EXCLUDED.subscription_id THEN NULL ELSE billing_invoice_enrollment.started_at END,
          customer_id=EXCLUDED.customer_id,subscription_id=EXCLUDED.subscription_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_invoice_activation_enrollment AFTER INSERT OR UPDATE OF stripe_customer_id,stripe_subscription_id,stripe_subscription_status
ON team_billing_account FOR EACH ROW EXECUTE FUNCTION queue_billing_invoice_enrollment();

INSERT INTO billing_invoice_enrollment(team_id,customer_id,subscription_id)
SELECT team_id,stripe_customer_id,stripe_subscription_id FROM team_billing_account WHERE stripe_subscription_status='active'
    AND stripe_customer_id IS NOT NULL AND stripe_subscription_id IS NOT NULL;
