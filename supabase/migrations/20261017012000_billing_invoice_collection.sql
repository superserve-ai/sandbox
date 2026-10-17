-- Accounting release hands collection to a durable, independently retried job.
CREATE TABLE billing_invoice_collection (
    invoice_id text PRIMARY KEY REFERENCES billing_invoice_close(invoice_id),
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    livemode boolean NOT NULL,
    settlement_hash text NOT NULL,
    idempotency_key text NOT NULL UNIQUE,
    payment_authorized boolean NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN
        ('pending','unknown','processing','requires_action','requires_payment_method','review_required','paid','void','uncollectible')),
    first_attempt_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_until timestamptz,
    last_error text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
ALTER TABLE billing_invoice_collection ENABLE ROW LEVEL SECURITY;
CREATE INDEX billing_invoice_collection_due ON billing_invoice_collection(next_attempt_at)
    WHERE state NOT IN ('paid','void');
CREATE INDEX billing_invoice_collection_leases ON billing_invoice_collection(lease_until)
    WHERE lease_until IS NOT NULL;
CREATE TABLE billing_invoice_collection_scheduler (id boolean PRIMARY KEY DEFAULT true CHECK (id));
INSERT INTO billing_invoice_collection_scheduler DEFAULT VALUES;
ALTER TABLE billing_invoice_collection_scheduler ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION guard_billing_invoice_collection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.invoice_id,NEW.customer_id,NEW.subscription_id,NEW.livemode,NEW.settlement_hash,NEW.idempotency_key,NEW.payment_authorized)
       IS DISTINCT FROM ROW(OLD.invoice_id,OLD.customer_id,OLD.subscription_id,OLD.livemode,OLD.settlement_hash,OLD.idempotency_key,OLD.payment_authorized)
       OR (OLD.first_attempt_at IS NOT NULL AND NEW.first_attempt_at IS DISTINCT FROM OLD.first_attempt_at) THEN
        RAISE EXCEPTION 'invoice collection authority is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_collection_guard BEFORE UPDATE ON billing_invoice_collection
    FOR EACH ROW EXECUTE FUNCTION guard_billing_invoice_collection();
