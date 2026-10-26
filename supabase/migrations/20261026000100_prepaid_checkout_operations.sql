-- An operation is a purchase intent, independent of browser and provider replies.
-- Retain its binding after team deletion, like the durable purchase history.
CREATE TABLE billing_prepaid_checkout_operation (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    amount_cents bigint NOT NULL CHECK (amount_cents >= 500 AND amount_cents <= 100000000 AND amount_cents % 500 = 0),
    success_url text NOT NULL,
    cancel_url text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION guard_billing_prepaid_checkout_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM team WHERE id=NEW.team_id FOR KEY SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'checkout operation team does not exist' USING ERRCODE='23503'; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'checkout operation bindings are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER billing_prepaid_checkout_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_prepaid_checkout_operation
    FOR EACH ROW EXECUTE FUNCTION guard_billing_prepaid_checkout_operation();
CREATE TRIGGER billing_prepaid_checkout_operation_truncate_guard BEFORE TRUNCATE ON billing_prepaid_checkout_operation
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_prepaid_checkout_operation();
ALTER TABLE billing_prepaid_checkout_operation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_prepaid_checkout_operation FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_billing_prepaid_checkout_operation() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_prepaid_checkout_operation FROM %I',r);
            EXECUTE format('REVOKE ALL ON FUNCTION guard_billing_prepaid_checkout_operation() FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT SELECT, INSERT ON billing_prepaid_checkout_operation TO service_role;
    END IF;
END $$;
