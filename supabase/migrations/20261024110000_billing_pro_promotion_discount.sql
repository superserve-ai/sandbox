-- The promotion code a contract was sold with. It discounts only the checkout
-- invoice: discounted_cents is how much of that invoice's licensed fee it
-- covered. The contract's fee and terms never change because of it.
CREATE TABLE billing_contract_promotion (
    contract_id uuid PRIMARY KEY,
    team_id uuid NOT NULL,
    discount_id text NOT NULL CHECK (btrim(discount_id) <> ''),
    promotion_code text NOT NULL CHECK (btrim(promotion_code) <> ''),
    coupon_id text NOT NULL CHECK (btrim(coupon_id) <> ''),
    coupon_duration text NOT NULL CHECK (coupon_duration IN ('once', 'repeating', 'forever')),
    amount_off_cents bigint CHECK (amount_off_cents > 0),
    percent_off numeric CHECK (percent_off > 0 AND percent_off <= 100),
    checkout_invoice_id text NOT NULL UNIQUE CHECK (btrim(checkout_invoice_id) <> ''),
    discounted_cents bigint NOT NULL CHECK (discounted_cents >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (team_id, contract_id) REFERENCES billing_commercial_contract(team_id, id),
    CHECK ((amount_off_cents IS NULL) <> (percent_off IS NULL))
);
CREATE TRIGGER billing_contract_promotion_guard BEFORE UPDATE OR DELETE ON billing_contract_promotion
    FOR EACH ROW EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_contract_promotion_truncate_guard BEFORE TRUNCATE ON billing_contract_promotion
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();

-- A receipt's cash must cover the licensed fee less the promotion on its
-- contract's checkout invoice. This replaces the column check, which could
-- not see the promotion; every other invoice must still pay the full fee.
CREATE FUNCTION guard_billing_contract_payment_cash() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE discounted bigint;
BEGIN
    SELECT p.discounted_cents INTO discounted FROM billing_contract_promotion p
    WHERE p.contract_id = NEW.contract_id AND p.checkout_invoice_id = NEW.invoice_id;
    IF NEW.invoice_amount_paid_cents < NEW.base_amount_paid_cents - COALESCE(discounted, 0)
        OR COALESCE(discounted, 0) > NEW.base_amount_paid_cents THEN
        RAISE EXCEPTION 'invoice cash does not cover the licensed fee';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_contract_payment_cash_guard BEFORE INSERT ON billing_contract_payment
    FOR EACH ROW EXECUTE FUNCTION guard_billing_contract_payment_cash();

DO $$ DECLARE c text; BEGIN
    SELECT conname INTO STRICT c FROM pg_constraint
    WHERE conrelid = 'billing_contract_payment'::regclass AND contype = 'c'
        AND pg_get_constraintdef(oid) = 'CHECK ((invoice_amount_paid_cents >= base_amount_paid_cents))';
    EXECUTE format('ALTER TABLE billing_contract_payment DROP CONSTRAINT %I', c);
END $$;

DO $$ DECLARE r text; BEGIN
    ALTER TABLE billing_contract_promotion ENABLE ROW LEVEL SECURITY;
    REVOKE ALL ON TABLE billing_contract_promotion FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_billing_contract_payment_cash() FROM PUBLIC;
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON TABLE billing_contract_promotion FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION guard_billing_contract_payment_cash() FROM %I', r);
            IF r = 'service_role' THEN
                GRANT SELECT, INSERT ON TABLE billing_contract_promotion TO service_role;
                CREATE POLICY billing_contract_promotion_backend ON billing_contract_promotion TO service_role USING (true) WITH CHECK (true);
                GRANT EXECUTE ON FUNCTION guard_billing_contract_payment_cash() TO service_role;
            END IF;
        END IF;
    END LOOP;
END $$;
