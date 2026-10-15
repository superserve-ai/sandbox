-- Existing teams remain PAYG; only newly created teams enter plan selection.
CREATE TABLE billing_signup_choice (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    offer_key text CHECK (offer_key IN ('free','pro_monthly','pro_annual')),
    state text NOT NULL DEFAULT 'selecting' CHECK (state IN ('selecting','pending','committed')),
    generation timestamptz,
    actor_id uuid,
    base_price_id text,
    request_payload jsonb,
    session_id text,
    subscription_id text,
    next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text,
    invoice_cursor text,
    paid_observed_at timestamptz,
    paid_observed_until timestamptz,
    revision bigint NOT NULL DEFAULT 0,
    CHECK ((state='selecting' AND offer_key IS NULL) OR (state<>'selecting' AND offer_key IS NOT NULL)),
    CHECK (offer_key IS NULL OR offer_key='free' OR (generation IS NOT NULL AND actor_id IS NOT NULL AND base_price_id IS NOT NULL AND request_payload IS NOT NULL))
);
CREATE UNIQUE INDEX billing_signup_subscription ON billing_signup_choice(subscription_id) WHERE subscription_id IS NOT NULL;
CREATE INDEX billing_signup_recovery ON billing_signup_choice(next_check_at,team_id) WHERE offer_key IN ('pro_monthly','pro_annual');
ALTER TABLE billing_signup_choice ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_signup_choice FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_signup_choice FROM %I',r);
            IF r='service_role' THEN
                GRANT SELECT,INSERT,UPDATE ON billing_signup_choice TO service_role;
                CREATE POLICY billing_signup_backend ON billing_signup_choice TO service_role USING (true) WITH CHECK (true);
            END IF;
        END IF;
    END LOOP;
END $$;
CREATE FUNCTION initialize_billing_signup_choice() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    INSERT INTO public.billing_signup_choice(team_id) VALUES(NEW.id);
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION initialize_billing_signup_choice() FROM PUBLIC;
CREATE TRIGGER billing_signup_choice_insert AFTER INSERT ON team FOR EACH ROW EXECUTE FUNCTION initialize_billing_signup_choice();

-- Older API cells must not route Pro through the PAYG promotion lifecycle.
CREATE FUNCTION guard_pro_billing_account() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE choice billing_signup_choice;
BEGIN
    SELECT * INTO choice FROM billing_signup_choice WHERE team_id=NEW.team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NEW; END IF;
    IF choice.offer_key IN ('pro_monthly','pro_annual') THEN
        IF NEW.stripe_activation_credit_reserved_at IS NOT NULL OR NEW.stripe_activation_credit_granted_at IS NOT NULL
            OR NEW.stripe_activation_credit_grant_id IS NOT NULL THEN
            RAISE EXCEPTION 'Pro purchase cannot reserve or receive a PAYG promotion';
        END IF;
        IF NEW.checkout_initializing_at IS NOT NULL AND
            (NEW.checkout_initializing_at IS DISTINCT FROM choice.generation OR NEW.checkout_request_key NOT LIKE 'pro:%') THEN
            RAISE EXCEPTION 'conflicting Pro checkout generation';
        END IF;
        IF NEW.trial_ended_at IS DISTINCT FROM OLD.trial_ended_at AND NOT EXISTS (
            SELECT 1 FROM billing_contract_payment p JOIN billing_commercial_contract c ON c.id=p.contract_id
            WHERE c.team_id=NEW.team_id AND c.subscription_id=NEW.stripe_subscription_id
        ) THEN RAISE EXCEPTION 'Pro trial termination requires verified base payment'; END IF;
    ELSIF NEW.checkout_initializing_at IS NOT NULL AND OLD.checkout_initializing_at IS NULL THEN
        UPDATE billing_signup_choice SET offer_key='free',state='committed',revision=revision+1 WHERE team_id=NEW.team_id;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION guard_pro_billing_account() FROM PUBLIC;
CREATE TRIGGER pro_billing_account_guard BEFORE UPDATE ON team_billing_account FOR EACH ROW EXECUTE FUNCTION guard_pro_billing_account();

-- Paid invoices are immutable; remembering verified observations bounds recovery work.
CREATE TABLE billing_pro_invoice_seen (
 team_id uuid NOT NULL REFERENCES billing_signup_choice(team_id) ON DELETE CASCADE,
 invoice_id text PRIMARY KEY,
 checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE billing_pro_invoice_seen ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_invoice_seen FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_pro_invoice_seen FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT ON billing_pro_invoice_seen TO service_role;
    CREATE POLICY billing_pro_invoice_seen_backend ON billing_pro_invoice_seen TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
END $$;

CREATE TABLE billing_pro_closed_purchase (
 team_id uuid NOT NULL REFERENCES billing_signup_choice(team_id) ON DELETE CASCADE,
 generation timestamptz NOT NULL,
 session_id text NOT NULL UNIQUE,
 subscription_id text NOT NULL UNIQUE,
 evidence jsonb NOT NULL,
 PRIMARY KEY(team_id,generation)
);
ALTER TABLE billing_pro_closed_purchase ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_closed_purchase FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_pro_closed_purchase FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT ON billing_pro_closed_purchase TO service_role;
    CREATE POLICY billing_pro_closed_purchase_backend ON billing_pro_closed_purchase TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
END $$;

CREATE INDEX billing_pro_pending_paid ON billing_signup_choice(offer_key,paid_observed_at)
 WHERE state='pending' AND paid_observed_at IS NOT NULL;
CREATE INDEX billing_pro_pending_due ON billing_signup_choice(offer_key,next_check_at) WHERE state='pending';

-- Verification observations are separate from immutable payment receipts.
CREATE TABLE billing_pro_payment_verification (
 invoice_id text PRIMARY KEY REFERENCES billing_contract_payment(invoice_id),
 review_required boolean NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence)='object')
);
ALTER TABLE billing_pro_payment_verification ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_payment_verification FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_pro_payment_verification FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON billing_pro_payment_verification TO service_role;
    CREATE POLICY billing_pro_payment_verification_backend ON billing_pro_payment_verification TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
END $$;
CREATE FUNCTION guard_pro_payment_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'payment verification history cannot be deleted'; END IF;
 IF TG_OP='UPDATE' AND NEW.invoice_id<>OLD.invoice_id THEN RAISE EXCEPTION 'payment verification identity is immutable'; END IF;
 PERFORM 1 FROM billing_commercial_contract c JOIN billing_contract_payment p ON p.contract_id=c.id WHERE p.invoice_id=NEW.invoice_id FOR UPDATE OF c;
 NEW.observed_at:=clock_timestamp();
 RETURN NEW;
END $$;
CREATE TRIGGER billing_pro_payment_verification_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_pro_payment_verification FOR EACH ROW EXECUTE FUNCTION guard_pro_payment_verification();

CREATE OR REPLACE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.status='active' AND c.collection_has_overdue_balance IS FALSE
  AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until>clock_timestamp() AND c.starts_at<=s
  AND (c.ends_at IS NULL OR c.ends_at>=e)
  AND EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND p.service_period_start<=s AND p.service_period_end>=e
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required))
  AND EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=c.team_id
   AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id);
$$;
CREATE FUNCTION guard_pro_payment_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- A possible external write must still be recoverable; only new authorization stops.
 IF TG_OP='UPDATE' AND OLD.state<>'pending' THEN RETURN NEW; END IF;
 PERFORM 1 FROM billing_commercial_contract WHERE id=NEW.contract_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM billing_contract_payment p JOIN billing_pro_payment_verification v USING(invoice_id)
  WHERE p.id=NEW.payment_id AND v.review_required) THEN RAISE EXCEPTION 'base payment verification requires review'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_pro_payment_entitlement_guard BEFORE INSERT OR UPDATE ON billing_usage_entitlement FOR EACH ROW EXECUTE FUNCTION guard_pro_payment_entitlement();
CREATE FUNCTION guard_pro_payment_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='pending' AND NEW.status='active' AND NOT EXISTS(
  SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=NEW.id
   AND p.service_period_start<=clock_timestamp() AND p.service_period_end>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required))
 THEN RAISE EXCEPTION 'activation requires an unquestioned base payment'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_pro_payment_activation_guard BEFORE UPDATE ON billing_commercial_contract FOR EACH ROW EXECUTE FUNCTION guard_pro_payment_activation();
REVOKE ALL ON FUNCTION guard_pro_payment_verification(),guard_pro_payment_entitlement(),guard_pro_payment_activation() FROM PUBLIC;
CREATE INDEX billing_pro_unexpired_payment_lookup ON billing_contract_payment(team_id,service_period_end);
