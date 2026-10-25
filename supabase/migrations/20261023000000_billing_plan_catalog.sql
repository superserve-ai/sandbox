-- Self-serve subscription plans. Checkout freezes a plan's terms into the
-- purchase, so editing a row changes only checkouts started afterwards; rows
-- are never deleted because contracts keep referencing their offer_key.
-- Stripe price IDs differ per environment and stay in API configuration.
-- Every plan activates with its own limits.
CREATE TABLE billing_plan (
    offer_key text PRIMARY KEY REFERENCES plan_limits(offer_key) CHECK (offer_key ~ '^[a-z][a-z0-9]*_(monthly|annual)$'),
    family text NOT NULL CHECK (family ~ '^[a-z][a-z0-9]*$'),
    display_name text NOT NULL CHECK (btrim(display_name) <> ''),
    charge_interval_months integer NOT NULL CHECK (charge_interval_months IN (1, 12)),
    charge_amount_cents bigint NOT NULL CHECK (charge_amount_cents > 0),
    monthly_credit_cents bigint NOT NULL CHECK (monthly_credit_cents > 0),
    -- Unavailable plans reject new checkouts but keep existing purchases working.
    available boolean NOT NULL DEFAULT false,
    sort_order integer NOT NULL DEFAULT 0,
    CHECK (offer_key = family || CASE charge_interval_months WHEN 1 THEN '_monthly' ELSE '_annual' END)
);
ALTER TABLE billing_plan ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_plan FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_plan FROM %I',r);
            IF r='service_role' THEN
                GRANT SELECT ON billing_plan TO service_role;
                CREATE POLICY billing_plan_backend ON billing_plan TO service_role USING (true);
            END IF;
        END IF;
    END LOOP;
END $$;

-- Contracts and purchases keep referencing a plan's offer_key, and the
-- billing guards below treat only catalog plans as paid plans.
CREATE FUNCTION guard_billing_plan_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'billing plans cannot be deleted or renamed';
END $$;
CREATE TRIGGER billing_plan_identity_guard BEFORE DELETE OR UPDATE OF offer_key ON billing_plan
    FOR EACH ROW EXECUTE FUNCTION guard_billing_plan_identity();
CREATE TRIGGER billing_plan_truncate_guard BEFORE TRUNCATE ON billing_plan
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_plan_identity();

INSERT INTO billing_plan VALUES
    ('pro_monthly', 'pro', 'Pro', 1, 120000, 100000, true, 20),
    ('pro_annual', 'pro', 'Pro', 12, 1200000, 100000, true, 21);

CREATE FUNCTION billing_plan_offer(p_offer text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM billing_plan WHERE offer_key = p_offer);
$$;

ALTER TABLE billing_signup_choice DROP CONSTRAINT billing_signup_choice_offer_key_check;
CREATE FUNCTION guard_billing_signup_offer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.offer_key IS NOT NULL AND NEW.offer_key <> 'free' AND NOT billing_plan_offer(NEW.offer_key) THEN
        RAISE EXCEPTION 'unknown signup offer %', NEW.offer_key;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_signup_offer_guard BEFORE INSERT OR UPDATE OF offer_key ON billing_signup_choice
    FOR EACH ROW EXECUTE FUNCTION guard_billing_signup_offer();

-- Amounts are frozen per purchase and verified against the Stripe price, so
-- the contract only pins the shape every self-serve plan shares.
DO $$ DECLARE c text; BEGIN
    SELECT conname INTO STRICT c FROM pg_constraint
    WHERE conrelid = 'billing_commercial_contract'::regclass AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%pro_monthly%';
    EXECUTE format('ALTER TABLE billing_commercial_contract DROP CONSTRAINT %I', c);
END $$;
CREATE FUNCTION guard_billing_plan_contract() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p billing_plan;
BEGIN
    SELECT * INTO p FROM billing_plan WHERE offer_key = NEW.offer_key;
    IF FOUND AND (NEW.charge_kind <> 'subscription' OR NEW.entitlement_kind <> 'metered_usage'
        OR NEW.entitlement_cadence <> 'monthly' OR NEW.charge_interval_months <> p.charge_interval_months) THEN
        RAISE EXCEPTION 'contract shape differs from plan %', NEW.offer_key;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_plan_contract_guard
    BEFORE INSERT OR UPDATE OF offer_key, charge_kind, entitlement_kind, entitlement_cadence, charge_interval_months
    ON billing_commercial_contract
    FOR EACH ROW EXECUTE FUNCTION guard_billing_plan_contract();
REVOKE ALL ON FUNCTION billing_plan_offer(text), guard_billing_plan_identity(), guard_billing_signup_offer(), guard_billing_plan_contract() FROM PUBLIC;
-- Security-invoker guards and eligibility checks call the predicate as the
-- backend role.
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN GRANT EXECUTE ON FUNCTION billing_plan_offer(text) TO service_role; END IF; END $$;

DROP INDEX billing_signup_recovery;
CREATE INDEX billing_signup_recovery ON billing_signup_choice(next_check_at,team_id) WHERE offer_key <> 'free';
DROP INDEX billing_entitlement_audit_contract;
CREATE INDEX billing_entitlement_audit_contract ON billing_commercial_contract(id) WHERE status='active';

-- The functions below are unchanged apart from recognising every catalog plan
-- where they previously listed the two Pro offers.
CREATE OR REPLACE FUNCTION guard_pro_billing_account() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE choice billing_signup_choice;
BEGIN
    SELECT * INTO choice FROM billing_signup_choice WHERE team_id=NEW.team_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NEW; END IF;
    IF billing_plan_offer(choice.offer_key) THEN
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

CREATE OR REPLACE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.status='active' AND c.collection_has_overdue_balance IS FALSE
  AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until>clock_timestamp() AND c.starts_at<=s
  AND (c.ends_at IS NULL OR c.ends_at>=e)
  AND (NOT (billing_plan_offer(c.offer_key) OR c.offer_key IN ('yc_2026','sponsored_usage')) OR
    (c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
     AND (c.collection_evidence->>'period_start')::timestamptz=s
     AND (c.collection_evidence->>'period_end')::timestamptz=e))
  AND (billing_sponsored_covered(c,s,e,true) OR billing_yc_covered(c,s,e,true) OR EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND p.service_period_start<=s AND p.service_period_end>=e
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)
   AND (NOT (billing_plan_offer(c.offer_key) OR c.offer_key IN ('yc_2026','sponsored_usage')) OR EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute'))))
  AND EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=c.team_id
   AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id);
$$;

CREATE OR REPLACE FUNCTION enqueue_billing_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND (billing_plan_offer(NEW.offer_key) OR NEW.offer_key IN ('yc_2026','sponsored_usage')) AND (TG_OP='INSERT' OR OLD.status IS DISTINCT FROM NEW.status) THEN
  INSERT INTO billing_entitlement_work(contract_id) VALUES(NEW.id)
  ON CONFLICT(contract_id) DO UPDATE SET next_check_at=least(billing_entitlement_work.next_check_at,clock_timestamp()),wake_generation=billing_entitlement_work.wake_generation+1;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION fence_sponsored_billing() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE t uuid;
BEGIN
 t:=NEW.team_id;
 PERFORM 1 FROM team_billing_account WHERE team_id=t FOR UPDATE;
 IF TG_TABLE_NAME='billing_sponsored_operation' THEN
  IF EXISTS(SELECT 1 FROM billing_sponsored_operation o JOIN billing_commercial_contract c ON c.id=o.contract_id
   WHERE o.team_id=t AND o.subscription_id=NEW.subscription_id AND o.resource_terms<>NEW.resource_terms) THEN
   RAISE EXCEPTION 'subscription resource terms conflict with historical sponsorship'; END IF;
  IF EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=t AND status<>'ended')
   OR EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=t AND NOT billing_yc_released(t))
   OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=t AND billing_plan_offer(offer_key) AND state<>'selecting')
   OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=t AND (checkout_initializing_at IS NOT NULL OR checkout_may_exist)) THEN
   RAISE EXCEPTION 'sponsorship conflicts with commercial authority'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM billing_sponsored_operation o WHERE o.team_id=t AND
    (o.state NOT IN ('revoked','expired') OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.sponsorship_id=o.id AND e.period_end>clock_timestamp()))) THEN
   IF TG_TABLE_NAME='billing_commercial_contract' THEN
    IF NEW.charge_kind<>'sponsored_entitlement' THEN RAISE EXCEPTION 'commercial authority conflicts with sponsorship'; END IF;
   ELSIF TG_TABLE_NAME='team_billing_account' THEN
    IF NEW.checkout_initializing_at IS NOT NULL OR NEW.checkout_may_exist THEN RAISE EXCEPTION 'checkout conflicts with sponsorship'; END IF;
   ELSE RAISE EXCEPTION 'commercial authority conflicts with sponsorship'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION guard_billing_plan_release() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a team_billing_account; o billing_yc_operation;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'plan release history is immutable'; END IF;
 SELECT * INTO STRICT a FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
 IF (a.stripe_customer_id,a.stripe_subscription_id) IS DISTINCT FROM (NEW.customer_id,NEW.subscription_id)
 OR NEW.previous_account IS DISTINCT FROM to_jsonb(a)
 OR NOT EXISTS(SELECT 1 FROM billing_signup_choice c WHERE c.team_id=NEW.team_id AND to_jsonb(c)=NEW.previous_choice)
 OR EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.team_id=NEW.team_id AND c.status<>'ended') THEN
  RAISE EXCEPTION 'plan release account preconditions changed';
 END IF;
 IF (a.checkout_initializing_at IS NOT NULL OR a.checkout_may_exist) AND NOT COALESCE(
  billing_plan_offer(NEW.previous_choice->>'offer_key') AND NEW.previous_choice->>'state'='committed'
  AND cardinality(a.checkout_pending_attempt_ids)=0
  AND NEW.provider_evidence->'checkout'->>'status'='complete'
  AND NEW.provider_evidence->'checkout'->>'mode'='subscription'
  AND NEW.provider_evidence->'checkout'->>'id'=a.checkout_session_id
  AND NEW.provider_evidence->'checkout'->>'id'=NEW.previous_choice->>'session_id'
  AND NEW.provider_evidence->'checkout'->>'customer'=NEW.customer_id
  AND NEW.provider_evidence->'checkout'->>'subscription'=NEW.subscription_id
  AND NEW.provider_evidence->'checkout'->>'client_reference_id'=NEW.team_id::text
  AND (NEW.provider_evidence->'checkout'->'metadata'->>'checkout_generation')::timestamptz=a.checkout_initializing_at
  AND (NEW.previous_choice->>'generation')::timestamptz=a.checkout_initializing_at
  AND NEW.provider_evidence->'checkout'->'metadata'->>'commercial_offer'=NEW.previous_choice->>'offer_key'
  AND NEW.provider_evidence->'checkout'->'metadata'->>'activation_user_id'=NEW.previous_choice->>'actor_id'
  AND NEW.previous_choice->'request_payload'->>'CustomerID'=NEW.customer_id
  AND NEW.previous_choice->'request_payload'->>'IdempotencyKey'=a.checkout_request_key,false) THEN
   RAISE EXCEPTION 'plan release has unresolved checkout attempts';
 END IF;
 IF NEW.subscription_id IS NULL THEN
  IF NEW.provider_status<>'no_attempt' THEN RAISE EXCEPTION 'missing subscription requires no-attempt proof'; END IF;
 ELSIF NEW.provider_status NOT IN ('canceled','incomplete_expired') OR NEW.provider_evidence='{}'::jsonb THEN
  RAISE EXCEPTION 'plan release requires terminal provider evidence';
 END IF;
 SELECT * INTO o FROM billing_yc_operation WHERE team_id=NEW.team_id FOR UPDATE;
 IF FOUND AND NOT billing_yc_released(NEW.team_id) THEN
  IF NEW.yc_operation_id IS DISTINCT FROM o.id OR NEW.previous_yc IS DISTINCT FROM to_jsonb(o)
   OR o.state<>'ended' OR (o.subscription_id IS NULL AND (o.provider_attempt_at IS NOT NULL OR o.revoked_at IS NULL)) THEN
   RAISE EXCEPTION 'YC release requires reconciled terminal operation';
  END IF;
 ELSIF NEW.yc_operation_id IS NOT NULL OR NEW.previous_yc IS NOT NULL THEN
  RAISE EXCEPTION 'YC release identity missing';
 END IF;
 RETURN NEW;
END $$;
