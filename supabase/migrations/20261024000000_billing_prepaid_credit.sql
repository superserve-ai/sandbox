-- Starter prepaid credit: each purchase is one durable row that first proves a
-- payment and then issues exactly one non-expiring credit grant for it.
CREATE TABLE billing_prepaid_purchase (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    customer_id text NOT NULL CHECK (btrim(customer_id) <> ''),
    source text NOT NULL CHECK (source IN ('checkout', 'auto_recharge')),
    amount_cents bigint NOT NULL CHECK (amount_cents >= 500 AND amount_cents % 500 = 0 AND amount_cents <= 100000000),
    actor_id uuid,
    plan_snapshot jsonb CHECK (plan_snapshot IS NULL OR jsonb_typeof(plan_snapshot)='object'),
    payment_state text NOT NULL DEFAULT 'pending' CHECK (payment_state IN ('pending', 'uncertain', 'processing', 'succeeded', 'failed')),
    payment_idempotency_key text NOT NULL UNIQUE,
    payment_request jsonb,
    payment_first_attempt_at timestamptz,
    checkout_session_id text UNIQUE CHECK (btrim(checkout_session_id) <> ''),
    payment_intent_id text UNIQUE CHECK (btrim(payment_intent_id) <> ''),
    invoice_id text UNIQUE CHECK (btrim(invoice_id) <> ''),
    payment_evidence jsonb,
    paid_at timestamptz,
    failure_code text,
    failure_reason text,
    credit_state text NOT NULL DEFAULT 'none' CHECK (credit_state IN ('none', 'pending', 'uncertain', 'issued')),
    credit_idempotency_key text NOT NULL UNIQUE,
    credit_request jsonb,
    credit_first_attempt_at timestamptz,
    stripe_credit_grant_id text UNIQUE CHECK (btrim(stripe_credit_grant_id) <> ''),
    credit_evidence jsonb,
    credited_at timestamptz,
    credit_voided_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    failures integer NOT NULL DEFAULT 0,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (source = 'auto_recharge' OR actor_id IS NOT NULL),
    CHECK ((payment_state = 'succeeded') = (paid_at IS NOT NULL AND payment_evidence IS NOT NULL)),
    CHECK ((payment_state = 'failed') = (failure_reason IS NOT NULL)),
    CHECK (payment_state <> 'pending' OR payment_first_attempt_at IS NULL),
    CHECK (credit_state = 'none' OR payment_state = 'succeeded'),
    CHECK ((credit_state = 'none') = (credit_request IS NULL)),
    CHECK ((credit_state IN ('none', 'pending')) = (credit_first_attempt_at IS NULL)),
    CHECK ((credit_state = 'issued') = (stripe_credit_grant_id IS NOT NULL AND credit_evidence IS NOT NULL AND credited_at IS NOT NULL)),
    CHECK (credit_voided_at IS NULL OR credit_state = 'issued')
);
CREATE INDEX billing_prepaid_purchase_team ON billing_prepaid_purchase(team_id, created_at);
CREATE INDEX billing_prepaid_purchase_paid ON billing_prepaid_purchase(paid_at) WHERE payment_state = 'succeeded';
CREATE INDEX billing_prepaid_purchase_due ON billing_prepaid_purchase(next_attempt_at)
    WHERE payment_state IN ('pending', 'uncertain', 'processing') OR credit_state IN ('pending', 'uncertain');
-- A team never has two automatic charges that could both still succeed.
CREATE UNIQUE INDEX billing_prepaid_auto_recharge_in_flight ON billing_prepaid_purchase(team_id)
    WHERE source = 'auto_recharge' AND payment_state IN ('pending', 'uncertain', 'processing');

CREATE TABLE billing_prepaid_auto_recharge (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    threshold_cents bigint CHECK (threshold_cents >= 500 AND threshold_cents % 500 = 0 AND threshold_cents <= 100000000),
    amount_cents bigint CHECK (amount_cents >= 500 AND amount_cents % 500 = 0 AND amount_cents <= 100000000),
    updated_by uuid,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    disabled_reason text CHECK (btrim(disabled_reason) <> ''),
    disabled_at timestamptz,
    disabled_by uuid,
    notified_at timestamptz,
    CHECK (NOT enabled OR (threshold_cents IS NOT NULL AND amount_cents IS NOT NULL)),
    CHECK ((disabled_reason IS NULL) = (disabled_at IS NULL)),
    CHECK (NOT enabled OR disabled_reason IS NULL)
);

CREATE FUNCTION guard_billing_prepaid_purchase() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'prepaid purchase history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM team WHERE id=NEW.team_id FOR KEY SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'purchase team does not exist' USING ERRCODE='23503'; END IF;
        NEW.payment_idempotency_key := 'prepaid-payment:v1:' || NEW.id;
        NEW.credit_idempotency_key := 'prepaid-credit:v1:' || NEW.id;
        NEW.payment_state := 'pending';
        NEW.credit_state := 'none';
        NEW.payment_first_attempt_at := NULL;
        NEW.paid_at := NULL;
        NEW.payment_evidence := NULL;
        NEW.credit_request := NULL;
        NEW.stripe_credit_grant_id := NULL;
        NEW.credit_evidence := NULL;
        NEW.credited_at := NULL;
        NEW.credit_voided_at := NULL;
        RETURN NEW;
    END IF;
    IF (NEW.id, NEW.team_id, NEW.customer_id, NEW.source, NEW.amount_cents, NEW.actor_id, NEW.payment_idempotency_key, NEW.credit_idempotency_key, NEW.created_at, NEW.plan_snapshot)
        IS DISTINCT FROM (OLD.id, OLD.team_id, OLD.customer_id, OLD.source, OLD.amount_cents, OLD.actor_id, OLD.payment_idempotency_key, OLD.credit_idempotency_key, OLD.created_at, OLD.plan_snapshot) THEN
        RAISE EXCEPTION 'prepaid purchase terms are immutable';
    END IF;
    IF OLD.payment_state IN ('succeeded', 'failed') AND (NEW.payment_state, NEW.payment_evidence, NEW.paid_at, NEW.failure_reason)
        IS DISTINCT FROM (OLD.payment_state, OLD.payment_evidence, OLD.paid_at, OLD.failure_reason) THEN
        RAISE EXCEPTION 'a settled payment outcome is immutable';
    END IF;
    IF OLD.payment_request IS NOT NULL AND NEW.payment_request IS DISTINCT FROM OLD.payment_request THEN
        RAISE EXCEPTION 'a dispatched payment request is immutable';
    END IF;
    IF OLD.payment_first_attempt_at IS NOT NULL AND NEW.payment_first_attempt_at IS DISTINCT FROM OLD.payment_first_attempt_at THEN
        RAISE EXCEPTION 'payment attempt identity is immutable';
    END IF;
    IF (OLD.checkout_session_id IS NOT NULL AND NEW.checkout_session_id IS DISTINCT FROM OLD.checkout_session_id)
        OR (OLD.payment_intent_id IS NOT NULL AND NEW.payment_intent_id IS DISTINCT FROM OLD.payment_intent_id)
        OR (OLD.invoice_id IS NOT NULL AND NEW.invoice_id IS DISTINCT FROM OLD.invoice_id) THEN
        RAISE EXCEPTION 'payment references are immutable once recorded';
    END IF;
    IF NEW.payment_state = 'succeeded' AND OLD.payment_state <> 'succeeded'
        AND ((NEW.payment_evidence->>'amount_cents')::bigint IS DISTINCT FROM NEW.amount_cents
            OR NEW.payment_evidence->>'customer' IS DISTINCT FROM NEW.customer_id) THEN
        RAISE EXCEPTION 'payment evidence does not prove this purchase';
    END IF;
    IF NEW.credit_state IS DISTINCT FROM OLD.credit_state
        OR NEW.credit_request IS DISTINCT FROM OLD.credit_request
        OR NEW.credit_first_attempt_at IS DISTINCT FROM OLD.credit_first_attempt_at
        OR (NEW.stripe_credit_grant_id, NEW.credit_evidence, NEW.credited_at) IS DISTINCT FROM (OLD.stripe_credit_grant_id, OLD.credit_evidence, OLD.credited_at) THEN
        IF OLD.credit_state = 'none' AND NEW.credit_state = 'pending' THEN
            IF NEW.credit_first_attempt_at IS NOT NULL
                OR NEW.credit_request->>'customer' IS DISTINCT FROM NEW.customer_id
                OR NEW.credit_request->>'category' IS DISTINCT FROM 'paid'
                OR (NEW.credit_request #>> '{amount,monetary,value}')::bigint IS DISTINCT FROM NEW.amount_cents
                OR NEW.credit_request #>> '{amount,monetary,currency}' IS DISTINCT FROM 'usd'
                OR NEW.credit_request->>'priority' IS DISTINCT FROM '50'
                OR NEW.credit_request ? 'expires_at'
                OR NEW.credit_request #>> '{applicability_config,scope,price_type}' IS DISTINCT FROM 'metered'
                OR NEW.credit_request #>> '{metadata,prepaid_purchase_id}' IS DISTINCT FROM NEW.id::text THEN
                RAISE EXCEPTION 'credit request does not match the paid purchase';
            END IF;
        ELSIF OLD.credit_state = 'pending' AND NEW.credit_state = 'uncertain' AND NEW.credit_request = OLD.credit_request THEN
            IF NEW.credit_first_attempt_at IS NULL OR NEW.credit_first_attempt_at > clock_timestamp() OR NEW.credit_first_attempt_at < clock_timestamp() - interval '1 minute' THEN
                RAISE EXCEPTION 'credit intent must be recorded at dispatch';
            END IF;
        ELSIF OLD.credit_state = 'uncertain' AND NEW.credit_state = 'issued' AND NEW.credit_request = OLD.credit_request
            AND NEW.credit_first_attempt_at = OLD.credit_first_attempt_at THEN
            IF NEW.credit_evidence->>'id' IS DISTINCT FROM NEW.stripe_credit_grant_id
                OR COALESCE((NEW.credit_evidence->>'voided_at')::bigint, 0) <> 0
                OR COALESCE((NEW.credit_evidence->>'expires_at')::bigint, 0) <> 0
                OR NEW.credit_evidence->'customer' IS DISTINCT FROM NEW.credit_request->'customer'
                OR NEW.credit_evidence->'amount' IS DISTINCT FROM NEW.credit_request->'amount'
                OR NEW.credit_evidence->'category' IS DISTINCT FROM NEW.credit_request->'category'
                OR NEW.credit_evidence->'priority' IS DISTINCT FROM NEW.credit_request->'priority'
                OR NEW.credit_evidence #> '{applicability_config,scope,price_type}' IS DISTINCT FROM NEW.credit_request #> '{applicability_config,scope,price_type}'
                OR jsonb_array_length(COALESCE(NEW.credit_evidence #> '{applicability_config,scope,prices}', '[]'::jsonb)) <> 0
                OR NEW.credit_evidence #>> '{metadata,prepaid_purchase_id}' IS DISTINCT FROM NEW.id::text
                OR NEW.credited_at > clock_timestamp() OR NEW.credited_at < NEW.credit_first_attempt_at THEN
                RAISE EXCEPTION 'grant confirmation does not match the frozen request';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid prepaid credit transition';
        END IF;
    END IF;
    IF OLD.credit_voided_at IS NOT NULL AND NEW.credit_voided_at IS DISTINCT FROM OLD.credit_voided_at THEN
        RAISE EXCEPTION 'a voided grant stays voided';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_prepaid_purchase_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_prepaid_purchase
    FOR EACH ROW EXECUTE FUNCTION guard_billing_prepaid_purchase();

DO $$ DECLARE t text; r text; BEGIN
    FOREACH t IN ARRAY ARRAY['billing_prepaid_purchase', 'billing_prepaid_auto_recharge'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
        FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN EXECUTE format('REVOKE ALL ON %I FROM %I', t, r); END IF;
        END LOOP;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO service_role', t);
            EXECUTE format('CREATE POLICY backend_access ON %I TO service_role USING (true) WITH CHECK (true)', t);
        END IF;
    END LOOP;
END $$;
REVOKE ALL ON FUNCTION guard_billing_prepaid_purchase() FROM PUBLIC;

ALTER TABLE billing_prepaid_purchase ADD COLUMN credit_balance_checked_at timestamptz;
CREATE INDEX billing_prepaid_purchase_live_credit ON billing_prepaid_purchase(COALESCE(credit_balance_checked_at, '-infinity'::timestamptz))
    WHERE credit_state = 'issued' AND credit_voided_at IS NULL;

-- A prepaid team's compute is funded only by observed credit: a saved card
-- never substitutes for balance. Plan changes away from prepaid clear it.
ALTER TABLE billing_funding_account ADD COLUMN prepaid boolean NOT NULL DEFAULT false;
ALTER TABLE billing_funding_account ADD CONSTRAINT billing_funding_account_prepaid_enforced CHECK (NOT prepaid OR enforce);

-- Observation throughput is a policy next to the cohort budget so both can be
-- raised together after measuring refresh latency at the new size.
ALTER TABLE billing_funding_policy ADD COLUMN batch_size integer NOT NULL DEFAULT 4 CHECK (batch_size BETWEEN 1 AND 64);
UPDATE billing_funding_policy SET max_observed_teams = greatest(max_observed_teams, 30);

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE
 WHEN EXISTS(SELECT 1 FROM abuse_restrictions r WHERE r.subject_team_id=p_team_id AND r.released_at IS NULL
 AND (r.expires_at IS NULL OR r.expires_at>now()) AND r.action IN ('create','resume')) THEN false
 WHEN qm_team_managed_billing(p_team_id) THEN true
 WHEN NOT COALESCE(f.enforce,false) THEN team_sandbox_billing_eligible_legacy(p_team_id)
 WHEN f.observed_generation IS DISTINCT FROM f.generation
 OR (f.customer_id,f.subscription_id) IS DISTINCT FROM (a.stripe_customer_id,a.stripe_subscription_id) THEN false
 WHEN f.prepaid THEN f.credit_usd>0 AND f.credit_valid_until>now()
 WHEN f.credit_usd>0 AND f.credit_valid_until>now() AND (
 NOT EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=p_team_id AND state NOT IN ('revoked','expired'))
 OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.team_id=p_team_id AND e.sponsorship_id IS NOT NULL AND e.state='issued' AND e.period_start<=now() AND e.period_end>now())) THEN true
 ELSE COALESCE(f.payment_method_ready AND f.collection_ready AND f.provider_valid_until>now()
 AND (billing_funding_fingerprint(p_team_id)='clear' OR f.cash_collected),false) END
 FROM (SELECT p_team_id team_id) t LEFT JOIN billing_funding_account f USING(team_id)
 LEFT JOIN team_billing_account a USING(team_id);
$$;
CREATE INDEX billing_prepaid_purchase_customer_open ON billing_prepaid_purchase(customer_id)
    WHERE payment_state IN ('uncertain', 'processing');
-- Set when a paid prepaid team could not take an observation slot; the
-- prepaid worker retries until it does.
ALTER TABLE billing_funding_account ADD COLUMN prepaid_enrolment_due_at timestamptz;
CREATE INDEX billing_funding_account_prepaid_enrolment_due ON billing_funding_account(prepaid_enrolment_due_at) WHERE prepaid_enrolment_due_at IS NOT NULL;
