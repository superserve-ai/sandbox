-- Commercial terms are separate from provider execution and grant issuance.
CREATE TABLE billing_commercial_offer_version (
    offer_key text NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    rate_card_key text NOT NULL REFERENCES pricing_plan(key),
    plan_tier text NOT NULL CHECK (plan_tier = 'pro'),
    currency text NOT NULL CHECK (currency = 'usd'),
    term_months integer NOT NULL CHECK (term_months BETWEEN 1 AND 24),
    charge_amount_cents bigint NOT NULL CHECK (charge_amount_cents >= 0),
    charge_interval_months integer NOT NULL CHECK (charge_interval_months IN (1,12)),
    initial_fee_waived boolean NOT NULL,
    payment_requirement text NOT NULL CHECK (payment_requirement IN ('eligible_credit_or_verified_payment','verified_payment')),
    default_successor_family text NOT NULL CHECK (default_successor_family IN ('pro_annual','pro_monthly')),
    allowance_source text NOT NULL CHECK (allowance_source = 'usage_allowance'),
    monthly_allowance_cents bigint[] NOT NULL,
    rollover boolean NOT NULL DEFAULT false CHECK (NOT rollover),
    proration boolean NOT NULL DEFAULT false CHECK (NOT proration),
    published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (offer_key,version),
    CHECK (cardinality(monthly_allowance_cents)=term_months),
    CHECK (array_ndims(monthly_allowance_cents)=1 AND array_lower(monthly_allowance_cents,1)=1),
    CHECK (0 < ALL(monthly_allowance_cents) AND array_position(monthly_allowance_cents,NULL) IS NULL)
);

INSERT INTO billing_commercial_offer_version
(offer_key,version,rate_card_key,plan_tier,currency,term_months,charge_amount_cents,charge_interval_months,initial_fee_waived,payment_requirement,default_successor_family,allowance_source,monthly_allowance_cents)
VALUES ('yc_2026',1,'payg','pro','usd',12,1200000,12,true,'eligible_credit_or_verified_payment','pro_annual','usage_allowance',
 ARRAY[3000000,3000000,3000000,100000,100000,100000,100000,100000,100000,100000,100000,100000]),
 ('pro_annual',1,'payg','pro','usd',12,1200000,12,false,'verified_payment','pro_annual','usage_allowance',array_fill(100000::bigint,ARRAY[12]));

INSERT INTO feature_flag(key,enabled,description)
VALUES ('billing_commercial_offer_assignments_enabled',false,'Admit commercial offer assignments after checkout writer rollout and reconciliation.')
ON CONFLICT(key) DO NOTHING;

CREATE TABLE billing_commercial_checkout_attempt (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL REFERENCES team(id),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','dispatched','no_effect','customer_observed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    prepared_until timestamptz NOT NULL DEFAULT clock_timestamp()+interval '1 minute',
    dispatched_at timestamptz,
    customer_id text,
    CHECK (prepared_until > created_at),
    CHECK ((state='customer_observed') = (customer_id IS NOT NULL)),
    CHECK (state NOT IN ('prepared','no_effect') OR dispatched_at IS NULL),
    CHECK (state<>'dispatched' OR dispatched_at IS NOT NULL)
);
CREATE INDEX commercial_checkout_attempt_team ON billing_commercial_checkout_attempt(team_id,state);
ALTER TABLE billing_commercial_checkout_attempt ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_commercial_checkout_attempt FROM PUBLIC;

CREATE TABLE billing_commercial_offer_assignment (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL UNIQUE REFERENCES team(id),
    approval_id uuid NOT NULL UNIQUE,
    company_identity text NOT NULL CHECK (length(company_identity) BETWEEN 1 AND 500),
    home_region text NOT NULL,
    offer_key text NOT NULL,
    offer_version integer NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    rate_card_key text NOT NULL REFERENCES pricing_plan(key),
    rate_ids uuid[] NOT NULL CHECK (cardinality(rate_ids) > 0),
    pricing_at timestamptz NOT NULL,
    resource_rates jsonb NOT NULL CHECK (jsonb_typeof(resource_rates)='array'),
    request jsonb NOT NULL,
    assigned_by uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    reference text NOT NULL CHECK (length(reference) BETWEEN 1 AND 2000),
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (offer_key,offer_version) REFERENCES billing_commercial_offer_version(offer_key,version),
    UNIQUE (id,team_id),
    UNIQUE (team_id,idempotency_key)
);

CREATE TABLE billing_commercial_offer_activation (
    assignment_id uuid PRIMARY KEY,
    team_id uuid NOT NULL,
    contract_id uuid NOT NULL UNIQUE,
    merchant_account text NOT NULL CHECK (merchant_account LIKE 'acct_%'),
    live_mode boolean NOT NULL,
    anchor timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > anchor),
    materialized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (assignment_id,team_id) REFERENCES billing_commercial_offer_assignment(id,team_id),
    FOREIGN KEY (contract_id,team_id) REFERENCES billing_commercial_contract(id,team_id)
);

CREATE TABLE billing_commercial_offer_period (
    assignment_id uuid NOT NULL,
    team_id uuid NOT NULL,
    month_offset integer NOT NULL CHECK (month_offset BETWEEN 0 AND 23),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    amount_cents bigint NOT NULL CHECK (amount_cents > 0),
    allowance_source text NOT NULL CHECK (allowance_source = 'usage_allowance'),
    PRIMARY KEY (assignment_id,month_offset),
    FOREIGN KEY (assignment_id,team_id) REFERENCES billing_commercial_offer_assignment(id,team_id),
    CHECK (ends_at > starts_at AND expires_at = ends_at)
);

CREATE FUNCTION billing_commercial_offer_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'published commercial terms and assigned periods are immutable';
END $$;
CREATE TRIGGER commercial_offer_version_immutable BEFORE UPDATE OR DELETE ON billing_commercial_offer_version
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_immutable();
CREATE TRIGGER commercial_offer_assignment_immutable BEFORE UPDATE OR DELETE ON billing_commercial_offer_assignment
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_immutable();
CREATE TRIGGER commercial_offer_activation_immutable BEFORE UPDATE OR DELETE ON billing_commercial_offer_activation
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_immutable();
CREATE TRIGGER commercial_offer_period_immutable BEFORE UPDATE OR DELETE ON billing_commercial_offer_period
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_immutable();

CREATE FUNCTION billing_commercial_offer_assignment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v billing_commercial_offer_version; region text;
BEGIN
    SELECT home_region INTO STRICT region FROM team WHERE id=NEW.team_id FOR NO KEY UPDATE;
    PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
    IF NOT feature_enabled('billing_commercial_offer_assignments_enabled',NEW.team_id) THEN
        RAISE EXCEPTION 'commercial offer assignments are disabled';
    END IF;
    IF EXISTS(SELECT 1 FROM billing_commercial_checkout_attempt WHERE team_id=NEW.team_id
       AND (state IN ('dispatched','customer_observed') OR (state='prepared' AND prepared_until>clock_timestamp()))) THEN
        RAISE EXCEPTION 'ordinary checkout attempt reserves this team';
    END IF;
    SELECT * INTO STRICT v FROM billing_commercial_offer_version WHERE offer_key=NEW.offer_key AND version=NEW.offer_version;
    IF NEW.home_region <> region OR NEW.offer_key <> 'yc_2026'
       OR NEW.rate_card_key <> v.rate_card_key THEN
        RAISE EXCEPTION 'invalid offer assignment region, family or rate card';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER commercial_offer_assignment_guard BEFORE INSERT ON billing_commercial_offer_assignment
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_assignment_guard();

CREATE FUNCTION billing_commercial_offer_period_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a billing_commercial_offer_assignment; v billing_commercial_offer_version; activation billing_commercial_offer_activation;
BEGIN
    SELECT * INTO STRICT a FROM billing_commercial_offer_assignment WHERE id=NEW.assignment_id AND team_id=NEW.team_id;
    SELECT * INTO STRICT v FROM billing_commercial_offer_version WHERE offer_key=a.offer_key AND version=a.offer_version;
    SELECT * INTO STRICT activation FROM billing_commercial_offer_activation WHERE assignment_id=a.id;
    IF NEW.month_offset >= v.term_months
       OR NEW.starts_at <> billing_anniversary_boundary(activation.anchor,NEW.month_offset)
       OR NEW.ends_at <> billing_anniversary_boundary(activation.anchor,NEW.month_offset+1)
       OR NEW.amount_cents <> v.monthly_allowance_cents[NEW.month_offset+1]
       OR NEW.allowance_source <> v.allowance_source THEN
        RAISE EXCEPTION 'period differs from assigned commercial terms';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER commercial_offer_period_guard BEFORE INSERT ON billing_commercial_offer_period
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_period_guard();

CREATE FUNCTION billing_commercial_offer_activation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a billing_commercial_offer_assignment; v billing_commercial_offer_version; c billing_commercial_contract; billing_anchor timestamptz; resource_terms jsonb;
BEGIN
    IF NOT feature_enabled('billing_commercial_offer_assignments_enabled',NEW.team_id) THEN
        RAISE EXCEPTION 'commercial offer assignments are disabled';
    END IF;
    SELECT * INTO STRICT a FROM billing_commercial_offer_assignment WHERE id=NEW.assignment_id AND team_id=NEW.team_id;
    SELECT * INTO STRICT v FROM billing_commercial_offer_version WHERE offer_key=a.offer_key AND version=a.offer_version;
    PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR SHARE;
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id=NEW.contract_id AND team_id=NEW.team_id FOR UPDATE;
    SELECT commercial_billing_anchor INTO STRICT billing_anchor FROM team_billing_account
      WHERE team_id=NEW.team_id AND stripe_customer_id=c.customer_id AND stripe_subscription_id=c.subscription_id;
    IF c.status <> 'active' OR c.entitlement_cadence <> 'scheduled' OR c.entitlement_kind <> 'metered_usage'
       OR billing_anchor IS NULL OR NEW.anchor <> billing_anchor OR NEW.anchor <> c.entitlement_anchor
       OR NEW.anchor <> c.starts_at OR NEW.anchor <> date_trunc('second',NEW.anchor)
       OR NOT isfinite(NEW.anchor) OR NEW.ends_at IS DISTINCT FROM c.ends_at
       OR NEW.ends_at <> billing_anniversary_boundary(NEW.anchor,v.term_months)
       OR (SELECT array_agg(amount_cents ORDER BY month_offset) FROM billing_contract_entitlement_schedule WHERE contract_id=c.id) IS DISTINCT FROM v.monthly_allowance_cents THEN
        RAISE EXCEPTION 'activation differs from verified commercial contract and allowance schedule';
    END IF;
    IF NEW.anchor > clock_timestamp() OR NEW.ends_at <= clock_timestamp()
       OR c.created_at < a.assigned_at OR NOT v.initial_fee_waived OR v.charge_amount_cents<>1200000
       OR v.charge_interval_months<>12 OR v.term_months<>12 THEN
        RAISE EXCEPTION 'activation is not a current waived annual assignment';
    END IF;
    IF c.offer_key='yc_2026' AND c.charge_kind='subscription'
       AND c.charge_amount_cents=v.charge_amount_cents AND c.charge_interval_months=v.charge_interval_months THEN
        SELECT o.resource_terms INTO STRICT resource_terms
        FROM billing_yc_operation o JOIN billing_contract_waiver w ON w.id=o.id
        WHERE o.id=a.approval_id AND o.team_id=a.team_id AND o.contract_id=c.id AND o.state='active'
          AND o.revoked_at IS NULL AND o.customer_id=c.customer_id AND o.subscription_id=c.subscription_id
          AND o.starts_at=NEW.anchor AND o.ends_at=NEW.ends_at
          AND o.request->>'company_identity'=a.company_identity AND o.request->>'home_region'=a.home_region
          AND o.request->>'merchant_account'=NEW.merchant_account AND (o.request->>'live_mode')::boolean=NEW.live_mode
          AND w.team_id=a.team_id AND w.contract_id=c.id AND w.offer_key=a.offer_key AND w.offer_version=a.offer_version
          AND w.customer_id=c.customer_id AND w.subscription_id=c.subscription_id
          AND w.starts_at=NEW.anchor AND w.ends_at=NEW.ends_at AND w.collectible_base_cents=0
        FOR SHARE OF o;
    ELSIF c.offer_key='sponsored_usage' AND c.charge_kind='sponsored_entitlement' AND c.charge_amount_cents=0 THEN
        SELECT o.resource_terms INTO STRICT resource_terms
        FROM billing_sponsored_annual_authority annual JOIN billing_sponsored_operation o ON o.id=annual.sponsorship_id
        WHERE annual.team_id=a.team_id AND annual.contract_id=c.id AND annual.state='active'
          AND annual.customer_id=c.customer_id AND annual.subscription_id=c.subscription_id
          AND annual.starts_at=NEW.anchor AND annual.waiver_ends_at=NEW.ends_at AND annual.home_region=a.home_region
          AND annual.request->>'merchant_account'=NEW.merchant_account AND annual.live_mode=NEW.live_mode
          AND (annual.request->>'live_mode')::boolean=NEW.live_mode
          AND o.team_id=a.team_id AND o.contract_id=c.id AND o.state='active' AND o.revoked_at IS NULL
          AND o.customer_id=c.customer_id AND o.subscription_id=c.subscription_id
          AND o.anchor=NEW.anchor AND o.starts_at=NEW.anchor AND o.ends_at=NEW.ends_at
        FOR SHARE OF annual,o;
    ELSE
        RAISE EXCEPTION 'unsupported annual execution authority';
    END IF;
    IF jsonb_typeof(resource_terms->'ResourceTerms') IS DISTINCT FROM 'array'
       OR jsonb_array_length(resource_terms->'ResourceTerms')<>jsonb_array_length(a.resource_rates)
       OR EXISTS(SELECT 1 FROM jsonb_array_elements(a.resource_rates) rate
          WHERE rate->>'plan_key'<>a.rate_card_key OR rate->>'currency'<>'USD' OR rate->>'unit'<>'second'
          OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(resource_terms->'ResourceTerms') term
              WHERE term->>'ResourceKey'=rate->>'resource'
                AND (term->>'UnitAmountDecimal')::numeric=(rate->>'price_usd')::numeric*360000
                AND COALESCE(term->>'PriceID','')<>'' AND COALESCE(term->>'MeterID','')<>'' AND COALESCE(term->>'EventName','')<>'')) THEN
        RAISE EXCEPTION 'execution resource terms differ from accepted rate card';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER commercial_offer_activation_guard BEFORE INSERT ON billing_commercial_offer_activation
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_activation_guard();

CREATE FUNCTION billing_commercial_offer_materialize() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO billing_commercial_offer_period(assignment_id,team_id,month_offset,starts_at,ends_at,expires_at,amount_cents,allowance_source)
    SELECT NEW.assignment_id,NEW.team_id,n-1,billing_anniversary_boundary(NEW.anchor,n-1),
        billing_anniversary_boundary(NEW.anchor,n),billing_anniversary_boundary(NEW.anchor,n),
        v.monthly_allowance_cents[n],v.allowance_source
    FROM billing_commercial_offer_assignment a JOIN billing_commercial_offer_version v ON v.offer_key=a.offer_key AND v.version=a.offer_version
    CROSS JOIN LATERAL generate_series(1,v.term_months) n
    WHERE a.id=NEW.assignment_id;
    RETURN NEW;
END $$;
CREATE TRIGGER commercial_offer_materialize AFTER INSERT ON billing_commercial_offer_activation
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_materialize();

ALTER TABLE billing_commercial_offer_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_commercial_offer_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_commercial_offer_activation ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_commercial_offer_period ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_commercial_offer_version,billing_commercial_offer_assignment,billing_commercial_offer_activation,billing_commercial_offer_period FROM PUBLIC;
REVOKE ALL ON FUNCTION billing_commercial_offer_immutable(),billing_commercial_offer_assignment_guard(),billing_commercial_offer_period_guard(),billing_commercial_offer_materialize() FROM PUBLIC;

CREATE TABLE billing_commercial_offer_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL REFERENCES team(id),
    actor_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('preflight','assign','status')),
    assignment_id uuid REFERENCES billing_commercial_offer_assignment(id),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE billing_commercial_offer_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_commercial_offer_audit FROM PUBLIC;
CREATE TRIGGER commercial_offer_audit_immutable BEFORE UPDATE OR DELETE ON billing_commercial_offer_audit
FOR EACH ROW EXECUTE FUNCTION billing_commercial_offer_immutable();
REVOKE ALL ON FUNCTION billing_commercial_offer_activation_guard() FROM PUBLIC;

DO $$ DECLARE role_name text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
            EXECUTE format('REVOKE ALL ON billing_commercial_offer_version,billing_commercial_offer_assignment,billing_commercial_offer_activation,billing_commercial_offer_period,billing_commercial_offer_audit FROM %I',role_name);
            EXECUTE format('REVOKE ALL ON FUNCTION billing_commercial_offer_immutable(),billing_commercial_offer_assignment_guard(),billing_commercial_offer_period_guard(),billing_commercial_offer_materialize(),billing_commercial_offer_activation_guard() FROM %I',role_name);
        END IF;
    END LOOP;
END $$;
DO $$ DECLARE t text; BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        REVOKE ALL ON billing_commercial_offer_version,billing_commercial_offer_assignment,billing_commercial_offer_activation,billing_commercial_offer_period,billing_commercial_offer_audit FROM service_role;
        GRANT SELECT ON billing_commercial_offer_version TO service_role;
        CREATE POLICY commercial_offer_catalog_read ON billing_commercial_offer_version TO service_role USING(true);
        FOREACH t IN ARRAY ARRAY['billing_commercial_offer_assignment','billing_commercial_offer_activation','billing_commercial_offer_period','billing_commercial_offer_audit'] LOOP
            EXECUTE format('GRANT SELECT,INSERT ON %I TO service_role',t);
            EXECUTE format('CREATE POLICY commercial_offer_backend ON %I TO service_role USING(true) WITH CHECK(true)',t);
        END LOOP;
    END IF;
END $$;

-- Prepared leases can expire; dispatch evidence never expires or downgrades.
CREATE FUNCTION billing_commercial_checkout_attempt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'checkout attempt history is immutable'; END IF;
    PERFORM 1 FROM team WHERE id=NEW.team_id FOR NO KEY UPDATE;
    PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'prepared' OR NEW.dispatched_at IS NOT NULL OR NEW.customer_id IS NOT NULL
           OR NEW.created_at>clock_timestamp() OR NEW.prepared_until>clock_timestamp()+interval '1 minute' THEN
            RAISE EXCEPTION 'invalid prepared checkout attempt';
        END IF;
    ELSE
        IF (NEW.id,NEW.team_id,NEW.created_at,NEW.prepared_until) IS DISTINCT FROM
           (OLD.id,OLD.team_id,OLD.created_at,OLD.prepared_until) THEN
            RAISE EXCEPTION 'checkout attempt identity and deadline are immutable';
        END IF;
        IF NOT ((OLD.state='prepared' AND NEW.state IN ('dispatched','no_effect','customer_observed'))
             OR (OLD.state='dispatched' AND NEW.state='customer_observed')) THEN
            RAISE EXCEPTION 'invalid checkout attempt transition';
        END IF;
        IF NEW.state='dispatched' THEN
            IF OLD.prepared_until<=clock_timestamp() THEN RAISE EXCEPTION 'checkout preparation expired'; END IF;
            NEW.dispatched_at := clock_timestamp();
        ELSIF NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at THEN
            RAISE EXCEPTION 'checkout dispatch evidence is immutable';
        END IF;
    END IF;
    IF NEW.state IN ('prepared','dispatched','customer_observed') AND EXISTS(
        SELECT 1 FROM billing_commercial_offer_assignment WHERE team_id=NEW.team_id) THEN
        RAISE EXCEPTION 'commercial offer assignment reserves this team';
    END IF;
    IF NEW.state='customer_observed' AND NOT EXISTS(
        SELECT 1 FROM team_billing_account WHERE team_id=NEW.team_id AND stripe_customer_id=NEW.customer_id) THEN
        RAISE EXCEPTION 'checkout customer observation requires persisted identity';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER commercial_checkout_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_commercial_checkout_attempt
FOR EACH ROW EXECUTE FUNCTION billing_commercial_checkout_attempt_guard();
REVOKE ALL ON FUNCTION billing_commercial_checkout_attempt_guard() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_commercial_checkout_attempt FROM %I',r);
            EXECUTE format('REVOKE ALL ON FUNCTION billing_commercial_checkout_attempt_guard() FROM %I',r);
        END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT SELECT,INSERT,UPDATE ON billing_commercial_checkout_attempt TO service_role;
        CREATE POLICY commercial_checkout_backend ON billing_commercial_checkout_attempt TO service_role USING(true) WITH CHECK(true);
    END IF;
END $$;
