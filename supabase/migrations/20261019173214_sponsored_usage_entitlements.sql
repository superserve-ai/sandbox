-- Sponsorship is operator spending authority, independent of paid evidence.
CREATE TABLE billing_sponsored_operation (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL REFERENCES team(id),
 contract_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 resource_terms jsonb NOT NULL CHECK(jsonb_typeof(resource_terms)='object'),
 approved_by uuid NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 2000),
 reference text NOT NULL CHECK(length(btrim(reference)) BETWEEN 1 AND 2000),
 customer_id text, subscription_id text,
 customer_name text NOT NULL DEFAULT '',
 customer_attempt_at timestamptz, provider_attempt_at timestamptz,
 resolved_start timestamptz NOT NULL DEFAULT date_trunc('second',clock_timestamp()),
 anchor timestamptz, starts_at timestamptz, ends_at timestamptz,
 state text NOT NULL DEFAULT 'approved' CHECK(state IN ('approved','active','revoking','revoked','expired')),
 revoked_at timestamptz, revoked_by uuid,
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token uuid, lease_until timestamptz,
 last_error text,
 UNIQUE(team_id,idempotency_key), UNIQUE(team_id,contract_id,id),
 CHECK((revoked_at IS NULL)=(revoked_by IS NULL)),
 CHECK((starts_at IS NULL AND ends_at IS NULL AND anchor IS NULL) OR
 (starts_at IS NOT NULL AND ends_at>starts_at AND anchor IS NOT NULL))
);
CREATE UNIQUE INDEX sponsored_current ON billing_sponsored_operation(team_id) WHERE state NOT IN ('revoked','expired');
CREATE INDEX sponsored_due ON billing_sponsored_operation(next_check_at,id) WHERE state NOT IN ('revoked','expired');
CREATE INDEX sponsored_awaiting_activation ON billing_sponsored_operation(approved_at) WHERE state='approved';
ALTER TABLE billing_sponsored_operation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_sponsored_operation FROM PUBLIC;
ALTER TABLE billing_usage_entitlement ADD COLUMN sponsorship_id uuid;
ALTER TABLE billing_usage_entitlement DROP CONSTRAINT entitlement_one_authority;
ALTER TABLE billing_usage_entitlement ADD CONSTRAINT entitlement_one_authority
 CHECK(num_nonnulls(payment_id,waiver_id,sponsorship_id)=1);
ALTER TABLE billing_usage_entitlement ADD FOREIGN KEY(team_id,contract_id,sponsorship_id)
 REFERENCES billing_sponsored_operation(team_id,contract_id,id);
ALTER TABLE billing_commercial_contract DROP CONSTRAINT billing_commercial_contract_charge_kind_check;
ALTER TABLE billing_commercial_contract DROP CONSTRAINT billing_commercial_contract_charge_amount_cents_check;
ALTER TABLE billing_commercial_contract DROP CONSTRAINT billing_commercial_contract_base_price_id_check;
ALTER TABLE billing_commercial_contract ADD CHECK(
 (charge_kind='sponsored_entitlement' AND offer_key='sponsored_usage' AND charge_amount_cents=0 AND base_price_id='' AND entitlement_cadence='scheduled' AND ends_at IS NOT NULL)
 OR (charge_kind IN ('subscription','upfront') AND charge_amount_cents>0 AND btrim(base_price_id)<>'' AND offer_key<>'sponsored_usage'));

CREATE FUNCTION billing_sponsored_covered(c billing_commercial_contract,s timestamptz,e timestamptz,issuing boolean)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT c.charge_kind='sponsored_entitlement' AND EXISTS(
 SELECT 1 FROM billing_sponsored_operation o WHERE o.contract_id=c.id AND o.team_id=c.team_id
 AND o.customer_id=c.customer_id AND o.subscription_id=c.subscription_id
 AND o.anchor=c.entitlement_anchor AND o.starts_at=c.starts_at AND o.ends_at>=c.ends_at
 AND o.starts_at<=s AND o.ends_at>=e AND o.state IN ('approved','active','revoking','revoked','expired')
 AND (NOT issuing OR o.revoked_at IS NULL));
$$;

CREATE FUNCTION guard_sponsored_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'sponsorship audit history is immutable'; END IF;
 IF TG_OP='UPDATE' AND (
 (NEW.id,NEW.team_id,NEW.contract_id,NEW.idempotency_key,NEW.request,NEW.resource_terms,NEW.approved_by,NEW.approved_at,NEW.reason,NEW.reference,NEW.resolved_start,NEW.customer_name)
 IS DISTINCT FROM (OLD.id,OLD.team_id,OLD.contract_id,OLD.idempotency_key,OLD.request,OLD.resource_terms,OLD.approved_by,OLD.approved_at,OLD.reason,OLD.reference,OLD.resolved_start,OLD.customer_name)
 OR OLD.customer_id IS NOT NULL AND NEW.customer_id IS DISTINCT FROM OLD.customer_id
 OR OLD.subscription_id IS NOT NULL AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
 OR OLD.customer_attempt_at IS NOT NULL AND NEW.customer_attempt_at IS DISTINCT FROM OLD.customer_attempt_at
 OR OLD.provider_attempt_at IS NOT NULL AND NEW.provider_attempt_at IS DISTINCT FROM OLD.provider_attempt_at
 OR OLD.starts_at IS NOT NULL AND (NEW.anchor,NEW.starts_at,NEW.ends_at) IS DISTINCT FROM (OLD.anchor,OLD.starts_at,OLD.ends_at)
 OR OLD.revoked_at IS NOT NULL AND (NEW.revoked_at,NEW.revoked_by) IS DISTINCT FROM (OLD.revoked_at,OLD.revoked_by)
 OR OLD.state IN ('revoked','expired') AND NEW.state<>OLD.state) THEN
 RAISE EXCEPTION 'sponsorship authority and history are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sponsored_operation_guard BEFORE UPDATE OR DELETE ON billing_sponsored_operation
 FOR EACH ROW EXECUTE FUNCTION guard_sponsored_operation();

-- Serialize competing operator and self-service authorities on the account row.
CREATE FUNCTION fence_sponsored_billing() RETURNS trigger LANGUAGE plpgsql AS $$
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
   OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=t AND offer_key IN ('pro_monthly','pro_annual') AND state<>'selecting')
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
CREATE TRIGGER sponsored_authority_fence BEFORE INSERT ON billing_sponsored_operation FOR EACH ROW EXECUTE FUNCTION fence_sponsored_billing();
CREATE TRIGGER sponsored_contract_fence BEFORE INSERT ON billing_commercial_contract FOR EACH ROW EXECUTE FUNCTION fence_sponsored_billing();
CREATE TRIGGER sponsored_yc_fence BEFORE INSERT ON billing_yc_operation FOR EACH ROW EXECUTE FUNCTION fence_sponsored_billing();
CREATE TRIGGER sponsored_checkout_fence BEFORE UPDATE OF checkout_initializing_at,checkout_may_exist ON team_billing_account FOR EACH ROW EXECUTE FUNCTION fence_sponsored_billing();

CREATE OR REPLACE FUNCTION guard_billing_commercial_contract() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE months integer;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'commercial contract history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM team_billing_account WHERE team_id = NEW.team_id
            AND stripe_customer_id = NEW.customer_id AND stripe_subscription_id = NEW.subscription_id
            AND commercial_billing_anchor = NEW.entitlement_anchor FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'commercial contract billing association or anniversary differs'; END IF;
        IF NEW.starts_at IS DISTINCT FROM
            (SELECT period_start FROM billing_entitlement_period(NEW.entitlement_anchor, NEW.starts_at)) THEN
            RAISE EXCEPTION 'contract must start on its billing anniversary';
        END IF;
        IF EXISTS (SELECT 1 FROM billing_commercial_contract previous WHERE previous.subscription_id = NEW.subscription_id
            AND (previous.team_id, previous.customer_id) IS DISTINCT FROM (NEW.team_id, NEW.customer_id)) THEN
            RAISE EXCEPTION 'subscription history belongs to another billing account';
        END IF;
        IF NEW.charge_kind = 'upfront' AND (NEW.ends_at IS NULL OR NEW.ends_at IS DISTINCT FROM
            billing_anniversary_boundary(NEW.entitlement_anchor, NEW.charge_interval_months +
                (extract(year FROM NEW.starts_at AT TIME ZONE 'UTC')::integer - extract(year FROM NEW.entitlement_anchor AT TIME ZONE 'UTC')::integer) * 12
                + extract(month FROM NEW.starts_at AT TIME ZONE 'UTC')::integer - extract(month FROM NEW.entitlement_anchor AT TIME ZONE 'UTC')::integer)) THEN
            RAISE EXCEPTION 'upfront payment requires a bounded service term';
        END IF;
        IF NEW.status <> 'pending' OR NEW.revision <> 0 OR NEW.collection_checked_at IS NOT NULL THEN
            RAISE EXCEPTION 'commercial contracts must begin pending';
        END IF;
    ELSE
        IF (to_jsonb(NEW) - ARRAY['status','ends_at','collection_has_overdue_balance','collection_checked_at','collection_valid_until','collection_evidence','revision'])
            IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status','ends_at','collection_has_overdue_balance','collection_checked_at','collection_valid_until','collection_evidence','revision']) THEN
            RAISE EXCEPTION 'commercial terms are immutable';
        END IF;
        IF NEW.revision <> OLD.revision + 1 OR OLD.status = 'ended'
            OR (OLD.status = 'active' AND NEW.status = 'pending') THEN
            RAISE EXCEPTION 'invalid commercial contract transition';
        END IF;
        IF (NEW.collection_has_overdue_balance, NEW.collection_checked_at, NEW.collection_valid_until, NEW.collection_evidence)
            IS DISTINCT FROM (OLD.collection_has_overdue_balance, OLD.collection_checked_at, OLD.collection_valid_until, OLD.collection_evidence)
            AND (NEW.collection_checked_at IS NULL OR NEW.collection_checked_at > clock_timestamp()
                OR NEW.collection_checked_at <= COALESCE(OLD.collection_checked_at, '-infinity'::timestamptz)) THEN
            RAISE EXCEPTION 'collection observation must advance';
        END IF;
        IF OLD.ends_at IS NOT NULL AND (NEW.ends_at IS NULL OR NEW.ends_at > OLD.ends_at) THEN
            RAISE EXCEPTION 'contract end cannot be extended';
        END IF;
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NEW.entitlement_cadence = 'scheduled' THEN
            months := (extract(year FROM NEW.ends_at AT TIME ZONE 'UTC')::integer - extract(year FROM NEW.starts_at AT TIME ZONE 'UTC')::integer) * 12
                + extract(month FROM NEW.ends_at AT TIME ZONE 'UTC')::integer - extract(month FROM NEW.starts_at AT TIME ZONE 'UTC')::integer;
            IF NEW.ends_at IS NULL OR months <= 0 OR (SELECT count(*) FROM billing_contract_entitlement_schedule WHERE contract_id = NEW.id) <> months
                OR EXISTS (SELECT 1 FROM billing_contract_entitlement_schedule WHERE contract_id = NEW.id AND month_offset >= months) THEN
                RAISE EXCEPTION 'scheduled contract requires every monthly amount before activation';
            END IF;
        END IF;
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NOT billing_sponsored_covered(NEW, NEW.starts_at, NEW.ends_at, false) AND NOT billing_yc_covered(NEW, NEW.starts_at, NEW.ends_at, false) AND NOT EXISTS (
            SELECT 1 FROM billing_contract_payment p WHERE p.contract_id = NEW.id
                AND p.service_period_start <= clock_timestamp() AND p.service_period_end > clock_timestamp()) THEN
            RAISE EXCEPTION 'activation requires verified base payment coverage';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION guard_pro_payment_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='pending' AND NEW.status='active' AND NOT billing_sponsored_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT billing_yc_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT EXISTS(
  SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=NEW.id
   AND p.service_period_start<=clock_timestamp() AND p.service_period_end>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required))
 THEN RAISE EXCEPTION 'activation requires an unquestioned base payment'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.status='active' AND c.collection_has_overdue_balance IS FALSE
  AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until>clock_timestamp() AND c.starts_at<=s
  AND (c.ends_at IS NULL OR c.ends_at>=e)
  AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026','sponsored_usage') OR
    (c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
     AND (c.collection_evidence->>'period_start')::timestamptz=s
     AND (c.collection_evidence->>'period_end')::timestamptz=e))
  AND (billing_sponsored_covered(c,s,e,true) OR billing_yc_covered(c,s,e,true) OR EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND p.service_period_start<=s AND p.service_period_end>=e
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)
   AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026','sponsored_usage') OR EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute'))))
  AND EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=c.team_id
   AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id);
$$;

CREATE OR REPLACE FUNCTION guard_billing_usage_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; p billing_contract_payment; s timestamptz; e timestamptz; amount bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'entitlement history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR UPDATE;
        IF NEW.payment_id IS NOT NULL THEN
            SELECT * INTO STRICT p FROM billing_contract_payment WHERE team_id=NEW.team_id AND contract_id=NEW.contract_id AND id=NEW.payment_id;
        ELSIF NEW.sponsorship_id IS NOT NULL THEN
            IF NOT billing_sponsored_covered(c,NEW.period_start,NEW.period_end,true) THEN RAISE EXCEPTION 'entitlement lacks sponsored authority'; END IF;
        ELSIF NOT billing_yc_covered(c,NEW.period_start,NEW.period_end,true) THEN
            RAISE EXCEPTION 'entitlement lacks current waiver authority';
        END IF;
        SELECT period_start, period_end, amount_cents INTO s, e, amount FROM billing_contract_entitlement(c, clock_timestamp());
        IF (NEW.kind, NEW.amount_cents, NEW.currency)
            IS DISTINCT FROM (c.entitlement_kind, amount, c.currency)
            OR (NEW.payment_id IS NOT NULL AND (p.service_period_start > NEW.period_start OR p.service_period_end < NEW.period_end)) THEN
            RAISE EXCEPTION 'entitlement lacks eligible paid contract';
        END IF;
        IF s IS NULL OR (NEW.period_start, NEW.period_end) IS DISTINCT FROM (s, e) THEN
            RAISE EXCEPTION 'only the current anniversary period can be claimed';
        END IF;
        IF NEW.issuance_source = 'adopted' AND NEW.state = 'issued' THEN
            PERFORM billing_validate_entitlement_adoption(NEW);
        ELSIF NEW.issuance_source <> 'created' OR NEW.state <> 'pending' OR NOT billing_contract_eligible(c, NEW.period_start, NEW.period_end) THEN
            RAISE EXCEPTION 'entitlement lacks eligible paid contract';
        END IF;
    ELSE
        IF (to_jsonb(NEW) - ARRAY['state','first_attempt_at','request_payload','provider_invoice_start','provider_invoice_end','stripe_credit_grant_id','issuance_evidence','issued_at','issuance_source','provider_created_at','adopted_at','adopted_available_balance_cents'])
            IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','first_attempt_at','request_payload','provider_invoice_start','provider_invoice_end','stripe_credit_grant_id','issuance_evidence','issued_at','issuance_source','provider_created_at','adopted_at','adopted_available_balance_cents']) THEN
            RAISE EXCEPTION 'entitlement terms and identity are immutable';
        END IF;
        IF OLD.state = 'issued' THEN RAISE EXCEPTION 'issued entitlement is immutable'; END IF;
        IF NEW.issuance_source IS DISTINCT FROM OLD.issuance_source THEN
            RAISE EXCEPTION 'adoption cannot replace an issuance intent';
        END IF;
        IF OLD.state = 'uncertain' THEN
            IF NEW.state NOT IN ('uncertain','issued') OR
                (NEW.first_attempt_at, NEW.request_payload, NEW.provider_invoice_start, NEW.provider_invoice_end)
                IS DISTINCT FROM (OLD.first_attempt_at, OLD.request_payload, OLD.provider_invoice_start, OLD.provider_invoice_end) THEN
                RAISE EXCEPTION 'possible Stripe success must retain its original request';
            END IF;
        ELSIF NEW.state <> 'uncertain' THEN
            RAISE EXCEPTION 'issuance must record a possible external write before confirmation';
        ELSE
            SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id = NEW.contract_id FOR UPDATE;
            IF NOT billing_contract_eligible(c, NEW.period_start, NEW.period_end)
                OR clock_timestamp() < NEW.period_start OR clock_timestamp() >= NEW.period_end
                OR NEW.first_attempt_at > clock_timestamp() OR NEW.first_attempt_at < clock_timestamp() - interval '1 minute' THEN
                RAISE EXCEPTION 'entitlement is not eligible for issuance';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM billing_invoice_calendar cal WHERE cal.team_id = NEW.team_id
                AND cal.period_start = NEW.period_start AND cal.period_end = NEW.period_end
                AND cal.customer_id = c.customer_id AND cal.subscription_id = c.subscription_id
                AND cal.invoice_start = NEW.provider_invoice_start AND cal.invoice_end = NEW.provider_invoice_end) THEN
                RAISE EXCEPTION 'grant invoice boundaries differ from the authoritative calendar';
            END IF;
            IF NEW.provider_invoice_start <> date_trunc('second', NEW.provider_invoice_start)
                OR NEW.provider_invoice_end <> date_trunc('second', NEW.provider_invoice_end)
                OR NEW.provider_invoice_start >= NEW.period_end OR NEW.provider_invoice_end < NEW.period_end
                OR (NEW.request_payload->>'customer') IS DISTINCT FROM c.customer_id
                OR (NEW.request_payload->>'category') IS DISTINCT FROM 'promotional'
                OR (NEW.request_payload #>> '{amount,type}') IS DISTINCT FROM 'monetary'
                OR (NEW.request_payload #>> '{amount,monetary,currency}') IS DISTINCT FROM NEW.currency
                OR (NEW.request_payload #>> '{amount,monetary,value}')::bigint IS DISTINCT FROM NEW.amount_cents
                OR (NEW.request_payload #>> '{metadata,entitlement_id}') IS DISTINCT FROM NEW.id::text
                OR (NEW.request_payload->>'expires_at')::bigint IS DISTINCT FROM extract(epoch FROM NEW.provider_invoice_end)::bigint + 1
                OR (NEW.request_payload ? 'effective_at' AND (NEW.request_payload->>'effective_at')::bigint IS DISTINCT FROM greatest(ceil(extract(epoch FROM NEW.first_attempt_at))::bigint, extract(epoch FROM NEW.provider_invoice_start)::bigint + 1))
                OR (NOT NEW.request_payload ? 'effective_at' AND (NEW.first_attempt_at < NEW.provider_invoice_start + interval '1 second' OR NEW.first_attempt_at >= NEW.provider_invoice_end))
                OR (NEW.request_payload->>'effective_at')::bigint > extract(epoch FROM NEW.provider_invoice_end)::bigint
                OR jsonb_typeof(NEW.request_payload #> '{applicability_config,scope,prices}') IS DISTINCT FROM 'array'
                OR jsonb_array_length(NEW.request_payload #> '{applicability_config,scope,prices}') = 0
                OR NEW.request_payload #> '{applicability_config,scope,price_type}' IS NOT NULL THEN
                RAISE EXCEPTION 'grant request does not match entitlement or mapped invoice';
            END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.request_payload #> '{applicability_config,scope,prices}') price
                WHERE jsonb_typeof(price->'id') IS DISTINCT FROM 'string' OR btrim(price->>'id') = '' OR price->>'id' = c.base_price_id) THEN
                RAISE EXCEPTION 'grant price scope is invalid';
            END IF;
        END IF;
        IF NEW.state = 'issued' AND (
            NEW.issuance_evidence->>'id' IS DISTINCT FROM NEW.stripe_credit_grant_id
            OR COALESCE((NEW.issuance_evidence->>'voided_at')::bigint,0) <> 0
            OR NEW.issuance_evidence->'customer' IS DISTINCT FROM NEW.request_payload->'customer'
            OR NEW.issuance_evidence->'amount' IS DISTINCT FROM NEW.request_payload->'amount'
            OR NEW.issuance_evidence->'category' IS DISTINCT FROM NEW.request_payload->'category'
            OR (NEW.request_payload ? 'effective_at' AND NEW.issuance_evidence->'effective_at' IS DISTINCT FROM NEW.request_payload->'effective_at')
            OR (NOT NEW.request_payload ? 'effective_at' AND (
                (NEW.issuance_evidence->>'effective_at')::bigint IS NULL
                OR (NEW.issuance_evidence->>'effective_at')::bigint < floor(extract(epoch FROM NEW.first_attempt_at))::bigint
                OR (NEW.issuance_evidence->>'effective_at')::bigint <= extract(epoch FROM NEW.provider_invoice_start)::bigint
                OR (NEW.issuance_evidence->>'effective_at')::bigint > extract(epoch FROM NEW.provider_invoice_end)::bigint
                OR (NEW.issuance_evidence->>'effective_at')::bigint > extract(epoch FROM clock_timestamp())::bigint))
            OR (NEW.request_payload ? 'priority' AND NEW.issuance_evidence->'priority' IS DISTINCT FROM NEW.request_payload->'priority')
            OR NEW.issuance_evidence->'expires_at' IS DISTINCT FROM NEW.request_payload->'expires_at'
            OR NEW.issuance_evidence->'applicability_config' IS DISTINCT FROM NEW.request_payload->'applicability_config'
            OR NEW.issuance_evidence #>> '{metadata,entitlement_id}' IS DISTINCT FROM NEW.id::text
            OR NEW.issued_at > clock_timestamp() OR NEW.issued_at < NEW.first_attempt_at) THEN
            RAISE EXCEPTION 'grant confirmation does not match the frozen request';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER funding_sponsored_grant AFTER INSERT OR UPDATE ON billing_usage_entitlement
 FOR EACH ROW EXECUTE FUNCTION schedule_billing_funding();
DO $$ DECLARE r text; f regprocedure; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_sponsored_operation FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON billing_sponsored_operation TO service_role;
    CREATE POLICY sponsored_backend ON billing_sponsored_operation TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['billing_sponsored_covered(billing_commercial_contract,timestamptz,timestamptz,boolean)'::regprocedure,'guard_sponsored_operation()'::regprocedure,'fence_sponsored_billing()'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f); END IF;
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION billing_contract_apply_plan_limits() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.charge_kind<>'sponsored_entitlement' THEN
  PERFORM apply_plan_limits(NEW.team_id,CASE NEW.status WHEN 'active' THEN NEW.offer_key ELSE 'free' END);
 END IF;
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE
 WHEN EXISTS(SELECT 1 FROM abuse_restrictions r WHERE r.subject_team_id=p_team_id AND r.released_at IS NULL
 AND (r.expires_at IS NULL OR r.expires_at>now()) AND r.action IN ('create','resume')) THEN false
 WHEN qm_team_managed_billing(p_team_id) THEN true
 WHEN NOT COALESCE(f.enforce,false) THEN team_sandbox_billing_eligible_legacy(p_team_id)
 WHEN f.observed_generation IS DISTINCT FROM f.generation
 OR (f.customer_id,f.subscription_id) IS DISTINCT FROM (a.stripe_customer_id,a.stripe_subscription_id) THEN false
 WHEN f.credit_usd>0 AND f.credit_valid_until>now() AND (
 NOT EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=p_team_id AND state NOT IN ('revoked','expired'))
 OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.team_id=p_team_id AND e.sponsorship_id IS NOT NULL AND e.state='issued' AND e.period_start<=now() AND e.period_end>now())) THEN true
 ELSE COALESCE(f.payment_method_ready AND f.collection_ready AND f.provider_valid_until>now()
 AND (billing_funding_fingerprint(p_team_id)='clear' OR f.cash_collected),false) END
 FROM (SELECT p_team_id team_id) t LEFT JOIN billing_funding_account f USING(team_id)
 LEFT JOIN team_billing_account a USING(team_id);
$$;

CREATE OR REPLACE FUNCTION enqueue_billing_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND NEW.offer_key IN ('pro_monthly','pro_annual','yc_2026','sponsored_usage') AND (TG_OP='INSERT' OR OLD.status IS DISTINCT FROM NEW.status) THEN
  INSERT INTO billing_entitlement_work(contract_id) VALUES(NEW.id)
  ON CONFLICT(contract_id) DO UPDATE SET next_check_at=least(billing_entitlement_work.next_check_at,clock_timestamp()),wake_generation=billing_entitlement_work.wake_generation+1;
 END IF;
 RETURN NEW;
END $$;

-- A delayed checkout response cannot overwrite established sponsored identity.
CREATE FUNCTION guard_sponsored_customer_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.stripe_customer_id IS NOT NULL AND NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id
 AND EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=NEW.team_id) THEN
  RAISE EXCEPTION 'sponsored billing customer cannot be replaced';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sponsored_customer_binding BEFORE UPDATE OF stripe_customer_id ON team_billing_account
 FOR EACH ROW EXECUTE FUNCTION guard_sponsored_customer_binding();
REVOKE ALL ON FUNCTION guard_sponsored_customer_binding() FROM PUBLIC;
