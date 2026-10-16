-- Operator approval and provider recovery are durable before billing is enabled.
CREATE TABLE billing_yc_operation (
 team_id uuid PRIMARY KEY REFERENCES team(id),
 id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 contract_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 renewal_contract_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 approved_by text NOT NULL CHECK (btrim(approved_by) <> ''),
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 evidence_reference text NOT NULL CHECK (btrim(evidence_reference) <> ''),
 request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object' AND COALESCE(btrim(request->>'company_identity'),'')<>''),
 resource_terms jsonb NOT NULL CHECK (jsonb_typeof(resource_terms) = 'object'),
 customer_id text,
 subscription_id text UNIQUE,
 first_invoice_id text, approved_grant_evidence jsonb,
 state text NOT NULL DEFAULT 'approved' CHECK (state IN ('approved','provider_pending','enrolling','active','renewal_pending','renewed','ended')),
 provider_attempt_at timestamptz, customer_attempt_at timestamptz,
 starts_at timestamptz, ends_at timestamptz,
 payment_method_ready boolean NOT NULL DEFAULT false,
 payment_method_checked_at timestamptz,
 revoked_at timestamptz, revoked_by text,
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_error text, invoice_cursor text,
 cancel_generation bigint NOT NULL DEFAULT 0, cancel_pending boolean NOT NULL DEFAULT false, cancel_requested_at bigint, cancel_boundary timestamptz,
 CHECK ((starts_at IS NULL AND ends_at IS NULL) OR (starts_at IS NOT NULL AND ends_at=billing_anniversary_boundary(starts_at,12))),
 CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX billing_yc_company_identity ON billing_yc_operation ((request->>'company_identity'));
CREATE INDEX billing_yc_operation_due ON billing_yc_operation(next_check_at,team_id) WHERE state <> 'ended';
CREATE TABLE billing_contract_waiver (
 id uuid PRIMARY KEY REFERENCES billing_yc_operation(id),
 team_id uuid NOT NULL,
 contract_id uuid NOT NULL UNIQUE,
 offer_key text NOT NULL CHECK (offer_key='yc_2026'),
 offer_version integer NOT NULL CHECK (offer_version=1),
 customer_id text NOT NULL,
 subscription_id text NOT NULL,
 starts_at timestamptz NOT NULL,
 ends_at timestamptz NOT NULL,
 collectible_base_cents bigint NOT NULL CHECK (collectible_base_cents=0),
 FOREIGN KEY(team_id,contract_id) REFERENCES billing_commercial_contract(team_id,id),
 UNIQUE(team_id,contract_id,id),
 CHECK(ends_at=billing_anniversary_boundary(starts_at,12))
);
ALTER TABLE billing_usage_entitlement ALTER COLUMN payment_id DROP NOT NULL;
ALTER TABLE billing_usage_entitlement ADD COLUMN waiver_id uuid;
ALTER TABLE billing_usage_entitlement ADD CONSTRAINT entitlement_one_authority CHECK ((payment_id IS NULL) <> (waiver_id IS NULL));
ALTER TABLE billing_usage_entitlement ADD FOREIGN KEY(team_id,contract_id,waiver_id) REFERENCES billing_contract_waiver(team_id,contract_id,id);

CREATE FUNCTION billing_yc_covered(c billing_commercial_contract, s timestamptz, e timestamptz, issuing boolean)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT c.offer_key='yc_2026' AND EXISTS(
 SELECT 1 FROM billing_contract_waiver w JOIN billing_yc_operation o ON o.id=w.id
 WHERE w.contract_id=c.id AND w.team_id=c.team_id AND w.customer_id=c.customer_id AND w.subscription_id=c.subscription_id
 AND w.starts_at<=s AND w.ends_at>=e AND o.contract_id=c.id AND o.team_id=c.team_id
 AND o.customer_id=c.customer_id AND o.subscription_id=c.subscription_id
 AND o.payment_method_ready AND o.state IN ('enrolling','active','renewal_pending')
 AND (NOT issuing OR (o.revoked_at IS NULL AND o.payment_method_checked_at>clock_timestamp()-interval '1 minute')));
$$;
CREATE FUNCTION guard_billing_yc_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='billing_contract_waiver' THEN
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'waiver history is immutable'; END IF;
  IF NOT EXISTS(SELECT 1 FROM billing_commercial_contract c JOIN billing_yc_operation o ON o.contract_id=c.id
   WHERE o.id=NEW.id AND c.id=NEW.contract_id AND c.team_id=NEW.team_id AND o.team_id=c.team_id
   AND c.offer_key=NEW.offer_key AND c.customer_id=NEW.customer_id AND c.subscription_id=NEW.subscription_id
   AND o.customer_id=c.customer_id AND o.subscription_id=c.subscription_id
   AND c.starts_at=NEW.starts_at AND c.ends_at=NEW.ends_at AND o.starts_at=NEW.starts_at AND o.ends_at=NEW.ends_at
   AND c.status='pending') THEN RAISE EXCEPTION 'waiver differs from approved contract'; END IF;
 ELSE
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'YC approval history is immutable'; END IF;
  IF TG_OP='UPDATE' AND ((NEW.id,NEW.team_id,NEW.contract_id,NEW.renewal_contract_id,NEW.approved_by,NEW.approved_at,NEW.evidence_reference,NEW.request,NEW.resource_terms,NEW.approved_grant_evidence)
   IS DISTINCT FROM (OLD.id,OLD.team_id,OLD.contract_id,OLD.renewal_contract_id,OLD.approved_by,OLD.approved_at,OLD.evidence_reference,OLD.request,OLD.resource_terms,OLD.approved_grant_evidence)
   OR (OLD.customer_id IS NOT NULL AND NEW.customer_id IS DISTINCT FROM OLD.customer_id)
   OR (OLD.subscription_id IS NOT NULL AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id)
   OR (OLD.first_invoice_id IS NOT NULL AND NEW.first_invoice_id IS DISTINCT FROM OLD.first_invoice_id)
   OR (OLD.customer_attempt_at IS NOT NULL AND NEW.customer_attempt_at IS DISTINCT FROM OLD.customer_attempt_at)
   OR (OLD.provider_attempt_at IS NOT NULL AND NEW.provider_attempt_at IS DISTINCT FROM OLD.provider_attempt_at)
   OR (OLD.starts_at IS NOT NULL AND (NEW.starts_at,NEW.ends_at) IS DISTINCT FROM (OLD.starts_at,OLD.ends_at))
   OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at,NEW.revoked_by) IS DISTINCT FROM (OLD.revoked_at,OLD.revoked_by)))
  THEN RAISE EXCEPTION 'YC approval identity and history are immutable'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_yc_operation_guard BEFORE UPDATE OR DELETE ON billing_yc_operation FOR EACH ROW EXECUTE FUNCTION guard_billing_yc_authority();
CREATE TRIGGER billing_contract_waiver_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_contract_waiver FOR EACH ROW EXECUTE FUNCTION guard_billing_yc_authority();

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
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NOT billing_yc_covered(NEW, NEW.starts_at, NEW.ends_at, false) AND NOT EXISTS (
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
 IF OLD.status='pending' AND NEW.status='active' AND NOT billing_yc_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT EXISTS(
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
  AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026') OR
    (c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
     AND (c.collection_evidence->>'period_start')::timestamptz=s
     AND (c.collection_evidence->>'period_end')::timestamptz=e))
  AND (billing_yc_covered(c,s,e,true) OR EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND p.service_period_start<=s AND p.service_period_end>=e
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)
   AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026') OR EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute'))))
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

CREATE OR REPLACE FUNCTION billing_validate_entitlement_adoption(v billing_usage_entitlement) RETURNS void LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; evidence jsonb := v.issuance_evidence;
BEGIN
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id = v.contract_id FOR UPDATE;
    IF c.status <> 'pending'
        OR NOT (billing_yc_covered(c,v.period_start,v.period_end,true) OR EXISTS (SELECT 1 FROM billing_contract_payment p WHERE p.id = v.payment_id AND p.contract_id = c.id
            AND p.service_period_start <= v.period_start AND p.service_period_end >= v.period_end))
        OR NOT EXISTS (SELECT 1 FROM team_billing_account a WHERE a.team_id = c.team_id
            AND a.stripe_customer_id = c.customer_id AND a.stripe_subscription_id = c.subscription_id)
        OR v.period_start > clock_timestamp() OR v.period_end <= clock_timestamp()
        OR v.adopted_at > clock_timestamp() OR v.adopted_at < clock_timestamp() - interval '1 minute'
        OR v.provider_created_at <> date_trunc('second', v.provider_created_at)
        OR v.provider_created_at > v.adopted_at OR v.provider_created_at < c.starts_at
        OR v.issued_at IS DISTINCT FROM v.provider_created_at
        OR (evidence->>'created')::bigint IS DISTINCT FROM extract(epoch FROM v.provider_created_at)::bigint
        OR evidence->>'id' IS DISTINCT FROM v.stripe_credit_grant_id
        OR evidence->>'customer' IS DISTINCT FROM c.customer_id
        OR evidence->>'category' IS DISTINCT FROM 'promotional'
        OR evidence #>> '{amount,type}' IS DISTINCT FROM 'monetary'
        OR evidence #>> '{amount,monetary,currency}' IS DISTINCT FROM v.currency
        OR (evidence #>> '{amount,monetary,value}')::bigint IS DISTINCT FROM v.amount_cents
        OR (evidence->>'available_balance_cents')::bigint IS DISTINCT FROM v.adopted_available_balance_cents
        OR (NOT (c.offer_key='yc_2026' AND EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.contract_id=c.id AND o.request->>'existing_grant_id'=v.stripe_credit_grant_id)) AND (
evidence #>> '{metadata,superserve_offer}' IS DISTINCT FROM c.offer_key
        OR evidence #>> '{metadata,superserve_contract_version}' IS DISTINCT FROM '1'
        OR evidence #>> '{metadata,superserve_object_role}' IS DISTINCT FROM 'monthly_usage_entitlement'
        OR evidence #>> '{metadata,superserve_team_id}' IS DISTINCT FROM v.team_id::text
        OR evidence #>> '{metadata,superserve_contract_id}' IS DISTINCT FROM v.contract_id::text
        OR evidence #>> '{metadata,superserve_entitlement}' IS DISTINCT FROM
            v.contract_id::text || ':usage:' || extract(epoch FROM v.period_start)::bigint::text || ':' || extract(epoch FROM v.period_end)::bigint::text
        OR (evidence #>> '{metadata,superserve_period_start}')::bigint IS DISTINCT FROM extract(epoch FROM v.period_start)::bigint
        OR (evidence #>> '{metadata,superserve_period_end}')::bigint IS DISTINCT FROM extract(epoch FROM v.period_end)::bigint))
        OR (evidence->>'effective_at')::bigint < extract(epoch FROM v.provider_invoice_start)::bigint + 1
        OR (evidence->>'effective_at')::bigint < extract(epoch FROM v.provider_created_at)::bigint
        OR (evidence->>'effective_at')::bigint > ceil(extract(epoch FROM v.adopted_at))::bigint
        OR evidence->>'effective_at' IS NULL
        OR (evidence->>'expires_at')::bigint IS DISTINCT FROM extract(epoch FROM v.provider_invoice_end)::bigint + 1
        OR jsonb_typeof(evidence #> '{applicability_config,scope,prices}') IS DISTINCT FROM 'array'
        OR jsonb_array_length(evidence #> '{applicability_config,scope,prices}') = 0
        OR evidence #> '{applicability_config,scope,price_type}' IS NOT NULL THEN
        RAISE EXCEPTION 'adopted grant does not match the entitlement';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM billing_invoice_calendar cal WHERE cal.team_id = v.team_id
        AND cal.period_start = v.period_start AND cal.period_end = v.period_end
        AND cal.customer_id = c.customer_id AND cal.subscription_id = c.subscription_id
        AND cal.invoice_start = v.provider_invoice_start AND cal.invoice_end = v.provider_invoice_end)
        OR v.provider_invoice_start <> date_trunc('second', v.provider_invoice_start)
        OR v.provider_invoice_end <> date_trunc('second', v.provider_invoice_end)
        OR v.provider_invoice_start >= v.period_end OR v.provider_invoice_end < v.period_end THEN
        RAISE EXCEPTION 'adopted grant differs from the authoritative calendar';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(evidence #> '{applicability_config,scope,prices}') price
        WHERE jsonb_typeof(price->'id') IS DISTINCT FROM 'string' OR btrim(price->>'id') = '' OR price->>'id' = c.base_price_id) THEN
        RAISE EXCEPTION 'adopted grant price scope is invalid';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION enqueue_billing_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND NEW.offer_key IN ('pro_monthly','pro_annual','yc_2026') THEN
  INSERT INTO billing_entitlement_work(contract_id) VALUES(NEW.id) ON CONFLICT(contract_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;

INSERT INTO plan_limits SELECT 'yc_2026',max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib FROM plan_limits WHERE offer_key='pro_annual';
-- An approved operator flow fences old binaries out of Checkout and promotions.
CREATE FUNCTION guard_yc_billing_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=NEW.team_id) THEN
  IF NEW.checkout_initializing_at IS NOT NULL OR NEW.stripe_activation_credit_reserved_at IS NOT NULL
   OR NEW.stripe_activation_credit_grant_id IS NOT NULL OR NEW.stripe_activation_credit_granted_at IS NOT NULL THEN
   RAISE EXCEPTION 'YC approval excludes self-service checkout and PAYG activation promotions';
  END IF;
  IF NEW.trial_ended_at IS DISTINCT FROM OLD.trial_ended_at AND NOT EXISTS(
   SELECT 1 FROM billing_commercial_contract c WHERE c.team_id=NEW.team_id AND c.status='active'
   AND billing_yc_covered(c,c.starts_at,c.ends_at,false)) THEN
   RAISE EXCEPTION 'YC trial completion requires usable covered access';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_billing_account_guard BEFORE UPDATE ON team_billing_account FOR EACH ROW EXECUTE FUNCTION guard_yc_billing_account();
DO $$ DECLARE t text; r text; BEGIN
 FOREACH t IN ARRAY ARRAY['billing_yc_operation','billing_contract_waiver'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',t);
  FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
   IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON %I FROM %I',t,r); END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
   EXECUTE format('GRANT SELECT,INSERT,UPDATE ON %I TO service_role',t);
   EXECUTE format('CREATE POLICY backend_access ON %I TO service_role USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION billing_yc_covered(billing_commercial_contract,timestamptz,timestamptz,boolean),guard_billing_yc_authority(),guard_yc_billing_account() FROM PUBLIC;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN GRANT EXECUTE ON FUNCTION billing_yc_covered(billing_commercial_contract,timestamptz,timestamptz,boolean) TO service_role; END IF; END $$;

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
WITH account AS (
 SELECT trial_ended_at,stripe_subscription_id,stripe_subscription_status FROM team_billing_account WHERE team_id=p_team_id
), grant_balance AS (
 SELECT COALESCE(SUM(remaining_usd) FILTER(WHERE expires_at IS NULL OR expires_at>now()),0)::numeric AS remaining_usd,
 COUNT(*)::int AS historical_count FROM team_credit_grant WHERE team_id=p_team_id AND reason='signup trial credit'
), denial AS (SELECT EXISTS(SELECT 1 FROM team_signup_trial_denial WHERE team_id=p_team_id) AS denied),
pending AS (SELECT EXISTS(SELECT 1 FROM team_signup_trial_provenance WHERE team_id=p_team_id AND completed_at IS NULL) AS pending)
SELECT CASE
 WHEN EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.team_id=p_team_id AND (NOT o.payment_method_ready OR o.payment_method_checked_at IS NULL OR o.payment_method_checked_at<now()-interval '5 minutes' OR o.state NOT IN ('active','renewed') OR (o.state='active' AND o.ends_at<=now()))) THEN false
 WHEN EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.team_id=p_team_id AND o.state='renewed' AND NOT EXISTS(
  SELECT 1 FROM billing_contract_payment p JOIN billing_pro_payment_verification v ON v.invoice_id=p.invoice_id
  WHERE p.team_id=o.team_id AND p.contract_id=o.renewal_contract_id AND p.service_period_start<=now() AND p.service_period_end>now() AND NOT v.review_required)) THEN false
 WHEN lower(coalesce(account.stripe_subscription_status,'')) IN ('active','trialing','past_due') THEN true
 WHEN account.trial_ended_at IS NOT NULL THEN false
 WHEN denial.denied OR pending.pending THEN false
 WHEN grant_balance.historical_count=0 AND account.stripe_subscription_id IS NULL THEN true
 ELSE grant_balance.remaining_usd>0 AND COALESCE(cache.eligible,true)
END FROM grant_balance CROSS JOIN denial CROSS JOIN pending LEFT JOIN account ON true
LEFT JOIN team_trial_eligibility_cache cache ON cache.team_id=p_team_id;
$$;

CREATE INDEX billing_yc_audit_contract ON billing_commercial_contract(id) WHERE status='active' AND offer_key='yc_2026';
