-- Durable scheduling is separate from the immutable entitlement identity.
CREATE TABLE billing_entitlement_work (
 contract_id uuid PRIMARY KEY REFERENCES billing_commercial_contract(id),
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token uuid, lease_until timestamptz,
 failures integer NOT NULL DEFAULT 0, problem_since timestamptz, alerted_at timestamptz,
 last_error text,
 inventory_head text, inventory_cursor text, inventory_new_head text,
 inventory_checked_at timestamptz
);
CREATE INDEX billing_entitlement_work_due ON billing_entitlement_work(next_check_at,contract_id);
CREATE INDEX billing_entitlement_work_fresh ON billing_entitlement_work(next_check_at,contract_id) WHERE failures=0;
CREATE INDEX billing_entitlement_work_retry ON billing_entitlement_work(next_check_at,contract_id) WHERE failures>0;
CREATE INDEX billing_entitlement_unresolved ON billing_usage_entitlement(contract_id,period_start) WHERE state <> 'issued';
CREATE INDEX billing_entitlement_audit_contract ON billing_commercial_contract(id) WHERE status='active' AND offer_key IN ('pro_monthly','pro_annual');
CREATE TABLE billing_entitlement_withheld (
 contract_id uuid NOT NULL REFERENCES billing_commercial_contract(id),
 period_start timestamptz NOT NULL, period_end timestamptz NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(), evidence jsonb NOT NULL, platform_failure_at timestamptz,
 PRIMARY KEY(contract_id,period_start), CHECK(period_end>period_start)
);
CREATE TABLE billing_entitlement_debt (
 contract_id uuid NOT NULL REFERENCES billing_commercial_contract(id),
 period_start timestamptz NOT NULL, invoice_id text NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(contract_id,period_start,invoice_id)
);
CREATE TABLE billing_invoice_credit_scan (
 customer_id text NOT NULL, invoice_end bigint NOT NULL,
 cursor text NOT NULL DEFAULT '', credits jsonb NOT NULL DEFAULT '[]',
 ledger_head text NOT NULL, inventory_head text NOT NULL,
 PRIMARY KEY(customer_id,invoice_end)
);
CREATE TABLE billing_invoice_discovery (
 customer_id text NOT NULL, subscription_id text NOT NULL,
 period_start bigint NOT NULL, period_end bigint NOT NULL,
 cursor text NOT NULL DEFAULT '', match_id text NOT NULL DEFAULT '',
 PRIMARY KEY(customer_id,subscription_id,period_start,period_end)
);
-- A resumable inventory index avoids re-reading every historical grant at each close.
CREATE TABLE billing_provider_credit (
 customer_id text NOT NULL, grant_id text NOT NULL, evidence jsonb NOT NULL,
 effective_at bigint NOT NULL, expires_at bigint NOT NULL,
 entitlement_id text, observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(customer_id,grant_id)
);
CREATE INDEX billing_provider_credit_period ON billing_provider_credit(customer_id,expires_at,effective_at);
CREATE INDEX billing_provider_credit_entitlement ON billing_provider_credit(customer_id,entitlement_id) WHERE entitlement_id IS NOT NULL;
CREATE FUNCTION enqueue_billing_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND NEW.offer_key IN ('pro_monthly','pro_annual') THEN
  INSERT INTO billing_entitlement_work(contract_id) VALUES(NEW.id) ON CONFLICT(contract_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_entitlement_enqueue AFTER INSERT OR UPDATE OF status ON billing_commercial_contract FOR EACH ROW EXECUTE FUNCTION enqueue_billing_entitlement();
INSERT INTO billing_entitlement_work(contract_id) SELECT id FROM billing_commercial_contract WHERE status='active' AND offer_key IN ('pro_monthly','pro_annual');

-- Retain the column name for old binaries, but only the new complete invoice
-- observation may authorize a Pro grant. Old overdue observations fail closed.
COMMENT ON COLUMN billing_commercial_contract.collection_has_overdue_balance IS 'For Pro: any unpaid finalized invoice, regardless of due date; evidence must use finalized_invoice_gate_v1.';
CREATE OR REPLACE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.status='active' AND c.collection_has_overdue_balance IS FALSE
  AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until>clock_timestamp() AND c.starts_at<=s
  AND (c.ends_at IS NULL OR c.ends_at>=e)
  AND (c.offer_key NOT IN ('pro_monthly','pro_annual') OR
    (c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
     AND (c.collection_evidence->>'period_start')::timestamptz=s
     AND (c.collection_evidence->>'period_end')::timestamptz=e))
  AND EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND p.service_period_start<=s AND p.service_period_end>=e
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)
   AND (c.offer_key NOT IN ('pro_monthly','pro_annual') OR EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute')))
  AND EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=c.team_id
   AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id);
$$;

CREATE OR REPLACE FUNCTION guard_billing_usage_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; p billing_contract_payment; s timestamptz; e timestamptz; amount bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'entitlement history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR UPDATE;
        SELECT * INTO STRICT p FROM billing_contract_payment WHERE team_id = NEW.team_id AND contract_id = NEW.contract_id AND id = NEW.payment_id;
        SELECT period_start, period_end, amount_cents INTO s, e, amount FROM billing_contract_entitlement(c, clock_timestamp());
        IF (NEW.kind, NEW.amount_cents, NEW.currency)
            IS DISTINCT FROM (c.entitlement_kind, amount, c.currency)
            OR p.service_period_start > NEW.period_start OR p.service_period_end < NEW.period_end THEN
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

DO $$ DECLARE t text; r text; BEGIN
 FOREACH t IN ARRAY ARRAY['billing_entitlement_work','billing_entitlement_withheld','billing_entitlement_debt','billing_invoice_discovery','billing_invoice_credit_scan','billing_provider_credit'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',t);
  FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
   IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON %I FROM %I',t,r); END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON %I TO service_role',t); EXECUTE format('CREATE POLICY backend_access ON %I TO service_role USING(true) WITH CHECK(true)',t); END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION enqueue_billing_entitlement() FROM PUBLIC;
