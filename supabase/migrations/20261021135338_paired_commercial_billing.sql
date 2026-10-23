-- Requires immutable commercial offer assignments. Acceptance and provisioning
-- journals are separate authorities and are deliberately not foreign keys here.
CREATE TABLE billing_contract_provider_binding (
 contract_id uuid PRIMARY KEY REFERENCES billing_commercial_contract(id),
 team_id uuid NOT NULL REFERENCES team(id),
 assignment_id uuid NOT NULL REFERENCES billing_commercial_offer_assignment(id),
 acceptance_id uuid NOT NULL,
 approval_semantic_revision bigint NOT NULL CHECK(approval_semantic_revision>=0),
 merchant text NOT NULL CHECK(merchant LIKE 'acct_%'),
 live_mode boolean NOT NULL,
 api_version text NOT NULL CHECK(btrim(api_version)<>''),
 terms_digest text NOT NULL CHECK(terms_digest ~ '^[0-9a-f]{64}$'),
 provider_terms_digest text NOT NULL CHECK(provider_terms_digest ~ '^[0-9a-f]{64}$'),
 customer_id text NOT NULL CHECK(customer_id LIKE 'cus_%'),
 usage_subscription_id text NOT NULL CHECK(usage_subscription_id LIKE 'sub_%'),
 fee_subscription_id text NOT NULL CHECK(fee_subscription_id LIKE 'sub_%'),
 fee_item_id text NOT NULL CHECK(fee_item_id LIKE 'si_%'),
 anchor timestamptz NOT NULL,
 fee_anchor timestamptz NOT NULL,
 starts_at timestamptz NOT NULL,
 ends_at timestamptz,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object'),
 verified_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(team_id,contract_id),
 CHECK(usage_subscription_id<>fee_subscription_id),
 CHECK(isfinite(fee_anchor) AND fee_anchor=date_trunc('second',fee_anchor) AND fee_anchor>=anchor AND fee_anchor<=starts_at),
 CHECK(isfinite(anchor) AND isfinite(starts_at) AND anchor=date_trunc('second',anchor) AND starts_at>=anchor AND (ends_at IS NULL OR isfinite(ends_at) AND ends_at>starts_at))
);
CREATE INDEX billing_provider_pair_usage ON billing_contract_provider_binding(team_id,usage_subscription_id,starts_at DESC);
CREATE INDEX billing_provider_pair_fee ON billing_contract_provider_binding(merchant,live_mode,fee_subscription_id);
ALTER TABLE billing_contract_provider_binding ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_contract_provider_binding FROM PUBLIC;

CREATE FUNCTION guard_billing_contract_provider_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; a billing_commercial_offer_assignment; t jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'provider binding history is immutable'; END IF;
 PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
 SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id=NEW.contract_id AND team_id=NEW.team_id FOR UPDATE;
 SELECT * INTO STRICT a FROM billing_commercial_offer_assignment WHERE id=NEW.assignment_id AND team_id=NEW.team_id;
 t:=NEW.binding->'terms';
 IF c.status<>'pending' OR c.charge_kind<>'subscription'
  OR (c.customer_id,c.subscription_id,c.entitlement_anchor,c.starts_at,c.ends_at)
     IS DISTINCT FROM (NEW.customer_id,NEW.usage_subscription_id,NEW.anchor,NEW.starts_at,NEW.ends_at)
  OR (c.base_price_id,c.charge_amount_cents,c.charge_interval_months,c.currency)
     IS DISTINCT FROM (t->>'fee_price_id',(t->>'fee_amount_cents')::bigint,(t->>'fee_months')::integer,t->>'currency')
  OR NEW.verified_at>clock_timestamp() OR NEW.verified_at<clock_timestamp()-interval '1 minute'
  OR NEW.starts_at IS DISTINCT FROM (SELECT period_start FROM billing_entitlement_period(NEW.anchor,NEW.starts_at))
  OR NEW.starts_at IS DISTINCT FROM (SELECT period_start FROM billing_entitlement_period(NEW.fee_anchor,NEW.starts_at)) THEN
  RAISE EXCEPTION 'provider binding differs from pending commercial terms';
 END IF;
 IF (NEW.binding->>'contract_id')::uuid IS DISTINCT FROM NEW.contract_id
  OR NEW.binding->'identity' IS DISTINCT FROM jsonb_build_object(
   'operation_id',NEW.binding->'identity'->>'operation_id','team_id',NEW.team_id,'assignment_id',NEW.assignment_id,
   'acceptance_id',NEW.acceptance_id,'approval_semantic_revision',NEW.approval_semantic_revision,
   'terms_digest',NEW.terms_digest,'provider_terms_digest',NEW.provider_terms_digest,
   'merchant',NEW.merchant,'live',NEW.live_mode,'api_version',NEW.api_version)
  OR (NEW.binding->>'customer_id',NEW.binding->>'usage_subscription_id',NEW.binding->>'fee_subscription_id',NEW.binding->>'fee_item_id')
   IS DISTINCT FROM (NEW.customer_id,NEW.usage_subscription_id,NEW.fee_subscription_id,NEW.fee_item_id)
  OR ((NEW.binding->>'anchor')::timestamptz,(NEW.binding->>'fee_anchor')::timestamptz,(NEW.binding->>'starts_at')::timestamptz,(NEW.binding->>'ends_at')::timestamptz)
   IS DISTINCT FROM (NEW.anchor,NEW.fee_anchor,NEW.starts_at,NEW.ends_at) THEN
  RAISE EXCEPTION 'provider binding projection differs from immutable evidence';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=NEW.team_id AND stripe_customer_id=NEW.customer_id
  AND stripe_subscription_id=NEW.usage_subscription_id AND commercial_billing_anchor=NEW.anchor) THEN
  RAISE EXCEPTION 'provider pair differs from usage account';
 END IF;
 IF EXISTS(SELECT 1 FROM billing_contract_provider_binding b WHERE b.merchant=NEW.merchant AND b.live_mode=NEW.live_mode
  AND (b.fee_subscription_id=NEW.fee_subscription_id OR b.usage_subscription_id=NEW.usage_subscription_id)
  AND ((b.team_id,b.assignment_id,b.customer_id,b.usage_subscription_id,b.fee_subscription_id,b.anchor)
   IS DISTINCT FROM (NEW.team_id,NEW.assignment_id,NEW.customer_id,NEW.usage_subscription_id,NEW.fee_subscription_id,NEW.anchor)
   OR b.binding#>>'{identity,operation_id}'=NEW.binding#>>'{identity,operation_id}'
   OR (b.binding->'terms'->'resources',b.binding->'terms'->'rounding') IS DISTINCT FROM (t->'resources',t->'rounding')
   OR tstzrange(b.starts_at,b.ends_at,'[)') && tstzrange(NEW.starts_at,NEW.ends_at,'[)'))) THEN
  RAISE EXCEPTION 'provider pair identity or service windows overlap';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_contract_provider_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_contract_provider_binding
 FOR EACH ROW EXECUTE FUNCTION guard_billing_contract_provider_binding();

-- The regional saga owns invalidation delivery and its permanent target fence.
-- This immutable receipt fences already-finalized paired commercial authority.
CREATE TABLE billing_provider_pair_revocation (
 contract_id uuid PRIMARY KEY,
 team_id uuid NOT NULL,
 identity jsonb NOT NULL CHECK(jsonb_typeof(identity)='object'),
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(team_id,contract_id) REFERENCES billing_contract_provider_binding(team_id,contract_id)
);
ALTER TABLE billing_provider_pair_revocation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_provider_pair_revocation FROM PUBLIC;
CREATE FUNCTION guard_billing_provider_pair_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'paired authority revocation is immutable'; END IF;
 PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
 PERFORM 1 FROM billing_commercial_contract WHERE id=NEW.contract_id AND team_id=NEW.team_id FOR UPDATE;
 IF NEW.revoked_at>clock_timestamp() OR NOT EXISTS(SELECT 1 FROM billing_contract_provider_binding b
  WHERE b.contract_id=NEW.contract_id AND b.team_id=NEW.team_id AND b.binding->'identity'=NEW.identity) THEN
  RAISE EXCEPTION 'revocation differs from finalized paired authority';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_provider_pair_revocation_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_provider_pair_revocation
 FOR EACH ROW EXECUTE FUNCTION guard_billing_provider_pair_revocation();
REVOKE ALL ON FUNCTION guard_billing_provider_pair_revocation() FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT ON billing_provider_pair_revocation TO service_role;
  CREATE POLICY provider_pair_revocation_backend ON billing_provider_pair_revocation TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;

-- A paid zero-dollar invoice proves the initial waiver, never cash settlement.
-- Current approval observation is refreshed under the acceptance authority guard.
CREATE TABLE billing_provider_pair_waiver (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL,
 contract_id uuid NOT NULL UNIQUE,
 invoice_id text NOT NULL UNIQUE CHECK(invoice_id LIKE 'in_%'),
 coupon_id text NOT NULL CHECK(btrim(coupon_id)<>''),
 starts_at timestamptz NOT NULL,
 ends_at timestamptz NOT NULL,
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 authority_checked_at timestamptz NOT NULL,
 authority_valid_until timestamptz NOT NULL,
 revoked_at timestamptz,
 UNIQUE(team_id,contract_id,id),
 FOREIGN KEY(team_id,contract_id) REFERENCES billing_contract_provider_binding(team_id,contract_id),
 CHECK(ends_at>starts_at AND authority_valid_until>authority_checked_at)
);
ALTER TABLE billing_provider_pair_waiver ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_provider_pair_waiver FROM PUBLIC;

CREATE FUNCTION guard_billing_provider_pair_waiver() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b billing_contract_provider_binding; c billing_commercial_contract;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'paired waiver history is immutable'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['authority_checked_at','authority_valid_until','revoked_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['authority_checked_at','authority_valid_until','revoked_at'])
   OR OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
   OR NEW.authority_checked_at<OLD.authority_checked_at THEN
   RAISE EXCEPTION 'paired waiver terms and revocation are immutable';
  END IF;
 ELSE
  SELECT * INTO STRICT b FROM billing_contract_provider_binding WHERE contract_id=NEW.contract_id AND team_id=NEW.team_id;
  SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id=NEW.contract_id FOR UPDATE;
  IF c.status<>'pending' OR c.offer_key<>'yc_2026' OR c.charge_amount_cents<>1200000 OR c.charge_interval_months<>12
   OR c.entitlement_cadence<>'scheduled' OR NEW.starts_at<>b.anchor
   OR NEW.ends_at<>billing_anniversary_boundary(b.anchor,12)
   OR (NEW.starts_at,NEW.ends_at) IS DISTINCT FROM (c.starts_at,c.ends_at)
   OR NEW.evidence->>'id' IS DISTINCT FROM NEW.invoice_id
   OR NEW.evidence->>'customer' IS DISTINCT FROM b.customer_id
   OR NEW.evidence#>>'{parent,subscription_details,subscription}' IS DISTINCT FROM b.fee_subscription_id
   OR NEW.evidence->>'status' IS DISTINCT FROM 'paid'
   OR (NEW.evidence->>'amount_paid')::bigint IS DISTINCT FROM 0
   OR (NEW.evidence->>'total')::bigint IS DISTINCT FROM 0 THEN
   RAISE EXCEPTION 'paired waiver differs from verified initial annual fee';
  END IF;
 END IF;
 IF NEW.authority_checked_at>clock_timestamp()
  OR (NEW.revoked_at IS NULL AND NEW.authority_checked_at<clock_timestamp()-interval '1 minute')
  OR NEW.authority_valid_until>NEW.authority_checked_at+interval '1 minute'
  OR NEW.revoked_at>clock_timestamp() THEN RAISE EXCEPTION 'paired authority observation is stale or future'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_provider_pair_waiver_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_provider_pair_waiver
 FOR EACH ROW EXECUTE FUNCTION guard_billing_provider_pair_waiver();

CREATE FUNCTION billing_provider_pair_covered(c billing_commercial_contract,s timestamptz,e timestamptz,issuing boolean)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.charge_kind='subscription' AND c.offer_key='yc_2026'
  AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=c.id) AND EXISTS(
  SELECT 1 FROM billing_provider_pair_waiver w JOIN billing_contract_provider_binding b ON b.contract_id=w.contract_id
  WHERE w.contract_id=c.id AND w.team_id=c.team_id AND b.customer_id=c.customer_id AND b.usage_subscription_id=c.subscription_id
  AND b.anchor=c.entitlement_anchor AND w.starts_at<=s AND w.ends_at>=e
  AND (NOT issuing OR EXISTS(SELECT 1 FROM billing_commercial_offer_activation a WHERE a.contract_id=c.id AND a.assignment_id=b.assignment_id))
  AND w.revoked_at IS NULL AND w.authority_checked_at<=clock_timestamp() AND w.authority_valid_until>clock_timestamp());
$$;

REVOKE ALL ON FUNCTION guard_billing_contract_provider_binding(),guard_billing_provider_pair_waiver() FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT ON billing_contract_provider_binding TO service_role;
  CREATE POLICY provider_binding_backend ON billing_contract_provider_binding TO service_role USING(true) WITH CHECK(true);
  GRANT SELECT,INSERT,UPDATE ON billing_provider_pair_waiver TO service_role;
  CREATE POLICY provider_waiver_backend ON billing_provider_pair_waiver TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;



-- Cash periods and allowance periods are separate immutable facts. Monthly
-- receipts authorize the same ordinal allowance, never a stretched cash period.
CREATE TABLE billing_provider_pair_monthly_payment (
 payment_id uuid PRIMARY KEY,
 team_id uuid NOT NULL,
 contract_id uuid NOT NULL,
 invoice_id text NOT NULL UNIQUE,
 fee_item_id text NOT NULL,
 fee_period_start timestamptz NOT NULL,
 fee_period_end timestamptz NOT NULL,
 period_start timestamptz NOT NULL,
 period_end timestamptz NOT NULL,
 amount_cents bigint NOT NULL CHECK(amount_cents=100000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(team_id,contract_id,payment_id) REFERENCES billing_contract_payment(team_id,contract_id,id),
 FOREIGN KEY(team_id,contract_id) REFERENCES billing_contract_provider_binding(team_id,contract_id),
 UNIQUE(team_id,period_start),
 UNIQUE(contract_id,fee_period_start),
 CHECK(isfinite(period_start) AND isfinite(period_end) AND period_start<period_end),
 CHECK(isfinite(fee_period_start) AND isfinite(fee_period_end) AND fee_period_start<fee_period_end)
);
ALTER TABLE billing_provider_pair_monthly_payment ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_provider_pair_monthly_payment FROM PUBLIC;
CREATE FUNCTION guard_billing_provider_pair_monthly_payment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; b billing_contract_provider_binding; p billing_contract_payment; m integer; fm integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'monthly payment mapping is immutable'; END IF;
 SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id=NEW.contract_id AND team_id=NEW.team_id FOR UPDATE;
 SELECT * INTO STRICT b FROM billing_contract_provider_binding WHERE contract_id=c.id AND team_id=c.team_id;
 SELECT * INTO STRICT p FROM billing_contract_payment WHERE id=NEW.payment_id AND contract_id=c.id AND team_id=c.team_id;
 IF c.status='ended' OR EXISTS(SELECT 1 FROM billing_provider_pair_revocation WHERE contract_id=c.id)
  OR (c.offer_key,c.charge_kind,c.charge_amount_cents,c.charge_interval_months,c.entitlement_kind,c.entitlement_cadence,c.entitlement_amount_cents,c.currency)
    IS DISTINCT FROM ('pro_monthly','subscription',120000::bigint,1,'metered_usage','monthly',100000::bigint,'usd')
  OR (NEW.invoice_id,NEW.fee_item_id,NEW.fee_period_start,NEW.fee_period_end)
    IS DISTINCT FROM (p.invoice_id,b.fee_item_id,p.service_period_start,p.service_period_end)
  OR (p.customer_id,p.subscription_id,p.base_price_id,p.base_amount_paid_cents,p.invoice_amount_paid_cents,p.currency)
    IS DISTINCT FROM (b.customer_id,b.fee_subscription_id,c.base_price_id,120000::bigint,120000::bigint,'usd')
  OR p.evidence#>>'{invoice,id}' IS DISTINCT FROM p.invoice_id
  OR p.evidence#>>'{invoice,lines,data,0,parent,subscription_item_details,subscription_item}' IS DISTINCT FROM b.fee_item_id
  OR jsonb_array_length(p.evidence#>'{invoice,lines,data}') IS DISTINCT FROM 1
  OR NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute') THEN
  RAISE EXCEPTION 'monthly mapping requires exact verified paid choice and fee receipt';
 END IF;
 m := (extract(year FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(year FROM b.anchor AT TIME ZONE 'UTC')::integer)*12
      +extract(month FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(month FROM b.anchor AT TIME ZONE 'UTC')::integer;
 fm := (extract(year FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(year FROM b.fee_anchor AT TIME ZONE 'UTC')::integer)*12
      +extract(month FROM p.service_period_start AT TIME ZONE 'UTC')::integer-extract(month FROM b.fee_anchor AT TIME ZONE 'UTC')::integer;
 IF (NEW.period_start,NEW.period_end) IS DISTINCT FROM (billing_anniversary_boundary(b.anchor,m),billing_anniversary_boundary(b.anchor,m+1))
  OR (p.service_period_start,p.service_period_end) IS DISTINCT FROM (billing_anniversary_boundary(b.fee_anchor,fm),billing_anniversary_boundary(b.fee_anchor,fm+1))
  OR NEW.period_start<c.starts_at OR (c.ends_at IS NOT NULL AND NEW.period_end>c.ends_at)
  OR NEW.created_at>clock_timestamp() THEN
  RAISE EXCEPTION 'monthly payment maps only to its corresponding original-calendar allowance';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_provider_pair_monthly_payment_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_provider_pair_monthly_payment
 FOR EACH ROW EXECUTE FUNCTION guard_billing_provider_pair_monthly_payment();
REVOKE ALL ON FUNCTION guard_billing_provider_pair_monthly_payment() FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT ON billing_provider_pair_monthly_payment TO service_role;
  CREATE POLICY provider_monthly_payment_backend ON billing_provider_pair_monthly_payment TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;

CREATE FUNCTION billing_payment_authorizes_entitlement(c billing_commercial_contract,p billing_contract_payment,s timestamptz,e timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT p.team_id=c.team_id AND p.contract_id=c.id AND CASE WHEN c.charge_interval_months=1
  AND EXISTS(SELECT 1 FROM billing_contract_provider_binding b WHERE b.contract_id=c.id)
 THEN EXISTS(SELECT 1 FROM billing_provider_pair_monthly_payment m WHERE m.payment_id=p.id
  AND m.contract_id=c.id AND m.team_id=c.team_id AND m.period_start=s AND m.period_end=e)
 ELSE p.service_period_start<=s AND p.service_period_end>=e END;
$$;

CREATE FUNCTION billing_payment_allows_activation(c billing_commercial_contract,p billing_contract_payment)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT p.team_id=c.team_id AND p.contract_id=c.id AND CASE WHEN c.charge_interval_months=1
  AND EXISTS(SELECT 1 FROM billing_contract_provider_binding b WHERE b.contract_id=c.id)
 THEN EXISTS(SELECT 1 FROM billing_provider_pair_monthly_payment m JOIN billing_pro_payment_verification v ON v.invoice_id=m.invoice_id
  WHERE m.payment_id=p.id AND m.contract_id=c.id AND m.period_start<=clock_timestamp() AND m.period_end>clock_timestamp()
  AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute')
 ELSE p.service_period_start<=clock_timestamp() AND p.service_period_end>clock_timestamp() END;
$$;

CREATE OR REPLACE FUNCTION guard_billing_contract_payment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; m integer; first_month integer; fee_anchor timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'base payment evidence is immutable'; END IF;
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR SHARE;
    IF (NEW.customer_id, NEW.subscription_id, NEW.base_price_id, NEW.currency, NEW.base_amount_paid_cents)
        IS DISTINCT FROM (c.customer_id, CASE c.charge_kind WHEN 'subscription' THEN COALESCE((SELECT b.fee_subscription_id FROM billing_contract_provider_binding b WHERE b.contract_id=c.id AND b.team_id=c.team_id),c.subscription_id) ELSE NULL END, c.base_price_id, c.currency, c.charge_amount_cents) THEN
        RAISE EXCEPTION 'base payment does not match commercial terms';
    END IF;
    IF c.charge_kind = 'upfront' AND ((NEW.service_period_start, NEW.service_period_end) IS DISTINCT FROM (c.starts_at, c.ends_at)
        OR NEW.evidence->'parent' IS DISTINCT FROM 'null'::jsonb) THEN
        RAISE EXCEPTION 'upfront receipt requires standalone invoice and exact contract term';
    END IF;
    IF c.status = 'ended' OR NEW.service_period_start < c.starts_at OR NEW.paid_at > clock_timestamp()
        OR NEW.verified_at > clock_timestamp() THEN RAISE EXCEPTION 'invalid base payment period or verification time'; END IF;
    SELECT COALESCE((SELECT b.fee_anchor FROM billing_contract_provider_binding b WHERE b.contract_id=c.id AND b.team_id=c.team_id),c.entitlement_anchor) INTO fee_anchor;
    m := (extract(year FROM NEW.service_period_start AT TIME ZONE 'UTC')::integer - extract(year FROM fee_anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM NEW.service_period_start AT TIME ZONE 'UTC')::integer - extract(month FROM fee_anchor AT TIME ZONE 'UTC')::integer;
    first_month := (extract(year FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(year FROM fee_anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(month FROM fee_anchor AT TIME ZONE 'UTC')::integer;
    IF (m - first_month) % c.charge_interval_months <> 0
        OR NEW.service_period_start <> billing_anniversary_boundary(fee_anchor, m)
        OR NEW.service_period_end <> billing_anniversary_boundary(fee_anchor, m + c.charge_interval_months) THEN
        RAISE EXCEPTION 'base payment service period differs from contract cadence';
    END IF;
    RETURN NEW;
END;
$$;

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
        IF OLD.status='pending' AND NEW.status='active' AND EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=NEW.id) THEN
            RAISE EXCEPTION 'paired authority is revoked';
        END IF;
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NOT billing_provider_pair_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT billing_sponsored_covered(NEW, NEW.starts_at, NEW.ends_at, false) AND NOT billing_yc_covered(NEW, NEW.starts_at, NEW.ends_at, false) AND NOT EXISTS (
            SELECT 1 FROM billing_contract_payment p WHERE p.contract_id = NEW.id
                AND billing_payment_allows_activation(NEW,p)) THEN
            RAISE EXCEPTION 'activation requires verified base payment coverage';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION guard_pro_payment_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='pending' AND NEW.status='active' AND NOT billing_provider_pair_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT billing_sponsored_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT billing_yc_covered(NEW,NEW.starts_at,NEW.ends_at,false) AND NOT EXISTS(
  SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=NEW.id
   AND billing_payment_allows_activation(NEW,p)
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required))
 THEN RAISE EXCEPTION 'activation requires an unquestioned base payment'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT c.status='active' AND c.collection_has_overdue_balance IS FALSE
  AND NOT EXISTS(SELECT 1 FROM billing_provider_pair_revocation r WHERE r.contract_id=c.id)
  AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until>clock_timestamp() AND c.starts_at<=s
  AND (c.ends_at IS NULL OR c.ends_at>=e)
  AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026','sponsored_usage') OR
    (c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
     AND (c.collection_evidence->>'period_start')::timestamptz=s
     AND (c.collection_evidence->>'period_end')::timestamptz=e))
  AND (billing_provider_pair_covered(c,s,e,true) OR billing_sponsored_covered(c,s,e,true) OR billing_yc_covered(c,s,e,true) OR EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id
   AND billing_payment_authorizes_entitlement(c,p,s,e)
   AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required)
   AND (c.offer_key NOT IN ('pro_monthly','pro_annual','yc_2026','sponsored_usage') OR EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND NOT v.review_required AND v.observed_at>clock_timestamp()-interval '1 minute'))))
  AND EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=c.team_id
   AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id);
$$;

CREATE OR REPLACE FUNCTION billing_commercial_offer_activation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
    IF EXISTS(SELECT 1 FROM billing_contract_provider_binding b WHERE b.contract_id=c.id) THEN
        IF c.offer_key<>'yc_2026' OR a.offer_key<>'yc_2026' OR c.charge_kind<>'subscription'
           OR c.charge_amount_cents<>v.charge_amount_cents OR c.charge_interval_months<>v.charge_interval_months THEN
            RAISE EXCEPTION 'paired execution differs from assigned annual offer';
        END IF;
        SELECT jsonb_build_object('ResourceTerms',b.binding->'terms'->'resources') INTO STRICT resource_terms
        FROM billing_contract_provider_binding b JOIN billing_provider_pair_waiver w ON w.contract_id=b.contract_id
        WHERE b.contract_id=c.id AND b.team_id=a.team_id AND b.assignment_id=a.id
          AND b.customer_id=c.customer_id AND b.usage_subscription_id=c.subscription_id
          AND b.merchant=NEW.merchant_account AND b.live_mode=NEW.live_mode
          AND b.anchor=NEW.anchor AND b.starts_at=NEW.anchor AND b.ends_at=NEW.ends_at
          AND billing_provider_pair_covered(c,NEW.anchor,NEW.ends_at,false)
        FOR SHARE OF w;
    ELSIF c.offer_key='yc_2026' AND c.charge_kind='subscription'
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

ALTER TABLE billing_usage_entitlement ADD COLUMN paired_waiver_id uuid;
ALTER TABLE billing_usage_entitlement DROP CONSTRAINT entitlement_one_authority;
ALTER TABLE billing_usage_entitlement ADD CONSTRAINT entitlement_one_authority
 CHECK(num_nonnulls(payment_id,waiver_id,sponsorship_id,paired_waiver_id)=1);
ALTER TABLE billing_usage_entitlement ADD FOREIGN KEY(team_id,contract_id,paired_waiver_id)
 REFERENCES billing_provider_pair_waiver(team_id,contract_id,id);

CREATE OR REPLACE FUNCTION guard_billing_usage_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; p billing_contract_payment; s timestamptz; e timestamptz; amount bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'entitlement history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR UPDATE;
        IF NEW.payment_id IS NOT NULL THEN
            SELECT * INTO STRICT p FROM billing_contract_payment WHERE team_id=NEW.team_id AND contract_id=NEW.contract_id AND id=NEW.payment_id;
        ELSIF NEW.paired_waiver_id IS NOT NULL THEN
            IF NOT billing_provider_pair_covered(c,NEW.period_start,NEW.period_end,true) THEN RAISE EXCEPTION 'entitlement lacks current paired waiver authority'; END IF;
        ELSIF NEW.sponsorship_id IS NOT NULL THEN
            IF NOT billing_sponsored_covered(c,NEW.period_start,NEW.period_end,true) THEN RAISE EXCEPTION 'entitlement lacks sponsored authority'; END IF;
        ELSIF NOT billing_yc_covered(c,NEW.period_start,NEW.period_end,true) THEN
            RAISE EXCEPTION 'entitlement lacks current waiver authority';
        END IF;
        SELECT period_start, period_end, amount_cents INTO s, e, amount FROM billing_contract_entitlement(c, clock_timestamp());
        IF (NEW.kind, NEW.amount_cents, NEW.currency)
            IS DISTINCT FROM (c.entitlement_kind, amount, c.currency)
            OR (NEW.payment_id IS NOT NULL AND NOT billing_payment_authorizes_entitlement(c,p,NEW.period_start,NEW.period_end)) THEN
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

-- Independent of the grant-inventory cursor; reset when the current allowance changes.
ALTER TABLE billing_entitlement_work
 ADD COLUMN paired_invoice_cursor text,
 ADD COLUMN paired_invoice_period_start timestamptz;
