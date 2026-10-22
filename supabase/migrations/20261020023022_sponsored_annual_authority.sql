-- Fee and product authority do not confer a second usage allowance.
CREATE TABLE billing_sponsored_annual_authority (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL REFERENCES team(id),
 sponsorship_id uuid NOT NULL,
 contract_id uuid NOT NULL,
 renewal_contract_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 approved_by uuid NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 customer_id text NOT NULL CHECK(btrim(customer_id)<>''),
 subscription_id text NOT NULL UNIQUE CHECK(btrim(subscription_id)<>''),
 item_id text NOT NULL UNIQUE CHECK(btrim(item_id)<>''),
 base_price_id text NOT NULL CHECK(btrim(base_price_id)<>''),
 base_product_id text NOT NULL CHECK(btrim(base_product_id)<>''),
 live_mode boolean NOT NULL,
 home_region text NOT NULL CHECK(btrim(home_region)<>''),
 starts_at timestamptz NOT NULL CHECK(isfinite(starts_at)),
 waiver_ends_at timestamptz NOT NULL CHECK(isfinite(waiver_ends_at)),
 provider_evidence jsonb NOT NULL CHECK(jsonb_typeof(provider_evidence)='object'),
 state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','renewal_pending','renewed','ended')),
 invoice_cursor text,
 next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_error text,
 lease_token uuid, lease_until timestamptz,
 UNIQUE(team_id,idempotency_key),
 UNIQUE(team_id,id),
 FOREIGN KEY(team_id,contract_id,sponsorship_id) REFERENCES billing_sponsored_operation(team_id,contract_id,id),
 CHECK(waiver_ends_at=billing_anniversary_boundary(starts_at,12)),
 CHECK((lease_token IS NULL)=(lease_until IS NULL))
);
CREATE UNIQUE INDEX sponsored_annual_current ON billing_sponsored_annual_authority(team_id) WHERE state<>'ended';
CREATE INDEX sponsored_annual_due ON billing_sponsored_annual_authority(next_check_at) WHERE state<>'ended';

CREATE FUNCTION guard_sponsored_annual_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'annual adoption history is immutable'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['state','invoice_cursor','next_check_at','last_error','lease_token','lease_until']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','invoice_cursor','next_check_at','last_error','lease_token','lease_until'])
     OR (OLD.state='ended' AND NEW.state<>'ended')
     OR (OLD.state IN ('renewal_pending','renewed') AND NEW.state='active') THEN
   RAISE EXCEPTION 'annual adoption terms and completed transitions are immutable';
  END IF;
  IF NEW.state IN ('renewal_pending','renewed') AND clock_timestamp()<NEW.waiver_ends_at THEN RAISE EXCEPTION 'annual renewal is not due'; END IF;
  IF NEW.state='renewed' AND NOT EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.id=NEW.renewal_contract_id AND c.team_id=NEW.team_id AND c.status='active') THEN RAISE EXCEPTION 'annual renewal lacks active paid contract'; END IF;
  RETURN NEW;
 END IF;
 PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
 IF NEW.state<>'active' OR NOT EXISTS(
  SELECT 1 FROM billing_sponsored_operation o JOIN billing_commercial_contract c ON c.id=o.contract_id
  JOIN team_billing_account a ON a.team_id=o.team_id JOIN team t ON t.id=o.team_id
  WHERE o.id=NEW.sponsorship_id AND o.team_id=NEW.team_id AND o.contract_id=NEW.contract_id
  AND o.state='active' AND o.revoked_at IS NULL AND c.status='active' AND c.charge_kind='sponsored_entitlement'
  AND o.customer_id=NEW.customer_id AND o.subscription_id=NEW.subscription_id
  AND a.stripe_customer_id=o.customer_id AND a.stripe_subscription_id=o.subscription_id
  AND a.commercial_billing_anchor=NEW.starts_at AND o.anchor=NEW.starts_at AND o.starts_at=NEW.starts_at
  AND o.ends_at=NEW.waiver_ends_at AND t.home_region=NEW.home_region
  AND NEW.starts_at<=clock_timestamp() AND NEW.waiver_ends_at>clock_timestamp()
  AND NOT a.checkout_may_exist AND a.checkout_initializing_at IS NULL
 ) THEN RAISE EXCEPTION 'annual adoption differs from active sponsored billing authority'; END IF;
 IF (SELECT count(*) FROM billing_contract_entitlement_schedule WHERE contract_id=NEW.contract_id)<>12
 OR EXISTS(SELECT 1 FROM billing_contract_entitlement_schedule WHERE contract_id=NEW.contract_id
 AND (month_offset NOT BETWEEN 0 AND 11 OR amount_cents<>CASE WHEN month_offset<3 THEN 3000000 ELSE 100000 END)) THEN
  RAISE EXCEPTION 'annual adoption requires the approved twelve month allowance schedule';
 END IF;
 IF EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE contract_id=NEW.contract_id AND state<>'issued') THEN RAISE EXCEPTION 'annual adoption awaits in-flight grant reconciliation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sponsored_annual_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_sponsored_annual_authority FOR EACH ROW EXECUTE FUNCTION guard_sponsored_annual_authority();

CREATE FUNCTION fence_sponsored_annual_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a billing_sponsored_annual_authority;
BEGIN
 PERFORM 1 FROM team_billing_account WHERE team_id=NEW.team_id FOR UPDATE;
 SELECT * INTO a FROM billing_sponsored_annual_authority WHERE team_id=NEW.team_id AND state<>'ended';
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='billing_commercial_contract' THEN
 IF NEW.id=a.renewal_contract_id
 AND NEW.offer_key='pro_annual' AND NEW.customer_id=a.customer_id AND NEW.subscription_id=a.subscription_id
 AND NEW.base_price_id=a.base_price_id AND NEW.starts_at=a.waiver_ends_at AND NEW.entitlement_anchor=a.starts_at
 AND clock_timestamp()>=a.waiver_ends_at THEN RETURN NEW; END IF;
 END IF;
 IF TG_TABLE_NAME='team_billing_account' THEN
  IF (NEW.stripe_customer_id,NEW.stripe_subscription_id,NEW.commercial_billing_anchor) IS NOT DISTINCT FROM (a.customer_id,a.subscription_id,a.starts_at)
  AND NOT NEW.checkout_may_exist AND NEW.checkout_initializing_at IS NULL THEN RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION 'operation conflicts with annual sponsorship authority';
END $$;
CREATE TRIGGER annual_contract_fence BEFORE INSERT ON billing_commercial_contract FOR EACH ROW EXECUTE FUNCTION fence_sponsored_annual_authority();
CREATE TRIGGER annual_sponsor_fence BEFORE INSERT ON billing_sponsored_operation FOR EACH ROW EXECUTE FUNCTION fence_sponsored_annual_authority();
CREATE TRIGGER annual_yc_fence BEFORE INSERT ON billing_yc_operation FOR EACH ROW EXECUTE FUNCTION fence_sponsored_annual_authority();
CREATE TRIGGER annual_account_fence BEFORE UPDATE OF stripe_customer_id,stripe_subscription_id,commercial_billing_anchor,checkout_may_exist,checkout_initializing_at ON team_billing_account FOR EACH ROW EXECUTE FUNCTION fence_sponsored_annual_authority();

CREATE FUNCTION sponsored_annual_plan_limits() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='active' AND clock_timestamp()<NEW.waiver_ends_at THEN
  PERFORM apply_plan_limits(NEW.team_id,'pro_annual');
 ELSIF NOT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=NEW.team_id AND status='active' AND charge_kind<>'sponsored_entitlement') THEN
  PERFORM apply_plan_limits(NEW.team_id,'free');
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER sponsored_annual_limits AFTER INSERT OR UPDATE OF state ON billing_sponsored_annual_authority FOR EACH ROW EXECUTE FUNCTION sponsored_annual_plan_limits();

ALTER TABLE billing_sponsored_annual_authority ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_sponsored_annual_authority FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_sponsored_annual_authority(),fence_sponsored_annual_authority(),sponsored_annual_plan_limits() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON billing_sponsored_annual_authority FROM %I',r); END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON billing_sponsored_annual_authority TO service_role;
  CREATE POLICY annual_backend ON billing_sponsored_annual_authority TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;
