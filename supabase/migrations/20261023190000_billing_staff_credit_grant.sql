-- One-off usage credit granted by staff, for example to correct a billing
-- mistake. It never expires: usage-only invoice reconciliation supports only
-- non-expiring metered credit. Each row is the durable intent behind exactly one Stripe credit
-- grant: the grant carries this row's id so a retry after a lost response
-- adopts it instead of granting twice.
CREATE TABLE billing_staff_credit_grant (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL REFERENCES team(id),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 customer_id text NOT NULL CHECK(btrim(customer_id)<>''),
 amount_cents bigint NOT NULL CHECK(amount_cents BETWEEN 1 AND 100000000),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 2000),
 requested_by uuid NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','issued')),
 stripe_credit_grant_id text UNIQUE CHECK(stripe_credit_grant_id IS NULL OR btrim(stripe_credit_grant_id)<>''),
 issued_at timestamptz,
 issuance_evidence jsonb,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 attempted_at timestamptz,
 last_error text,
 UNIQUE(team_id,idempotency_key),
 CHECK((state='issued')=(stripe_credit_grant_id IS NOT NULL) AND (state='issued')=(issued_at IS NOT NULL) AND (state='issued')=(issuance_evidence IS NOT NULL))
);
CREATE INDEX billing_staff_credit_grant_team ON billing_staff_credit_grant(team_id,requested_at DESC);
ALTER TABLE billing_staff_credit_grant ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_staff_credit_grant FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_staff_credit_grant FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON billing_staff_credit_grant TO service_role;
    CREATE POLICY staff_credit_backend ON billing_staff_credit_grant TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
END $$;

CREATE FUNCTION guard_billing_staff_credit_grant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'staff credit history is immutable'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'pending' OR NEW.attempts<>0 OR num_nonnulls(NEW.stripe_credit_grant_id,NEW.issued_at,NEW.issuance_evidence,NEW.last_error,NEW.attempted_at)<>0 THEN
   RAISE EXCEPTION 'staff credit must start pending';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.state='issued' THEN RAISE EXCEPTION 'issued staff credit is immutable'; END IF;
 IF NEW.attempts<OLD.attempts THEN RAISE EXCEPTION 'staff credit attempts only grow'; END IF;
 IF NEW.attempted_at IS DISTINCT FROM OLD.attempted_at AND NEW.attempts<>OLD.attempts+1 THEN
  RAISE EXCEPTION 'staff credit attempt time moves only with a new attempt';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','stripe_credit_grant_id','issued_at','issuance_evidence','attempts','attempted_at','last_error'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','stripe_credit_grant_id','issued_at','issuance_evidence','attempts','attempted_at','last_error']) THEN
  RAISE EXCEPTION 'staff credit request is immutable';
 END IF;
 IF NEW.state='issued' AND (NEW.issuance_evidence->>'id' IS DISTINCT FROM NEW.stripe_credit_grant_id
  OR NEW.issuance_evidence->>'customer' IS DISTINCT FROM NEW.customer_id
  OR NEW.issuance_evidence->>'category' IS DISTINCT FROM 'promotional'
  OR (NEW.issuance_evidence#>>'{amount,monetary,value}')::bigint IS DISTINCT FROM NEW.amount_cents
  OR NEW.issuance_evidence#>>'{metadata,staff_credit_grant}' IS DISTINCT FROM NEW.id::text
  OR NEW.issuance_evidence#>>'{applicability_config,scope,price_type}' IS DISTINCT FROM 'metered'
  OR NEW.issuance_evidence#>'{applicability_config,scope,prices}' IS NOT NULL AND jsonb_array_length(NEW.issuance_evidence#>'{applicability_config,scope,prices}')<>0
  OR COALESCE((NEW.issuance_evidence->>'priority')::bigint,0)<>50
  OR COALESCE((NEW.issuance_evidence->>'expires_at')::bigint,0)<>0
  OR COALESCE((NEW.issuance_evidence->>'voided_at')::bigint,0)<>0) THEN
  RAISE EXCEPTION 'issued grant does not match the staff credit';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_staff_credit_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_staff_credit_grant
 FOR EACH ROW EXECUTE FUNCTION guard_billing_staff_credit_grant();
REVOKE ALL ON FUNCTION guard_billing_staff_credit_grant() FROM PUBLIC;

-- A staff credit attempt checked the customer under the account lock; keep that
-- customer bound until the provider call it made has had time to finish.
CREATE FUNCTION guard_staff_credit_customer_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.stripe_customer_id IS NOT NULL AND NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id
 AND EXISTS(SELECT 1 FROM billing_staff_credit_grant WHERE team_id=NEW.team_id AND customer_id=OLD.stripe_customer_id
  AND state='pending' AND attempted_at>clock_timestamp()-interval '5 minutes') THEN
  RAISE EXCEPTION 'billing customer cannot be replaced while a staff credit is being issued';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER staff_credit_customer_binding BEFORE UPDATE OF stripe_customer_id ON team_billing_account
 FOR EACH ROW EXECUTE FUNCTION guard_staff_credit_customer_binding();
REVOKE ALL ON FUNCTION guard_staff_credit_customer_binding() FROM PUBLIC;

-- The backend role uses these through its own queries and the security-invoker triggers.
DO $$ DECLARE f regprocedure; BEGIN
 FOREACH f IN ARRAY ARRAY['guard_billing_staff_credit_grant()'::regprocedure,'guard_staff_credit_customer_binding()'::regprocedure] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f); END IF;
 END LOOP;
END $$;
