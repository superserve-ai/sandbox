CREATE TABLE billing_pro_upgrade (
    id uuid PRIMARY KEY,
    team_id uuid REFERENCES team(id) ON DELETE SET NULL,
    actor_id uuid NOT NULL,
    customer_id text NOT NULL,
    subscription_id text,
    offer_key text NOT NULL,
    request_payload jsonb NOT NULL,
    anchor timestamptz NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    quoted_at timestamptz NOT NULL,
    amount_cents bigint NOT NULL CHECK (amount_cents > 0),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','checkout','paid','credited','active','expired','ended')),
    session_id text UNIQUE,
    payment_evidence jsonb,
    payment_review_required boolean NOT NULL DEFAULT false,
    payment_review_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    payment_review_checked_at timestamptz,
    payment_method_id text,
    grant_id text UNIQUE,
    grant_attempted_at timestamptz,
    recurring_attempted_at timestamptz,
    base_created_at timestamptz,
    initial_assignment_id uuid,
    contract_id uuid REFERENCES billing_commercial_contract(id),
    next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text,
    CHECK (period_start <= quoted_at AND quoted_at < period_end),
    CHECK (state NOT IN ('paid','credited','active') OR payment_evidence IS NOT NULL),
    CHECK (state NOT IN ('credited','active') OR grant_id IS NOT NULL),
    CHECK (state <> 'active' OR contract_id IS NOT NULL)
);
CREATE UNIQUE INDEX billing_pro_upgrade_team ON billing_pro_upgrade(team_id) WHERE state NOT IN ('expired','ended');
CREATE INDEX billing_pro_upgrade_due ON billing_pro_upgrade(next_check_at) WHERE state NOT IN ('expired','ended') AND team_id IS NOT NULL;
CREATE TABLE billing_pro_upgrade_setup (
 id uuid PRIMARY KEY,
 upgrade_id uuid NOT NULL REFERENCES billing_pro_upgrade(id),
 request_payload jsonb NOT NULL,
 created_at timestamptz NOT NULL,
 session_id text UNIQUE,
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','complete','expired'))
);
CREATE UNIQUE INDEX billing_pro_upgrade_setup_pending ON billing_pro_upgrade_setup(upgrade_id) WHERE state<>'expired';
ALTER TABLE billing_pro_upgrade_setup ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_upgrade_setup FROM PUBLIC;
ALTER TABLE billing_pro_upgrade ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_upgrade FROM PUBLIC;

CREATE FUNCTION guard_pro_upgrade_entry() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=NEW.team_id AND state NOT IN ('active','expired','ended')) THEN
  RAISE EXCEPTION 'Pro upgrade payment confirmation is pending' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pro_upgrade_choice_entry BEFORE INSERT OR UPDATE OF offer_key,state ON billing_signup_choice
 FOR EACH ROW EXECUTE FUNCTION guard_pro_upgrade_entry();

CREATE FUNCTION guard_pro_upgrade_checkout() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.checkout_initializing_at IS NOT NULL AND NEW.checkout_initializing_at IS DISTINCT FROM OLD.checkout_initializing_at
 AND EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=NEW.team_id AND state NOT IN ('expired','ended')) THEN
  RAISE EXCEPTION 'Pro upgrade payment confirmation is pending' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pro_upgrade_checkout_entry BEFORE UPDATE ON team_billing_account
 FOR EACH ROW EXECUTE FUNCTION guard_pro_upgrade_checkout();
REVOKE ALL ON FUNCTION guard_pro_upgrade_entry(),guard_pro_upgrade_checkout() FROM PUBLIC;

CREATE TABLE billing_pro_upgrade_catchup (
 id uuid PRIMARY KEY,
 upgrade_id uuid NOT NULL REFERENCES billing_pro_upgrade(id),
 period_start timestamptz NOT NULL,
 period_end timestamptz NOT NULL CHECK(period_end>period_start),
 amount_cents bigint NOT NULL CHECK(amount_cents>0),
 created_at timestamptz NOT NULL,
 invoice_id text UNIQUE,
 UNIQUE(upgrade_id,period_start)
);
ALTER TABLE billing_pro_upgrade_catchup ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_pro_upgrade_catchup FROM PUBLIC;
DO $$
DECLARE t text; r text;
BEGIN
 FOREACH t IN ARRAY ARRAY['billing_pro_upgrade_setup','billing_pro_upgrade','billing_pro_upgrade_catchup'] LOOP
  FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
   IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
    EXECUTE format('REVOKE ALL ON %I FROM %I',t,r);
   END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
   EXECUTE format('GRANT SELECT,INSERT,UPDATE ON %I TO service_role',t);
   EXECUTE format('CREATE POLICY %I ON %I TO service_role USING(true) WITH CHECK(true)',t||'_backend',t);
  END IF;
 END LOOP;
END $$;

CREATE FUNCTION end_pro_upgrade() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='ended' THEN
  UPDATE billing_pro_upgrade SET state='ended' WHERE contract_id=NEW.id;
  UPDATE billing_signup_choice c SET offer_key='free',state='committed',generation=NULL,actor_id=NULL,base_price_id=NULL,request_payload=NULL,session_id=NULL,subscription_id=NULL,revision=c.revision+1
   FROM billing_pro_upgrade u WHERE u.contract_id=NEW.id AND u.team_id=c.team_id AND c.generation=u.quoted_at;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER end_pro_upgrade_contract AFTER UPDATE OF status ON billing_commercial_contract
 FOR EACH ROW EXECUTE FUNCTION end_pro_upgrade();
REVOKE ALL ON FUNCTION end_pro_upgrade() FROM PUBLIC;

CREATE FUNCTION guard_pro_upgrade_migration() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM id FROM team WHERE id=NEW.team_id FOR NO KEY UPDATE;
 IF EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=NEW.team_id) THEN
  RAISE EXCEPTION 'regional migration blocks new Pro upgrade authority' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pro_upgrade_migration_entry BEFORE INSERT ON billing_pro_upgrade
 FOR EACH ROW EXECUTE FUNCTION guard_pro_upgrade_migration();
REVOKE ALL ON FUNCTION guard_pro_upgrade_migration() FROM PUBLIC;
