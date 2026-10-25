
CREATE OR REPLACE FUNCTION billing_json_number(p jsonb)
RETURNS numeric LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN jsonb_typeof(p) = 'number' THEN p::text::numeric END;
$$;

CREATE OR REPLACE FUNCTION billing_json_cap(p jsonb)
RETURNS int LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN billing_json_number(p) BETWEEN 1 AND 2147483647 THEN billing_json_number(p)::int END;
$$;

CREATE OR REPLACE FUNCTION billing_free_plan(p_team uuid)
RETURNS TABLE(free_since timestamptz, allowance jsonb, max_vcpu int, max_memory_mib int, max_disk_mib int)
LANGUAGE sql STABLE AS $$
 SELECT a.effective_from,
        CASE WHEN jsonb_typeof(a.terms->'allowance') = 'object' THEN a.terms->'allowance' ELSE '{}'::jsonb END,
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_vcpu END, billing_json_cap(a.limits->'max_vcpu')),
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_memory_mib END, billing_json_cap(a.limits->'max_memory_mib')),
        COALESCE(CASE WHEN t.limits_customized THEN t.max_template_disk_mib END, billing_json_cap(a.limits->'max_disk_mib'))
 FROM team_plan_assignment a JOIN team t ON t.id = a.team_id
 WHERE a.team_id = p_team AND a.effective_to IS NULL AND a.kind = 'free';
$$;

CREATE OR REPLACE FUNCTION sandbox_snapshot_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    team_limit      int;
    sandbox_limit   int;
    in_flight_limit int;
    n               bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('sandbox_snapshot_quota'), hashtext(NEW.team_id::text));
    SELECT max_snapshots, max_snapshots_per_sandbox, max_snapshots_in_flight
    INTO team_limit, sandbox_limit, in_flight_limit
    FROM team
    WHERE id = NEW.team_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'team % does not exist', NEW.team_id;
    END IF;

    IF NEW.idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM sandbox_snapshot
        WHERE team_id = NEW.team_id
          AND sandbox_id = NEW.sandbox_id
          AND idempotency_key = NEW.idempotency_key
    ) THEN
        RETURN NEW;
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status = 'creating'
      AND created_at > now() - interval '1 hour';
    IF n >= in_flight_limit THEN
        RAISE EXCEPTION 'snapshots in flight limit reached for team (count=%, max=%)', n, in_flight_limit
            USING ERRCODE = 'SS003';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= team_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for team (count=%, max=%)', n, team_limit
            USING ERRCODE = 'SS002';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE sandbox_id = NEW.sandbox_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= sandbox_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for sandbox (count=%, max=%)', n, sandbox_limit
            USING ERRCODE = 'SS002';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_free_sandbox_shape() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE f record;
BEGIN
 BEGIN
  PERFORM 1 FROM team WHERE id=NEW.team_id FOR SHARE NOWAIT;
 EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'team plan assignment is changing' USING ERRCODE='SS003';
 END;
 SELECT * INTO f FROM billing_free_plan(NEW.team_id);
 IF FOUND AND ((f.max_vcpu IS NOT NULL AND NEW.vcpu_count>f.max_vcpu)
  OR (f.max_memory_mib IS NOT NULL AND NEW.memory_mib>f.max_memory_mib)
  OR (f.max_disk_mib IS NOT NULL AND NEW.disk_mib>f.max_disk_mib)) THEN
  RAISE EXCEPTION 'sandbox exceeds plan limits' USING ERRCODE='SS002',
   DETAIL=jsonb_build_object('max_vcpu',COALESCE(f.max_vcpu,0),'max_memory_mib',COALESCE(f.max_memory_mib,0),
    'max_disk_mib',COALESCE(f.max_disk_mib,0),'vcpu',NEW.vcpu_count,'memory_mib',NEW.memory_mib,'disk_mib',NEW.disk_mib)::text;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_free_shape BEFORE INSERT OR UPDATE OF status ON sandbox
 FOR EACH ROW WHEN (NEW.status IN ('starting','resuming')) EXECUTE FUNCTION guard_free_sandbox_shape();

CREATE OR REPLACE FUNCTION billing_compute_rates(p_team uuid)
RETURNS TABLE(vcpu_usd numeric, memory_gib_usd numeric)
LANGUAGE sql STABLE AS $$
 WITH ranked AS (
  SELECT r.resource, r.price_usd,
         row_number() OVER (PARTITION BY r.resource ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC) AS rate_rank
  FROM pricing_rate r JOIN pricing_plan pp ON pp.key = r.plan_key AND pp.active
  WHERE r.plan_key = COALESCE((SELECT tpp.plan_key FROM team_pricing_plan tpp JOIN pricing_plan tppp ON tppp.key = tpp.plan_key AND tppp.active
                               WHERE tpp.team_id = p_team AND tpp.effective_from <= now() AND (tpp.effective_to IS NULL OR tpp.effective_to > now())
                               ORDER BY tpp.effective_from DESC LIMIT 1), 'payg')
    AND r.unit = 'second' AND r.resource IN ('vcpu', 'memory_gib')
    AND r.effective_from <= now() AND (r.effective_to IS NULL OR r.effective_to > now())
 )
 SELECT COALESCE(MAX(price_usd) FILTER (WHERE resource = 'vcpu'), 0)::numeric,
        COALESCE(MAX(price_usd) FILTER (WHERE resource = 'memory_gib'), 0)::numeric
 FROM ranked WHERE rate_rank = 1;
$$;

CREATE INDEX team_plan_assignment_open_free ON team_plan_assignment(team_id) WHERE effective_to IS NULL AND kind = 'free';

CREATE TABLE billing_free_allowance (
 team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
 window_started_at timestamptz NOT NULL,
 resets_at timestamptz NOT NULL,
 allowance_usd numeric NOT NULL CHECK (allowance_usd >= 0),
 used_usd numeric NOT NULL CHECK (used_usd >= 0),
 blocked_until timestamptz,
 evaluated_at timestamptz NOT NULL,
 CHECK (resets_at = window_started_at + interval '24 hours'),
 CHECK (blocked_until IS NULL OR blocked_until = resets_at)
);
ALTER TABLE billing_free_allowance ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_free_allowance FROM PUBLIC;

CREATE OR REPLACE FUNCTION billing_free_window_start(p_team uuid, p_floor timestamptz, p_stored timestamptz, p_now timestamptz)
RETURNS timestamptz LANGUAGE plpgsql STABLE AS $$
DECLARE
 floor_at timestamptz := p_floor;
 started timestamptz;
BEGIN
 IF p_stored IS NOT NULL AND p_stored >= p_floor THEN
  IF p_stored + interval '24 hours' > p_now THEN
   RETURN p_stored;
  END IF;
  floor_at := p_stored + interval '24 hours';
 END IF;
 LOOP
  SELECT min(GREATEST(i.started_at, floor_at)) INTO started
  FROM sandbox_compute_billing_interval i
  WHERE i.team_id = p_team AND i.started_at < p_now AND (i.ended_at IS NULL OR i.ended_at > floor_at);
  IF started IS NULL OR started + interval '24 hours' > p_now THEN
   RETURN started;
  END IF;
  floor_at := started + interval '24 hours';
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION billing_free_allowance_eval(p_team uuid)
RETURNS TABLE(window_started_at timestamptz, resets_at timestamptz, allowance_usd numeric, used_usd numeric)
LANGUAGE sql STABLE AS $$
 WITH plan AS (
  SELECT * FROM billing_free_plan(p_team)
 ), rates AS (
  SELECT * FROM billing_compute_rates(p_team)
 ), win AS (
  SELECT billing_free_window_start(p_team, plan.free_since,
          (SELECT a.window_started_at FROM billing_free_allowance a WHERE a.team_id = p_team), now()) AS started
  FROM plan
 ), used AS (
  SELECT COALESCE(SUM(
          GREATEST(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, now()), win.started + interval '24 hours', now()) - GREATEST(i.started_at, win.started))), 0)
          * (i.vcpu_count * rates.vcpu_usd + i.memory_mib / 1024.0 * rates.memory_gib_usd)), 0)::numeric AS usd
  FROM win CROSS JOIN rates
  LEFT JOIN sandbox_compute_billing_interval i
   ON i.team_id = p_team AND i.started_at < now() AND (i.ended_at IS NULL OR i.ended_at > win.started)
  WHERE win.started IS NOT NULL
 )
 SELECT win.started,
        win.started + interval '24 hours',
        round(GREATEST(COALESCE(CASE WHEN jsonb_typeof(plan.allowance->'compute') = 'object'
              THEN billing_json_number(plan.allowance->'compute'->'seconds')
                   * (billing_json_number(plan.allowance->'compute'->'vcpu') * rates.vcpu_usd
                      + billing_json_number(plan.allowance->'compute'->'memory_gib') * rates.memory_gib_usd)
              ELSE billing_json_number(plan.allowance->'amount_cents') / 100 END, 0), 0), 6),
        round(COALESCE((SELECT usd FROM used), 0), 6)
 FROM plan, rates, win;
$$;

CREATE OR REPLACE FUNCTION billing_free_allowance_refresh(p_team uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
 e record;
BEGIN
 SELECT * INTO e FROM billing_free_allowance_eval(p_team);
 IF NOT FOUND THEN
  DELETE FROM billing_free_allowance WHERE team_id = p_team;
  RETURN false;
 END IF;
 IF e.window_started_at IS NULL THEN
  RETURN false;
 END IF;
 INSERT INTO billing_free_allowance AS a (team_id, window_started_at, resets_at, allowance_usd, used_usd, blocked_until, evaluated_at)
 VALUES (p_team, e.window_started_at, e.resets_at, e.allowance_usd, LEAST(e.used_usd, e.allowance_usd),
         CASE WHEN e.used_usd >= e.allowance_usd THEN e.resets_at END, now())
 ON CONFLICT (team_id) DO UPDATE SET
  window_started_at = EXCLUDED.window_started_at,
  resets_at = EXCLUDED.resets_at,
  allowance_usd = EXCLUDED.allowance_usd,
  used_usd = EXCLUDED.used_usd,
  blocked_until = CASE WHEN a.window_started_at = EXCLUDED.window_started_at AND a.blocked_until IS NOT NULL
                       THEN a.blocked_until ELSE EXCLUDED.blocked_until END,
  evaluated_at = EXCLUDED.evaluated_at;
 RETURN EXISTS(SELECT 1 FROM billing_free_allowance WHERE team_id = p_team AND blocked_until > now());
END $$;

CREATE OR REPLACE FUNCTION billing_free_allowance_blocked_until(p_team uuid)
RETURNS timestamptz LANGUAGE sql STABLE AS $$
 SELECT a.blocked_until FROM billing_free_allowance a JOIN billing_free_plan(p_team) f ON a.window_started_at >= f.free_since
 WHERE a.team_id = p_team AND a.blocked_until > now();
$$;

CREATE OR REPLACE FUNCTION billing_free_allowance_blocked(p_team uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT billing_free_allowance_blocked_until(p_team) IS NOT NULL;
$$;

CREATE TABLE billing_team_pause_request (
 assignment_id uuid PRIMARY KEY REFERENCES team_plan_assignment(id),
 team_id uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE billing_team_pause_request ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_team_pause_request FROM PUBLIC;

CREATE TABLE billing_team_pause_target (
 sandbox_id uuid NOT NULL REFERENCES sandbox(id) ON DELETE CASCADE,
 team_id uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
 assignment_id uuid NOT NULL REFERENCES billing_team_pause_request(assignment_id) ON DELETE CASCADE,
 reason text NOT NULL CHECK (reason IN ('plan_switch_free')),
 requested_at timestamptz NOT NULL,
 done_at timestamptz,
 PRIMARY KEY (sandbox_id, reason, requested_at)
);
CREATE INDEX billing_team_pause_target_open ON billing_team_pause_target(team_id) WHERE done_at IS NULL;
ALTER TABLE billing_team_pause_target ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_team_pause_target FROM PUBLIC;

CREATE OR REPLACE FUNCTION request_team_pause_all(p_team uuid, p_reason text)
RETURNS integer LANGUAGE sql AS $$
 WITH requested AS (
  INSERT INTO billing_team_pause_request(assignment_id,team_id)
  SELECT id,team_id FROM team_plan_assignment
  WHERE team_id=p_team AND effective_to IS NULL AND kind='free'
  ON CONFLICT DO NOTHING
  RETURNING assignment_id,team_id,requested_at
 ), added AS (
  INSERT INTO billing_team_pause_target (sandbox_id, team_id, assignment_id, reason, requested_at)
  SELECT s.id, s.team_id, r.assignment_id, p_reason, r.requested_at
  FROM requested r JOIN sandbox s ON s.team_id=r.team_id
  WHERE s.destroyed_at IS NULL AND s.status NOT IN ('paused', 'failed', 'deleted')
  RETURNING 1
 )
 SELECT count(*)::int FROM added;
$$;

CREATE OR REPLACE FUNCTION billing_pause_target_settled(p_target billing_team_pause_target)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS (SELECT 1 FROM sandbox s WHERE s.id = p_target.sandbox_id AND s.destroyed_at IS NULL AND s.status NOT IN ('paused', 'failed', 'deleted'))
     OR EXISTS (SELECT 1 FROM snapshot n WHERE n.sandbox_id = p_target.sandbox_id AND n.created_at >= p_target.requested_at)
     OR (p_target.reason = 'plan_switch_free' AND NOT EXISTS (SELECT 1 FROM team_plan_assignment a WHERE a.id=p_target.assignment_id AND a.effective_to IS NULL));
$$;

CREATE OR REPLACE FUNCTION billing_pause_reason(p_team uuid, p_sandbox uuid)
RETURNS text LANGUAGE sql STABLE AS $$
 SELECT CASE
  WHEN NOT team_sandbox_billing_eligible(p_team) THEN
   CASE WHEN billing_free_allowance_blocked(p_team) THEN 'free_allowance_exhausted' ELSE 'billing_ineligible' END
  ELSE (SELECT t.reason FROM billing_team_pause_target t
        WHERE t.sandbox_id = p_sandbox AND t.done_at IS NULL AND NOT billing_pause_target_settled(t)
        ORDER BY t.requested_at LIMIT 1)
 END;
$$;

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE
 WHEN EXISTS(SELECT 1 FROM abuse_restrictions r WHERE r.subject_team_id=p_team_id AND r.released_at IS NULL
 AND (r.expires_at IS NULL OR r.expires_at>now()) AND r.action IN ('create','resume')) THEN false
 WHEN qm_team_managed_billing(p_team_id) THEN true
 WHEN EXISTS(SELECT 1 FROM billing_free_plan(p_team_id)) THEN NOT billing_free_allowance_blocked(p_team_id)
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

DO $$ DECLARE r text; f regprocedure; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_free_allowance,billing_team_pause_target,billing_team_pause_request FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE,DELETE ON billing_free_allowance TO service_role;
    GRANT SELECT,INSERT,UPDATE ON billing_team_pause_target TO service_role;
    GRANT SELECT,INSERT ON billing_team_pause_request TO service_role;
    CREATE POLICY team_pause_request_backend ON billing_team_pause_request TO service_role USING(true) WITH CHECK(true);
    CREATE POLICY free_allowance_backend ON billing_free_allowance TO service_role USING(true) WITH CHECK(true);
    CREATE POLICY team_pause_target_backend ON billing_team_pause_target TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['guard_free_sandbox_shape()'::regprocedure,'billing_free_plan(uuid)'::regprocedure,'billing_compute_rates(uuid)'::regprocedure,
  'billing_free_window_start(uuid,timestamptz,timestamptz,timestamptz)'::regprocedure,'billing_free_allowance_eval(uuid)'::regprocedure,
  'billing_free_allowance_refresh(uuid)'::regprocedure,'billing_free_allowance_blocked(uuid)'::regprocedure,
  'request_team_pause_all(uuid,text)'::regprocedure,'billing_pause_target_settled(billing_team_pause_target)'::regprocedure,
  'billing_json_number(jsonb)'::regprocedure,'billing_json_cap(jsonb)'::regprocedure,'billing_free_allowance_blocked_until(uuid)'::regprocedure,'billing_pause_reason(uuid,uuid)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f); END IF;
 END LOOP;
END $$;

CREATE OR REPLACE FUNCTION pricing_v2_activation_bucket(p_team uuid)
RETURNS TABLE(bucket text, reason text, stripe_customer_id text)
LANGUAGE sql STABLE AS $$
 SELECT CASE
    WHEN x.reason = 'already_assigned' THEN 'assigned'
    WHEN x.reason = 'active_contract' THEN 'contract'
    WHEN x.reason = 'abuse_blocked' THEN 'blocked'
    WHEN x.reason IS NOT NULL THEN 'skipped'
    WHEN x.subscription IS NOT NULL AND lower(COALESCE(x.status, '')) IN ('active','trialing','past_due','unpaid','paused') THEN 'legacy_payg'
    WHEN x.customer IS NOT NULL OR x.subscription IS NOT NULL THEN 'lapsed'
    ELSE 'free' END,
  x.reason, x.customer
 FROM (
  SELECT a.stripe_customer_id AS customer, a.stripe_subscription_id AS subscription, a.stripe_subscription_status AS status,
   CASE
    WHEN EXISTS(SELECT 1 FROM team_plan_assignment pa WHERE pa.team_id = p_team AND pa.effective_to IS NULL) THEN 'already_assigned'
    WHEN qm_team_managed_billing(p_team) THEN 'qm_managed_billing'
    WHEN EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.team_id = p_team AND c.status='active') THEN 'active_contract'
    WHEN EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.team_id = p_team AND c.status='pending') THEN 'pending_contract'
    WHEN a.checkout_initializing_at IS NOT NULL OR a.checkout_may_exist
      OR EXISTS(SELECT 1 FROM billing_signup_choice c WHERE c.team_id=p_team AND c.state='pending' AND c.offer_key<>'free') THEN 'checkout_pending'
    WHEN EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.team_id = p_team AND o.state <> 'ended') THEN 'yc_operation'
    WHEN EXISTS(SELECT 1 FROM billing_sponsored_operation o WHERE o.team_id = p_team AND o.state NOT IN ('revoked','expired')) THEN 'sponsored_operation'
    WHEN EXISTS(SELECT 1 FROM abuse_restrictions r WHERE r.subject_team_id = p_team AND r.released_at IS NULL
                AND (r.expires_at IS NULL OR r.expires_at > now()) AND r.action IN ('create','resume')) THEN 'abuse_blocked'
   END AS reason
  FROM (SELECT p_team AS team_id) t LEFT JOIN team_billing_account a USING (team_id)
 ) x;
$$;
REVOKE ALL ON FUNCTION pricing_v2_activation_bucket(uuid) FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN GRANT EXECUTE ON FUNCTION pricing_v2_activation_bucket(uuid) TO service_role; END IF;
END $$;
