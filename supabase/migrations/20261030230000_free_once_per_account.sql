-- The Free allowance is once per account. Each cell claims a user's one Free
-- team atomically; a later team, or one Console marks additional because the
-- user holds a Free team in another cell, starts awaiting a paid plan instead,
-- under either pricing switch.
ALTER TABLE team_promotion_creation_attempt ADD COLUMN additional_team boolean NOT NULL DEFAULT false;

-- The claim outlives its team, so deleting a team never frees a second Free.
CREATE TABLE billing_account_free_team (
 user_id uuid PRIMARY KEY,
 team_id uuid NOT NULL UNIQUE,
 claimed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE billing_additional_team (
 team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
 marked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE billing_account_free_team ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_additional_team ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_account_free_team, billing_additional_team FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_account_free_team, billing_additional_team FROM %I',r);
  END IF;
 END LOOP;
 -- Console reads other cells' claims before creating a team.
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT ON billing_account_free_team TO service_role;
  CREATE POLICY account_free_team_backend_read ON billing_account_free_team FOR SELECT TO service_role USING(true);
 END IF;
END $$;

-- Teams that already started on Free hold their creator's claim, whether the
-- cohort enrolled them or the v2 switch assigned Free directly.
INSERT INTO billing_account_free_team(user_id,team_id,claimed_at)
SELECT DISTINCT ON (c.user_id) c.user_id,c.team_id,c.claimed_at
FROM (
 SELECT e.creator_user_id AS user_id,e.team_id,e.enrolled_at AS claimed_at
 FROM billing_new_team_enrollment e WHERE e.initial_assignment_id IS NOT NULL
 UNION
 SELECT creator.user_id,a.team_id,a.effective_from
 FROM team_plan_assignment a
 JOIN LATERAL (
  SELECT o.user_id FROM team_signup_promotion_outcome o WHERE o.team_id=a.team_id
  UNION SELECT t.user_id FROM team_promotion_creation_attempt t WHERE t.team_id=a.team_id
 ) creator ON true
 WHERE a.kind='free' AND a.source='signup'
) c
ORDER BY c.user_id,c.claimed_at,c.team_id
ON CONFLICT DO NOTHING;

CREATE FUNCTION billing_team_is_additional(p_team uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM billing_additional_team WHERE team_id=p_team)
  OR EXISTS(SELECT 1 FROM team_promotion_creation_attempt a WHERE a.team_id=p_team AND a.additional_team);
$$;

-- Returns whether p_team holds p_user's Free claim; a loser is marked additional.
-- Only billing_insert_signup_team calls it, inside its own definer context.
CREATE FUNCTION billing_claim_free_team(p_user uuid, p_team uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 INSERT INTO billing_account_free_team(user_id,team_id) VALUES(p_user,p_team) ON CONFLICT (user_id) DO NOTHING;
 IF EXISTS(SELECT 1 FROM billing_account_free_team WHERE user_id=p_user AND team_id=p_team) THEN
  RETURN true;
 END IF;
 INSERT INTO billing_additional_team(team_id) VALUES(p_team) ON CONFLICT DO NOTHING;
 RETURN false;
END $$;

CREATE FUNCTION prepare_team_promotion_creation(p_operation_id uuid, p_user_id uuid,
    p_name text, p_home_region text, p_authority_unavailable boolean, p_additional_team boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt;
BEGIN
    IF p_operation_id IS NULL OR p_operation_id='00000000-0000-0000-0000-000000000000'::uuid
       OR p_user_id IS NULL OR p_user_id='00000000-0000-0000-0000-000000000000'::uuid
       OR NULLIF(BTRIM(p_name),'') IS NULL OR octet_length(p_name)>256
       OR p_home_region IS NULL OR p_home_region NOT IN ('use','usw')
       OR p_authority_unavailable IS NULL OR p_additional_team IS NULL THEN
        RAISE EXCEPTION 'invalid team creation preparation' USING ERRCODE='22023';
    END IF;
    INSERT INTO team_promotion_creation_attempt(attempt_id,team_id,user_id,name,home_region,authority_unavailable,operation_id,additional_team)
        VALUES(gen_random_uuid(),gen_random_uuid(),p_user_id,p_name,p_home_region,p_authority_unavailable,p_operation_id,p_additional_team)
        ON CONFLICT (operation_id) DO NOTHING;
    SELECT * INTO STRICT v_attempt FROM team_promotion_creation_attempt a
        WHERE a.operation_id=p_operation_id FOR UPDATE;
    IF v_attempt.user_id<>p_user_id OR v_attempt.name<>p_name OR v_attempt.home_region<>p_home_region
       OR v_attempt.authority_unavailable<>p_authority_unavailable OR v_attempt.additional_team<>p_additional_team THEN
        RAISE EXCEPTION 'team creation binding conflict' USING ERRCODE='23505';
    END IF;
    RETURN recover_team_promotion_creation(p_operation_id,p_user_id,p_home_region);
END $$;

-- Callers that predate the flag create first teams, as before.
CREATE OR REPLACE FUNCTION prepare_team_promotion_creation(p_operation_id uuid, p_user_id uuid,
    p_name text, p_home_region text, p_authority_unavailable boolean)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT prepare_team_promotion_creation(p_operation_id,p_user_id,p_name,p_home_region,p_authority_unavailable,false);
$$;

CREATE FUNCTION complete_team_promotion_creation(p_operation_id uuid, p_attempt_id uuid, p_team_id uuid,
    p_user_id uuid, p_name text, p_home_region text, p_authority_unavailable boolean, p_additional_team boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt;
BEGIN
    SELECT * INTO v_attempt FROM team_promotion_creation_attempt a
        WHERE a.operation_id=p_operation_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF v_attempt.attempt_id IS DISTINCT FROM p_attempt_id OR v_attempt.team_id IS DISTINCT FROM p_team_id
       OR v_attempt.user_id IS DISTINCT FROM p_user_id OR v_attempt.name IS DISTINCT FROM p_name
       OR v_attempt.home_region IS DISTINCT FROM p_home_region
       OR v_attempt.authority_unavailable IS DISTINCT FROM p_authority_unavailable
       OR v_attempt.additional_team IS DISTINCT FROM p_additional_team THEN
        RAISE EXCEPTION 'team creation binding conflict' USING ERRCODE='23505';
    END IF;
    -- The existing writer locks this same row and retains its result after deletion.
    PERFORM create_team_with_promotion_attempt(p_attempt_id,p_team_id,p_user_id,p_name,p_home_region,p_authority_unavailable);
    RETURN recover_team_promotion_creation(p_operation_id,p_user_id,p_home_region);
END $$;

CREATE OR REPLACE FUNCTION complete_team_promotion_creation(p_operation_id uuid, p_attempt_id uuid, p_team_id uuid,
    p_user_id uuid, p_name text, p_home_region text, p_authority_unavailable boolean)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT complete_team_promotion_creation(p_operation_id,p_attempt_id,p_team_id,p_user_id,p_name,p_home_region,p_authority_unavailable,false);
$$;

CREATE OR REPLACE FUNCTION billing_insert_signup_team(p_id uuid,p_name text,p_actor uuid,p_region text,p_source text)
RETURNS team LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g billing_new_team_gate; f billing_plan_version; result team; additional boolean; trial_first boolean;
BEGIN
 IF p_id IS NULL OR p_actor IS NULL OR p_region IS NULL OR p_region NOT IN ('use','usw') OR p_source IS NULL OR p_source NOT IN ('trusted_signup','trusted_creation_attempt') THEN
  RAISE EXCEPTION 'trusted signup identity required' USING ERRCODE='22023';
 END IF;
 PERFORM 1 FROM billing_pricing_switch WHERE singleton FOR SHARE;
 SELECT * INTO STRICT g FROM billing_new_team_gate WHERE singleton FOR SHARE;
 additional:=billing_team_is_additional(p_id);
 IF (SELECT pricing_version FROM billing_pricing_switch WHERE singleton)='legacy' AND g.state='released' AND NOT billing_new_team_ready() THEN
  RAISE EXCEPTION 'new-team gate requires verified writer authority' USING ERRCODE='55000';
 END IF;
 IF (SELECT pricing_version FROM billing_pricing_switch WHERE singleton)='legacy' AND billing_new_team_ready() THEN
  IF p_region<>g.region OR p_id=g.system_team_id OR qm_team_managed_billing(p_id) THEN
   RAISE EXCEPTION 'signup region or identity does not match new-team cell' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM billing_plan_version WHERE family IN ('developer','pro','free') AND pricing_version='v2' AND state='published' FOR SHARE;
  PERFORM 1 FROM billing_trial_policy WHERE singleton FOR SHARE;
  trial_first:=billing_paid_first_sellable() AND billing_trial_configured();
  IF NOT additional AND NOT trial_first THEN
   additional:=NOT billing_claim_free_team(p_actor,p_id);
  END IF;
  IF additional OR trial_first THEN
   INSERT INTO billing_new_team_enrollment(team_id,region,enrollment_epoch,creator_user_id,source)
    VALUES(p_id,p_region,g.epoch,p_actor,p_source);
  ELSE
   SELECT * INTO STRICT f FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published';
   INSERT INTO billing_new_team_enrollment(team_id,region,enrollment_epoch,initial_assignment_id,initial_free_version_id,creator_user_id,source)
    VALUES(p_id,p_region,g.epoch,gen_random_uuid(),f.id,p_actor,p_source);
  END IF;
 ELSIF (SELECT pricing_version FROM billing_pricing_switch WHERE singleton)='v2' AND NOT additional THEN
  -- v2 serves every team, so the claim does not depend on the cohort gate.
  PERFORM billing_claim_free_team(p_actor,p_id);
 END IF;
 INSERT INTO team(id,name,home_region) VALUES(p_id,p_name,p_region) RETURNING * INTO result;
 RETURN result;
END $$;

-- An additional team awaits its plan without a cohort enrollment, and keeps
-- awaiting it across a pricing rollback.
CREATE OR REPLACE FUNCTION billing_team_awaiting_plan(p_team uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT (EXISTS(SELECT 1 FROM billing_new_team_enrollment e WHERE e.team_id=p_team AND e.initial_assignment_id IS NULL)
   OR billing_team_is_additional(p_team))
  AND NOT EXISTS(SELECT 1 FROM team_plan_assignment p WHERE p.team_id=p_team AND p.effective_to IS NULL);
$$;

-- A team that loses the Free claim on this path must not take a trial either.
CREATE OR REPLACE FUNCTION create_team_with_signup_trial(
    p_name text,
    p_user_id uuid,
    p_home_region text,
    p_policy_mode text
)
RETURNS team
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    created_team team;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'signup trial requires a creator' USING ERRCODE = '22023';
    END IF;
    IF p_policy_mode IS NULL OR p_policy_mode NOT IN ('first_team', 'additional_team') THEN
        RAISE EXCEPTION 'unsupported team creation policy' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO created_team FROM billing_insert_signup_team(gen_random_uuid(),p_name,p_user_id,p_home_region,'trusted_signup');
    PERFORM claim_team_signup_trial(created_team.id, p_user_id);
    DELETE FROM team_signup_trial_provenance WHERE team_id = created_team.id;
    RETURN created_team;
END;
$$;

CREATE OR REPLACE FUNCTION assign_new_team_free_plan() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE v billing_plan_version; pricing text; g billing_new_team_gate; e billing_new_team_enrollment;
BEGIN
 SELECT pricing_version INTO pricing FROM billing_pricing_switch FOR SHARE;
 SELECT * INTO STRICT g FROM billing_new_team_gate WHERE singleton FOR SHARE;
 SELECT * INTO e FROM billing_new_team_enrollment WHERE team_id=NEW.id;
 IF current_setting('superserve.migrating_team_id',true)=NEW.id::text THEN
  IF pricing='v2' OR billing_new_team_ready() THEN RAISE EXCEPTION 'regional team import is unavailable while pricing v2 is active' USING ERRCODE='55000'; END IF;
  RETURN NULL;
 END IF;
 IF pricing IS DISTINCT FROM 'v2' THEN
  IF g.state='released' AND NOT billing_new_team_ready() THEN RAISE EXCEPTION 'new-team gate requires verified writer authority' USING ERRCODE='55000'; END IF;
  IF NOT billing_new_team_ready() THEN
   IF e.team_id IS NOT NULL THEN RAISE EXCEPTION 'new-team gate closed during signup' USING ERRCODE='55000'; END IF;
   RETURN NULL;
  END IF;
  IF NEW.id=g.system_team_id OR (NEW.home_region=g.region AND qm_team_managed_billing(NEW.id)) THEN RETURN NULL; END IF;
  IF e.team_id IS NULL OR e.region<>NEW.home_region OR e.region<>g.region OR e.enrollment_epoch<>g.epoch THEN
   RAISE EXCEPTION 'trusted actual new-team creation required' USING ERRCODE='55000';
  END IF;
  IF e.initial_assignment_id IS NULL THEN
   PERFORM apply_assignment_limits(NEW.id,jsonb_build_object('max_concurrent',0));
   RETURN NULL;
  END IF;
 ELSIF (e.team_id IS NOT NULL AND e.initial_assignment_id IS NULL) OR billing_team_is_additional(NEW.id) THEN
  PERFORM apply_assignment_limits(NEW.id,jsonb_build_object('max_concurrent',0));
  RETURN NULL;
 END IF;
 SELECT * INTO v FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'published v2 Free plan is required for team creation' USING ERRCODE='55000'; END IF;
 INSERT INTO team_plan_assignment(id,team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,reason)
 VALUES(COALESCE(e.initial_assignment_id,gen_random_uuid()),NEW.id,v.family,v.kind,v.id,
  jsonb_build_object('offer_key',v.family,'display_name',v.display_name,'fee_cents',0,'interval_months',0,
   'monthly_credit_cents',COALESCE(billing_plan_version_monthly_credit(v),0),'version_id',v.id,'version',v.version,
   'pricing_version',v.pricing_version,'kind',v.kind,'family',v.family,'grants',v.credit_schedule,
   'matching',CASE WHEN v.matching_bps IS NULL THEN NULL ELSE jsonb_build_object('matching_bps',v.matching_bps,'cap_cents',v.cap_cents) END,
   'allowance',CASE WHEN v.allowance_period IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object('amount_cents',COALESCE(v.allowance_cents,0),
    'period',v.allowance_period,'on_exhausted',v.allowance_on_exhausted,
    'compute',CASE WHEN v.allowance_compute_seconds IS NULL THEN NULL ELSE jsonb_build_object('seconds',v.allowance_compute_seconds,
     'vcpu',v.allowance_compute_vcpu,'memory_gib',v.allowance_compute_memory_gib) END)) END),
  jsonb_build_object('max_concurrent',v.max_sandboxes,'max_vcpu',v.max_template_vcpu,'max_memory_mib',v.max_template_memory_mib,
   'max_disk_mib',v.max_template_disk_mib,'max_templates',v.max_templates),
  COALESCE(e.enrolled_at,clock_timestamp()),'signup','new team');
 RETURN NULL;
END $$;

-- An additional team never takes the trial, whatever the cell's pricing or
-- cohort state: it records an ineligible outcome, which the device claim then
-- returns instead of a grant.
CREATE OR REPLACE FUNCTION claim_team_signup_trial(p_team_id uuid, p_user_id uuid)
RETURNS TABLE(outcome text, reason text) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF billing_team_is_additional(p_team_id)
       AND NOT EXISTS(SELECT 1 FROM team_signup_promotion_outcome o WHERE o.team_id=p_team_id) THEN
        INSERT INTO team_signup_trial_denial(team_id) VALUES(p_team_id) ON CONFLICT DO NOTHING;
        INSERT INTO team_signup_promotion_outcome(team_id, user_id, outcome, reason)
            VALUES(p_team_id, p_user_id, 'promotion_ineligible', 'additional_team');
        UPDATE team_signup_trial_provenance SET creator_user_id = p_user_id,
            creator_bound_at = COALESCE(creator_bound_at, now()), completed_at = now()
            WHERE team_id = p_team_id;
    END IF;
    RETURN QUERY SELECT c.outcome, c.reason
        FROM claim_team_signup_trial_with_device(p_team_id, p_user_id) c;
END $$;

-- An additional team was never offered a trial, so it asks for a plan rather
-- than reporting one that ended.
CREATE OR REPLACE FUNCTION billing_team_entry_state(p_team uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT CASE
  WHEN NOT billing_team_awaiting_plan(p_team) THEN 'active'
  WHEN billing_team_trial_active(p_team) THEN 'trial'
  WHEN EXISTS(SELECT 1 FROM billing_pro_upgrade_setup s JOIN billing_pro_upgrade u ON u.id=s.upgrade_id
   WHERE u.team_id=p_team AND u.state NOT IN ('expired','ended') AND s.state='open') THEN 'payment_failed'
  WHEN billing_team_is_additional(p_team) THEN 'plan_required'
  ELSE 'trial_ended' END;
$$;

DO $$ DECLARE f text; r text; BEGIN
    FOREACH f IN ARRAY ARRAY[
        'prepare_team_promotion_creation(uuid,uuid,text,text,boolean,boolean)',
        'complete_team_promotion_creation(uuid,uuid,uuid,uuid,text,text,boolean,boolean)',
        'billing_team_is_additional(uuid)'
    ] LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || f || ' FROM PUBLIC';
        FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
            IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f,r);
            END IF;
        END LOOP;
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
            EXECUTE 'GRANT EXECUTE ON FUNCTION ' || f || ' TO service_role';
        END IF;
    END LOOP;
END $$;

REVOKE ALL ON FUNCTION billing_claim_free_team(uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON FUNCTION billing_claim_free_team(uuid,uuid) FROM %I',r);
        END IF;
    END LOOP;
END $$;
