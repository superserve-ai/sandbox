-- Which plan a team is on, for every tier. Each row is one contiguous stretch
-- with the terms and limits frozen when it began; a change closes the open row
-- and opens the next at the same instant. Paid plans point at the commercial
-- contract that bills them.
CREATE TABLE team_plan_assignment (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL,
 plan_key text NOT NULL CHECK(btrim(plan_key)<>''),
 kind text NOT NULL CHECK(kind IN ('free','prepaid','subscription','legacy_payg','custom')),
 plan_version_id uuid REFERENCES billing_plan_version(id),
 terms jsonb NOT NULL CHECK(jsonb_typeof(terms)='object'),
 limits jsonb NOT NULL CHECK(jsonb_typeof(limits)='object' AND (jsonb_typeof(limits->'max_concurrent')='number') IS TRUE),
 effective_from timestamptz NOT NULL,
 effective_to timestamptz CHECK(effective_to IS NULL OR effective_to>=effective_from),
 contract_id uuid REFERENCES billing_commercial_contract(id),
 source text NOT NULL CHECK(source IN ('signup','migration','checkout','credit_purchase','plan_change','staff')),
 assigned_by uuid,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 2000),
 idempotency_key text CHECK(idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(team_id,idempotency_key)
);
CREATE UNIQUE INDEX team_plan_assignment_open ON team_plan_assignment(team_id) WHERE effective_to IS NULL;
CREATE INDEX team_plan_assignment_history ON team_plan_assignment(team_id,effective_from DESC);
CREATE INDEX team_plan_assignment_contract ON team_plan_assignment(contract_id) WHERE contract_id IS NOT NULL;

CREATE FUNCTION guard_team_plan_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'UPDATE' AND TG_OP<>'INSERT' THEN RAISE EXCEPTION 'plan assignment history is immutable'; END IF;
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM team WHERE id=NEW.team_id FOR KEY SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'assignment team does not exist' USING ERRCODE='23503'; END IF;
  IF NEW.effective_to IS NOT NULL OR NEW.effective_from>clock_timestamp() THEN
   RAISE EXCEPTION 'a plan assignment starts open and not in the future';
  END IF;
  IF EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=NEW.team_id AND (effective_to IS NULL OR effective_to>NEW.effective_from)) THEN
   RAISE EXCEPTION 'plan assignments of a team cannot overlap';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.effective_to IS NOT NULL OR NEW.effective_to IS NULL OR NEW.effective_to>clock_timestamp()
  OR (to_jsonb(NEW)-'effective_to') IS DISTINCT FROM (to_jsonb(OLD)-'effective_to') THEN
  RAISE EXCEPTION 'a plan assignment only closes once';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER team_plan_assignment_guard BEFORE INSERT OR UPDATE OR DELETE ON team_plan_assignment
 FOR EACH ROW EXECUTE FUNCTION guard_team_plan_assignment();
CREATE TRIGGER team_plan_assignment_truncate_guard BEFORE TRUNCATE ON team_plan_assignment
 FOR EACH STATEMENT EXECUTE FUNCTION guard_team_plan_assignment();

-- Writes an assignment's frozen limits to the team, unless staff set the
-- team's limits by hand. An absent per-sandbox cap falls back to the default.
CREATE FUNCTION apply_assignment_limits(p_team uuid, p_limits jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 PERFORM set_config('superserve.applying_plan_limits','on',true);
 PERFORM set_config('superserve.applying_assignment_limits','on',true);
 UPDATE team SET
  max_sandboxes=(p_limits->>'max_concurrent')::integer,
  max_template_vcpu=(p_limits->>'max_vcpu')::integer,
  max_template_memory_mib=(p_limits->>'max_memory_mib')::integer,
  max_template_disk_mib=(p_limits->>'max_disk_mib')::integer
 WHERE id=p_team AND NOT limits_customized;
 PERFORM set_config('superserve.applying_assignment_limits','off',true);
 PERFORM set_config('superserve.applying_plan_limits','off',true);
END $$;

-- Under pricing v2 a team's plan assignment owns its limits: contract and
-- sponsorship changes that apply legacy plan limits leave such a team alone.
CREATE FUNCTION team_limits_follow_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF current_setting('superserve.applying_plan_limits',true)='on'
  AND current_setting('superserve.applying_assignment_limits',true) IS DISTINCT FROM 'on'
  AND EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=NEW.id AND effective_to IS NULL) THEN
  NEW.max_sandboxes:=OLD.max_sandboxes;
  NEW.max_template_vcpu:=OLD.max_template_vcpu;
  NEW.max_template_memory_mib:=OLD.max_template_memory_mib;
  NEW.max_template_disk_mib:=OLD.max_template_disk_mib;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER team_a_limits_follow_assignment
 BEFORE UPDATE OF max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib ON team
 FOR EACH ROW EXECUTE FUNCTION team_limits_follow_assignment();

CREATE FUNCTION team_plan_assignment_apply_limits() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM apply_assignment_limits(NEW.team_id,NEW.limits);
 RETURN NULL;
END $$;
CREATE TRIGGER team_plan_assignment_limits AFTER INSERT ON team_plan_assignment
 FOR EACH ROW EXECUTE FUNCTION team_plan_assignment_apply_limits();

-- Under pricing v2 every new team starts on Free, whichever path created it.
-- The terms and limits are frozen in the same shape as an assignment made by
-- the backend.
CREATE FUNCTION assign_new_team_free_plan() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE v billing_plan_version; pricing text;
BEGIN
 SELECT pricing_version INTO pricing FROM billing_pricing_switch FOR SHARE;
 IF current_setting('superserve.migrating_team_id',true)=NEW.id::text THEN
  IF pricing='v2' THEN RAISE EXCEPTION 'regional team import is unavailable while pricing v2 is active' USING ERRCODE='55000'; END IF;
  RETURN NULL;
 END IF;
 IF pricing IS DISTINCT FROM 'v2' THEN RETURN NULL; END IF;
 SELECT * INTO v FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'published v2 Free plan is required for team creation' USING ERRCODE='55000'; END IF;
 INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,source,reason)
 VALUES(NEW.id,v.family,v.kind,v.id,
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
  clock_timestamp(),'signup','new team');
 RETURN NULL;
END $$;
CREATE TRIGGER team_new_free_plan AFTER INSERT ON team FOR EACH ROW EXECUTE FUNCTION assign_new_team_free_plan();

CREATE OR REPLACE FUNCTION team_effective_limits(p_team uuid)
RETURNS TABLE(max_concurrent integer, max_vcpu integer, max_memory_mib integer, max_disk_mib integer, max_templates integer)
LANGUAGE sql STABLE AS $$
    WITH base AS (
        SELECT max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates
        FROM billing_plan_version WHERE family = 'payg' AND pricing_version = 'legacy' AND kind = 'legacy_payg' AND state <> 'draft'
        ORDER BY state = 'published' DESC, version DESC LIMIT 1
    ), assigned AS (
        SELECT (limits->>'max_templates')::integer AS max_templates FROM team_plan_assignment
        WHERE team_id=p_team AND effective_to IS NULL
    ), frozen AS (
        SELECT l.max_templates FROM billing_commercial_contract c JOIN billing_contract_limits l ON l.contract_id = c.id
        WHERE c.team_id = p_team AND c.status = 'active' ORDER BY c.starts_at DESC LIMIT 1
    )
    SELECT t.max_sandboxes,
        COALESCE(t.max_template_vcpu, b.max_template_vcpu),
        COALESCE(t.max_template_memory_mib, b.max_template_memory_mib),
        COALESCE(t.max_template_disk_mib, b.max_template_disk_mib),
        COALESCE(t.max_templates, (SELECT max_templates FROM assigned), (SELECT max_templates FROM frozen), b.max_templates)
    FROM team t LEFT JOIN base b ON true WHERE t.id = p_team;
$$;

ALTER TABLE team_plan_assignment ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON team_plan_assignment FROM PUBLIC;
REVOKE ALL ON FUNCTION assign_new_team_free_plan() FROM PUBLIC;
DO $$ DECLARE r text; f regprocedure; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON team_plan_assignment FROM %I',r);
   EXECUTE format('REVOKE ALL ON FUNCTION assign_new_team_free_plan() FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON team_plan_assignment TO service_role;
    CREATE POLICY team_plan_assignment_backend ON team_plan_assignment TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['guard_team_plan_assignment()'::regprocedure,'apply_assignment_limits(uuid,jsonb)'::regprocedure,'team_plan_assignment_apply_limits()'::regprocedure,'team_limits_follow_assignment()'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f); END IF;
 END LOOP;
END $$;
