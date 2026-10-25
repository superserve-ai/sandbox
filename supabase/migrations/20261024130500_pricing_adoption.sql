CREATE TABLE billing_pricing_adoption (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton) REFERENCES billing_pricing_switch(singleton),
 region text CHECK(region IN ('use','usw')),
 system_team_id uuid CHECK(system_team_id <> '00000000-0000-0000-0000-000000000000'),
 epoch uuid NOT NULL DEFAULT gen_random_uuid(),
 state text NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','released')),
 evidence jsonb,
 released_at timestamptz,
 CHECK((region IS NULL)=(system_team_id IS NULL)),
 CHECK((state='released')=(released_at IS NOT NULL)),
 CHECK(state<>'released' OR (region IS NOT NULL AND evidence IS NOT NULL))
);
INSERT INTO billing_pricing_adoption(singleton) VALUES(true);

CREATE TABLE billing_pricing_adoption_inventory (
 epoch uuid NOT NULL,
 team_id uuid NOT NULL,
 assignment_id uuid,
 bucket text NOT NULL,
 reason text NOT NULL,
 present boolean NOT NULL DEFAULT true,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(epoch,team_id)
);
CREATE INDEX billing_pricing_adoption_residual ON billing_pricing_adoption_inventory(epoch) WHERE present AND assignment_id IS NULL;

CREATE TABLE billing_pricing_adoption_credit_hold (
 team_id uuid PRIMARY KEY,
 reason text NOT NULL CHECK(reason IN ('credit_unknown','lapsed_unchecked')),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE billing_pricing_adoption_credit_resolution (
 team_id uuid PRIMARY KEY,
 assignment_id uuid NOT NULL,
 source jsonb NOT NULL,
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION billing_pricing_adoption_credit_source(p_team uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=public,pg_temp AS $$
 SELECT jsonb_build_object('customer',a.stripe_customer_id,'subscription',a.stripe_subscription_id,'status',a.stripe_subscription_status)
 FROM (SELECT p_team AS team_id) t LEFT JOIN team_billing_account a USING(team_id);
$$;

CREATE FUNCTION billing_pricing_adoption_blocker(p_team uuid) RETURNS text
LANGUAGE sql STABLE SET search_path=public,pg_temp AS $$
 SELECT CASE
  WHEN EXISTS(SELECT 1 FROM billing_pricing_adoption_credit_hold WHERE team_id=p_team) THEN (SELECT reason FROM billing_pricing_adoption_credit_hold WHERE team_id=p_team)
  WHEN EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id=p_team AND (a.stripe_customer_id IS NOT NULL OR a.stripe_subscription_id IS NOT NULL)
   AND NOT EXISTS(SELECT 1 FROM billing_pricing_adoption_credit_resolution r JOIN team_plan_assignment pa ON pa.id=r.assignment_id
    WHERE r.team_id=p_team AND pa.team_id=p_team AND pa.effective_to IS NULL AND r.source=billing_pricing_adoption_credit_source(p_team))) THEN 'financial_source_unreconciled'
  WHEN EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.team_id=p_team AND c.status='active'
   AND NOT EXISTS(SELECT 1 FROM team_plan_assignment pa WHERE pa.team_id=p_team AND pa.effective_to IS NULL AND pa.contract_id=c.id AND pa.source='migration')) THEN 'active_contract_unreconciled'
  WHEN qm_team_managed_billing(p_team) THEN 'qm_managed_billing'
  WHEN EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=p_team AND status='pending') THEN 'pending_contract'
  WHEN EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=p_team AND (checkout_initializing_at IS NOT NULL OR checkout_may_exist))
   OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=p_team AND state='pending' AND offer_key<>'free') THEN 'checkout_pending'
  WHEN EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=p_team AND state<>'ended') THEN 'yc_operation'
  WHEN EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=p_team AND state NOT IN ('revoked','expired')) THEN 'sponsored_operation'
 END;
$$;

CREATE TABLE billing_pricing_adoption_event (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 epoch uuid NOT NULL,
 region text,
 action text NOT NULL,
 actor text NOT NULL,
 reason text NOT NULL,
 details jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER billing_pricing_adoption_event_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON billing_pricing_adoption_event
 FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_pricing_adoption_retained BEFORE DELETE OR TRUNCATE ON billing_pricing_adoption
 FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();

CREATE FUNCTION billing_pricing_adoption_rotate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE a billing_pricing_adoption;
BEGIN
 UPDATE billing_pricing_adoption SET epoch=gen_random_uuid(),state='preparing',evidence=NULL,released_at=NULL
 WHERE singleton RETURNING * INTO a;
 INSERT INTO billing_pricing_adoption_event(epoch,region,action,actor,reason,details)
 VALUES(a.epoch,a.region,'switch_reset',COALESCE(NEW.changed_by::text,'database'),COALESCE(NULLIF(btrim(NEW.reason),''),'raw pricing switch changed'),jsonb_build_object('from',OLD.pricing_version,'to',NEW.pricing_version));
 RETURN NULL;
END $$;
CREATE TRIGGER billing_pricing_adoption_reset AFTER UPDATE OF pricing_version ON billing_pricing_switch
 FOR EACH ROW WHEN(OLD.pricing_version IS DISTINCT FROM NEW.pricing_version) EXECUTE FUNCTION billing_pricing_adoption_rotate();

CREATE FUNCTION billing_pricing_adoption_evidence_valid(p_region text,p_system uuid,p_epoch uuid,p_evidence jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(p_region IN ('use','usw') AND p_system<>'00000000-0000-0000-0000-000000000000' AND p_epoch IS NOT NULL
  AND jsonb_typeof(p_evidence)='object'
  AND p_evidence->>'region'=p_region AND p_evidence->>'system_team_id'=p_system::text AND p_evidence->>'epoch'=p_epoch::text
  AND p_evidence->>'assembled_sha' ~ '^[0-9a-f]{40}$'
  AND p_evidence->>'worker_sha'=p_evidence->>'assembled_sha' AND p_evidence->>'schema_sha'=p_evidence->>'assembled_sha'
  AND btrim(p_evidence->>'deployment_reference')<>'' AND btrim(p_evidence->>'worker_reference')<>''
  AND p_evidence->'verified_worker'='true'::jsonb,false);
$$;

CREATE FUNCTION billing_pricing_public_state()
RETURNS TABLE(pricing_version text,entry_open boolean,epoch uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public,pg_temp AS $$
 WITH observed AS (
  SELECT s.pricing_version AS raw,a.* FROM (SELECT 1) one
  LEFT JOIN billing_pricing_switch s ON s.singleton
  LEFT JOIN billing_pricing_adoption a ON a.singleton=s.singleton
 ), checked AS (
  SELECT *,COALESCE(raw='v2' AND state='released' AND released_at IS NOT NULL
   AND billing_pricing_adoption_evidence_valid(region,system_team_id,epoch,evidence),false) AS ready
  FROM observed
 )
 SELECT CASE WHEN ready THEN 'v2' ELSE 'legacy' END,ready,
  CASE WHEN ready OR (raw IN ('legacy','v2') AND state='preparing' AND released_at IS NULL AND evidence IS NULL
   AND ((region IS NULL AND system_team_id IS NULL) OR (region IN ('use','usw') AND system_team_id<>'00000000-0000-0000-0000-000000000000'))) THEN epoch END
 FROM checked;
$$;

CREATE FUNCTION billing_assert_pricing_entry_open(p_epoch uuid DEFAULT NULL,p_pricing_version text DEFAULT NULL)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE actual_epoch uuid; model text; opened boolean;
BEGIN
 SELECT pricing_version,entry_open,epoch INTO model,opened,actual_epoch FROM billing_lock_pricing_public_state();
 IF NOT opened OR actual_epoch IS NULL OR (p_epoch IS NULL)<>(p_pricing_version IS NULL)
  OR (p_epoch IS NOT NULL AND p_epoch<>actual_epoch) OR (p_pricing_version IS NOT NULL AND p_pricing_version<>model) THEN
  RAISE EXCEPTION 'pricing adoption entry is closed or epoch changed' USING ERRCODE='55000';
 END IF;
 RETURN actual_epoch;
END $$;

CREATE FUNCTION billing_prepare_pricing_adoption(p_region text,p_system uuid,p_actor text,p_reason text)
RETURNS uuid LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE a billing_pricing_adoption;
BEGIN
 IF p_region IS NULL OR p_region NOT IN ('use','usw') OR p_system IS NULL OR p_system='00000000-0000-0000-0000-000000000000' OR COALESCE(btrim(p_actor),'')='' OR COALESCE(btrim(p_reason),'')='' THEN
  RAISE EXCEPTION 'region, nonzero system team, actor and reason are required';
 END IF;
 PERFORM 1 FROM billing_pricing_switch WHERE singleton FOR SHARE;
 SELECT * INTO STRICT a FROM billing_pricing_adoption WHERE singleton FOR UPDATE;
 IF a.region IS NOT NULL AND (a.region<>p_region OR a.system_team_id<>p_system) THEN
  RAISE EXCEPTION 'adoption is bound to another region or system team';
 END IF;
 IF a.state='released' THEN RAISE EXCEPTION 'released adoption cannot be prepared without pricing rollback'; END IF;
 UPDATE billing_pricing_adoption SET region=p_region,system_team_id=p_system WHERE singleton;
 INSERT INTO billing_pricing_adoption_event(epoch,region,action,actor,reason,details)
 VALUES(a.epoch,p_region,'prepare',p_actor,p_reason,'{}');
 RETURN a.epoch;
END $$;

CREATE FUNCTION billing_capture_pricing_adoption(p_region text,p_system uuid,p_actor text,p_reason text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=public,pg_temp SET row_security=off AS $$
DECLARE a billing_pricing_adoption; total bigint; residual bigint; deferred bigint;
BEGIN
 IF COALESCE(btrim(p_actor),'')='' OR COALESCE(btrim(p_reason),'')='' THEN RAISE EXCEPTION 'actor and reason required'; END IF;
 PERFORM 1 FROM billing_pricing_switch WHERE singleton FOR SHARE;
 SELECT * INTO STRICT a FROM billing_pricing_adoption WHERE singleton FOR UPDATE;
 IF p_region IS NULL OR p_system IS NULL OR a.region IS DISTINCT FROM p_region OR a.system_team_id IS DISTINCT FROM p_system THEN
  RAISE EXCEPTION 'prepare the matching region and system team before capture';
 END IF;
 UPDATE billing_pricing_adoption_inventory SET present=false WHERE epoch=a.epoch AND present;
 INSERT INTO billing_pricing_adoption_inventory(epoch,team_id,assignment_id,bucket,reason,observed_at)
 SELECT a.epoch,t.id,pa.id,CASE WHEN d.reason IS NULL THEN b.bucket ELSE 'skipped' END,COALESCE(d.reason,NULLIF(b.reason,''),b.bucket),clock_timestamp()
 FROM team t CROSS JOIN LATERAL pricing_v2_activation_bucket(t.id) b
 CROSS JOIN LATERAL (SELECT billing_pricing_adoption_blocker(t.id) AS reason) d
 LEFT JOIN team_plan_assignment pa ON pa.team_id=t.id AND pa.effective_to IS NULL
 WHERE t.id<>p_system
 ON CONFLICT(epoch,team_id) DO UPDATE SET assignment_id=EXCLUDED.assignment_id,bucket=EXCLUDED.bucket,reason=EXCLUDED.reason,present=true,observed_at=EXCLUDED.observed_at;
 SELECT count(*),count(*) FILTER(WHERE assignment_id IS NULL),count(*) FILTER(WHERE bucket='skipped') INTO total,residual,deferred FROM billing_pricing_adoption_inventory WHERE epoch=a.epoch AND present;
 INSERT INTO billing_pricing_adoption_event(epoch,region,action,actor,reason,details)
 VALUES(a.epoch,p_region,'capture',p_actor,p_reason,jsonb_build_object('total',total,'unassigned',residual,'deferred',deferred));
 RETURN jsonb_build_object('epoch',a.epoch,'state',a.state,'total',total,'assigned',total-residual,'unassigned',residual,'deferred',deferred);
END $$;

CREATE FUNCTION billing_release_pricing_adoption(p_region text,p_system uuid,p_epoch uuid,p_actor text,p_reason text,p_evidence jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=public,pg_temp SET row_security=off AS $$
DECLARE raw text; a billing_pricing_adoption; snapshot jsonb; f billing_plan_version;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'release requires READ COMMITTED isolation'; END IF;
 SELECT pricing_version INTO STRICT raw FROM billing_pricing_switch WHERE singleton FOR UPDATE;
 SELECT * INTO STRICT a FROM billing_pricing_adoption WHERE singleton FOR UPDATE;
 IF raw<>'v2' OR p_epoch IS NULL OR a.epoch<>p_epoch OR p_region IS NULL OR p_system IS NULL OR a.region IS DISTINCT FROM p_region OR a.system_team_id IS DISTINCT FROM p_system THEN
  RAISE EXCEPTION 'release requires raw v2 and the current prepared region, system team and epoch' USING ERRCODE='55000';
 END IF;
 IF COALESCE(btrim(p_actor),'')='' OR COALESCE(btrim(p_reason),'')='' THEN RAISE EXCEPTION 'actor and reason required'; END IF;
 IF NOT billing_pricing_adoption_evidence_valid(p_region,p_system,p_epoch,p_evidence) THEN
  RAISE EXCEPTION 'explicit current region/system/epoch and matching assembled/schema/worker SHA with deployment/verified worker evidence required';
 END IF;
 IF to_regprocedure('billing_lock_pricing_public_state()') IS NULL OR to_regclass('public.billing_free_allowance_retry') IS NULL OR to_regprocedure('request_team_pause_all(uuid,text)') IS NULL OR to_regprocedure('billing_pause_target_settled(billing_team_pause_target)') IS NULL
  OR to_regprocedure('billing_free_allowance_refresh(uuid)') IS NULL OR to_regprocedure('guard_free_sandbox_shape()') IS NULL THEN
  RAISE EXCEPTION 'required allowance and pause worker schema missing';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='sandbox'::regclass AND tgname='sandbox_free_shape' AND tgenabled IN ('O','A') AND tgfoid='guard_free_sandbox_shape()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='team'::regclass AND tgname='team_new_free_plan' AND tgenabled IN ('O','A') AND tgfoid='assign_new_team_free_plan()'::regprocedure) THEN
  RAISE EXCEPTION 'enabled shape and signup enforcement triggers required';
 END IF;
 SELECT * INTO f FROM billing_plan_version WHERE family='free' AND pricing_version='v2' AND state='published' FOR SHARE;
 IF NOT FOUND OR f.kind<>'free' OR f.max_sandboxes IS NULL OR f.max_template_vcpu IS NULL OR f.max_template_memory_mib IS NULL OR f.max_template_disk_mib IS NULL
  OR f.allowance_period IS DISTINCT FROM 'day_window' OR f.allowance_on_exhausted IS DISTINCT FROM 'pause' OR (f.allowance_cents IS NULL AND f.allowance_compute_seconds IS NULL) THEN
  RAISE EXCEPTION 'published usable v2 Free catalog required';
 END IF;
 PERFORM team_id FROM team_billing_account WHERE team_id<>p_system ORDER BY team_id FOR UPDATE;
 PERFORM id FROM team WHERE id<>p_system ORDER BY id FOR UPDATE;
 PERFORM team_id FROM team_billing_account WHERE team_id<>p_system ORDER BY team_id FOR UPDATE;
 snapshot:=billing_capture_pricing_adoption(p_region,p_system,p_actor,p_reason);
 IF (snapshot->>'unassigned')::bigint<>0 OR (snapshot->>'deferred')::bigint<>0 OR EXISTS(SELECT 1 FROM billing_free_allowance_retry WHERE team_id<>p_system) OR EXISTS(SELECT 1 FROM billing_team_pause_target t WHERE t.team_id<>p_system AND t.done_at IS NULL AND NOT billing_pause_target_settled(t)) THEN
  INSERT INTO billing_pricing_adoption_event(epoch,region,action,actor,reason,details) VALUES(a.epoch,p_region,'release_blocked',p_actor,p_reason,snapshot);
  RETURN snapshot||jsonb_build_object('released',false,'blocker','unassigned teams, unresolved obligations, allowance retries or unsettled pause targets');
 END IF;
 UPDATE billing_pricing_adoption SET state='released',evidence=p_evidence,released_at=clock_timestamp() WHERE singleton;
 INSERT INTO billing_pricing_adoption_event(epoch,region,action,actor,reason,details) VALUES(a.epoch,p_region,'release',p_actor,p_reason,p_evidence||snapshot);
 RETURN snapshot||jsonb_build_object('state','released','released',true);
END $$;

DO $$ DECLARE r text; t text; f regprocedure; BEGIN
 FOREACH t IN ARRAY ARRAY['billing_pricing_adoption','billing_pricing_adoption_inventory','billing_pricing_adoption_event','billing_pricing_adoption_credit_hold','billing_pricing_adoption_credit_resolution'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',t);
  FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
   IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON %I FROM %I',t,r); END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
   EXECUTE format('GRANT SELECT ON %I TO service_role',t);
   EXECUTE format('CREATE POLICY adoption_backend_read ON %I TO service_role USING(true)',t);
  END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['billing_pricing_adoption_credit_source(uuid)'::regprocedure,'billing_pricing_adoption_blocker(uuid)'::regprocedure,'billing_pricing_adoption_rotate()'::regprocedure,'billing_pricing_adoption_evidence_valid(text,uuid,uuid,jsonb)'::regprocedure,'billing_pricing_public_state()'::regprocedure,'billing_assert_pricing_entry_open(uuid,text)'::regprocedure,
  'billing_prepare_pricing_adoption(text,uuid,text,text)'::regprocedure,'billing_capture_pricing_adoption(text,uuid,text,text)'::regprocedure,'billing_release_pricing_adoption(text,uuid,uuid,text,text,jsonb)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
   IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f,r); END IF;
  END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT EXECUTE ON FUNCTION billing_pricing_public_state(),billing_assert_pricing_entry_open(uuid,text) TO service_role;
 END IF;
END $$;
