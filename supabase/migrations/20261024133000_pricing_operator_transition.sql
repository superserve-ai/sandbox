BEGIN;

CREATE FUNCTION public.billing_transition_pricing_version(p_target text,p_actor uuid,p_reason text)
RETURNS TABLE(pricing_version text,changed_by uuid,reason text,changed_at timestamptz,epoch uuid,adoption_state text,changed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE
 s public.billing_pricing_switch;
 a public.billing_pricing_adoption;
 f public.billing_plan_version;
 old_epoch uuid;
 old_version text;
 expected record;
 dependency text;
BEGIN
 IF p_target IS NULL OR p_target NOT IN ('legacy','v2') OR p_actor IS NULL OR p_actor='00000000-0000-0000-0000-000000000000'::uuid
  OR p_reason IS NULL OR btrim(p_reason)='' OR char_length(p_reason)>500 THEN
  RAISE EXCEPTION 'valid pricing target, actor and reason required' USING ERRCODE='22023',CONSTRAINT='billing_pricing_transition_input';
 END IF;
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('session_replication_role')<>'origin' THEN
  RAISE EXCEPTION 'read committed and origin trigger execution required' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
 END IF;
 FOREACH dependency IN ARRAY ARRAY['billing_pricing_switch','billing_pricing_adoption','billing_pricing_adoption_event','billing_pricing_switch_audit','billing_plan_version','profile','user_role_assignments','roles','role_permissions','permissions'] LOOP
  IF to_regclass('public.'||dependency) IS NULL THEN
   RAISE EXCEPTION 'pricing transition schema prerequisites missing' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
  END IF;
 END LOOP;
 BEGIN
  SELECT * INTO STRICT s FROM public.billing_pricing_switch WHERE singleton FOR UPDATE;
  SELECT * INTO STRICT a FROM public.billing_pricing_adoption WHERE singleton FOR UPDATE;
 EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'pricing singleton prerequisites missing or invalid' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
 END;
 IF NOT EXISTS(SELECT 1 FROM public.profile pr JOIN public.user_role_assignments ura ON ura.user_id=pr.id
  JOIN public.roles r ON r.id=ura.role_id AND r.scope_type='platform'
  JOIN public.role_permissions rp ON rp.role_id=r.id JOIN public.permissions p ON p.id=rp.permission_id
  WHERE pr.id=p_actor AND ura.scope_type='platform' AND ura.team_id IS NULL AND ura.revoked_at IS NULL AND p.name='platform:billing:write') THEN
  RAISE EXCEPTION 'platform billing write authority required' USING ERRCODE='42501',CONSTRAINT='billing_pricing_transition_actor';
 END IF;
 FOR expected IN SELECT * FROM (VALUES
  ('billing_pricing_adoption_reset','public.billing_pricing_adoption_rotate()'),
  ('billing_pricing_switch_sync','public.sync_all_billing_plan_offers()')) AS required(trigger_name,function_name)
 LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid='public.billing_pricing_switch'::regclass AND t.tgname=expected.trigger_name
    AND NOT t.tgisinternal AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
    AND t.tgtype=17 AND t.tgenabled IN ('O','A') AND t.tgnargs=0
    AND t.tgfoid=to_regprocedure(expected.function_name)
    AND t.tgattr::text=(SELECT attnum::text FROM pg_catalog.pg_attribute WHERE attrelid=t.tgrelid AND attname='pricing_version' AND NOT attisdropped)
    AND replace(pg_catalog.pg_get_triggerdef(t.oid,false),'public.','')=
     format('CREATE TRIGGER %I AFTER UPDATE OF pricing_version ON billing_pricing_switch FOR EACH ROW WHEN ((old.pricing_version IS DISTINCT FROM new.pricing_version)) EXECUTE FUNCTION %s',expected.trigger_name,replace(expected.function_name,'public.',''))) THEN
   RAISE EXCEPTION 'canonical pricing rotation and synchronization triggers required' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
  END IF;
 END LOOP;
 IF s.pricing_version=p_target THEN
  RETURN QUERY SELECT s.pricing_version,s.changed_by,s.reason,s.changed_at,a.epoch,a.state,false;
  RETURN;
 END IF;
 IF p_target='v2' THEN
  SELECT * INTO f FROM public.billing_plan_version v WHERE v.family='free' AND v.pricing_version='v2' AND v.state='published' FOR SHARE;
  IF NOT FOUND OR f.kind<>'free' OR f.max_sandboxes IS NULL OR f.max_template_vcpu IS NULL OR f.max_template_memory_mib IS NULL OR f.max_template_disk_mib IS NULL
   OR f.allowance_period IS DISTINCT FROM 'day_window' OR f.allowance_on_exhausted IS DISTINCT FROM 'pause' OR (f.allowance_cents IS NULL AND f.allowance_compute_seconds IS NULL) THEN
   RAISE EXCEPTION 'published usable v2 Free catalog required' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
  END IF;
 END IF;
 old_epoch:=a.epoch;
 old_version:=s.pricing_version;
 UPDATE public.billing_pricing_switch v SET pricing_version=p_target,changed_by=p_actor,reason=btrim(p_reason),changed_at=clock_timestamp()
 WHERE v.singleton RETURNING v.* INTO STRICT s;
 SELECT * INTO STRICT a FROM public.billing_pricing_adoption WHERE singleton;
 IF a.epoch=old_epoch OR a.state<>'preparing' OR a.released_at IS NOT NULL OR a.evidence IS NOT NULL THEN
  RAISE EXCEPTION 'pricing rotation postcondition failed' USING ERRCODE='55000',CONSTRAINT='billing_pricing_transition_prerequisite';
 END IF;
 INSERT INTO public.billing_pricing_switch_audit(actor_id,from_version,to_version,reason) VALUES(p_actor,old_version,p_target,btrim(p_reason));
 RETURN QUERY SELECT s.pricing_version,s.changed_by,s.reason,s.changed_at,a.epoch,a.state,true;
END $$;

REVOKE ALL ON FUNCTION public.billing_transition_pricing_version(text,uuid,text) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.billing_transition_pricing_version(text,uuid,text) FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='service_role') THEN
  GRANT EXECUTE ON FUNCTION public.billing_transition_pricing_version(text,uuid,text) TO service_role;
 END IF;
END $$;

COMMIT;
