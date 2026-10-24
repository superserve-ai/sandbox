CREATE FUNCTION billing_lock_pricing_public_state()
RETURNS TABLE(pricing_version text,entry_open boolean,epoch uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM 1 FROM public.billing_pricing_switch WHERE singleton FOR SHARE;
 IF to_regclass('public.billing_pricing_adoption') IS NULL
  OR to_regprocedure('public.billing_pricing_public_state()') IS NULL THEN
  RETURN QUERY SELECT 'legacy'::text,false,NULL::uuid;
  RETURN;
 END IF;
 PERFORM 1 FROM public.billing_pricing_adoption WHERE singleton FOR SHARE;
 RETURN QUERY SELECT p.pricing_version,p.entry_open,p.epoch FROM public.billing_pricing_public_state() p;
END $$;
REVOKE ALL ON FUNCTION billing_lock_pricing_public_state() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION billing_lock_pricing_public_state() FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT EXECUTE ON FUNCTION billing_lock_pricing_public_state() TO service_role;
 END IF;
END $$;
