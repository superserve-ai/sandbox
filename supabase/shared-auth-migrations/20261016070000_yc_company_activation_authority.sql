-- Global uniqueness survives regional retries and later eligibility handoffs.
-- The billing workflow owns this table; claim storage references its approval ID.
CREATE TABLE public.yc_company_activation_authority (
 company_identity text PRIMARY KEY CHECK (company_identity ~ '^https://www[.]ycombinator[.]com/companies/[a-z0-9]+(-[a-z0-9]+)*$'),
 approval_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 team_id uuid NOT NULL,
 home_region text NOT NULL CHECK (btrim(home_region)<>''),
 offer_key text NOT NULL DEFAULT 'yc_2026' CHECK (offer_key='yc_2026'),
 offer_version integer NOT NULL DEFAULT 1 CHECK (offer_version=1),
 approved_by uuid NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 approval_method text NOT NULL DEFAULT 'operator' CHECK (approval_method IN ('operator','verified_claim')),
 evidence_reference text NOT NULL CHECK (btrim(evidence_reference)<>''),
 claim_id uuid,
 revision bigint NOT NULL DEFAULT 0,
 revoked_at timestamptz, revoked_by uuid,
 UNIQUE(team_id),
 CHECK ((revoked_at IS NULL)=(revoked_by IS NULL))
);
ALTER TABLE public.yc_company_activation_authority ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_company_activation_authority FROM PUBLIC;
CREATE FUNCTION public.guard_yc_company_activation_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'company activation history is immutable'; END IF;
 IF TG_OP='UPDATE' AND ((to_jsonb(NEW)-ARRAY['revision','revoked_at','revoked_by']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['revision','revoked_at','revoked_by']) OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revision<>OLD.revision+1)
 THEN RAISE EXCEPTION 'only monotonic audited revocation may update company approval'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_company_activation_authority_guard BEFORE UPDATE OR DELETE ON public.yc_company_activation_authority FOR EACH ROW EXECUTE FUNCTION public.guard_yc_company_activation_authority();
REVOKE ALL ON FUNCTION public.guard_yc_company_activation_authority() FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON public.yc_company_activation_authority FROM %I',r);END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON public.yc_company_activation_authority TO service_role;
  CREATE POLICY backend_access ON public.yc_company_activation_authority TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;

-- Only narrowly scoped RPCs are exposed to the regional evidence connection.
CREATE FUNCTION public.read_yc_activation_authority(p_company text, p_team uuid)
RETURNS SETOF public.yc_company_activation_authority
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT * FROM public.yc_company_activation_authority WHERE company_identity=p_company OR team_id=p_team
$$;
CREATE FUNCTION public.reserve_yc_activation_authority(p_company text,p_team uuid,p_region text,p_actor uuid,p_method text,p_evidence text,p_claim uuid DEFAULT NULL)
RETURNS public.yc_company_activation_authority
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.yc_company_activation_authority;
BEGIN
 IF p_method='verified_claim' AND p_claim IS NULL THEN RAISE EXCEPTION 'verified claim identity required'; END IF;
 INSERT INTO public.yc_company_activation_authority(company_identity,team_id,home_region,approved_by,approval_method,evidence_reference,claim_id)
 VALUES(p_company,p_team,p_region,p_actor,p_method,p_evidence,p_claim) ON CONFLICT(company_identity) DO NOTHING;
 SELECT * INTO STRICT a FROM public.yc_company_activation_authority WHERE company_identity=p_company;
 IF a.team_id<>p_team OR a.home_region<>p_region OR a.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'company approval belongs to another team, region, or is revoked'; END IF;
 -- An existing operator approval may be adopted without rewriting its evidence.
 RETURN a;
END $$;
CREATE FUNCTION public.revoke_yc_activation_authority(p_approval uuid,p_team uuid,p_actor uuid)
RETURNS public.yc_company_activation_authority
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.yc_company_activation_authority;
BEGIN
 SELECT * INTO STRICT a FROM public.yc_company_activation_authority WHERE approval_id=p_approval AND team_id=p_team FOR UPDATE;
 IF a.revoked_at IS NULL THEN
  UPDATE public.yc_company_activation_authority SET revoked_at=clock_timestamp(),revoked_by=p_actor,revision=revision+1 WHERE approval_id=p_approval RETURNING * INTO a;
 END IF;
 RETURN a;
END $$;
REVOKE ALL ON FUNCTION public.read_yc_activation_authority(text,uuid),public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid),public.revoke_yc_activation_authority(uuid,uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['service_role','promotion_evidence_proxy'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('GRANT EXECUTE ON FUNCTION public.read_yc_activation_authority(text,uuid),public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid),public.revoke_yc_activation_authority(uuid,uuid,uuid) TO %I',r);
  END IF;
 END LOOP;
END $$;

CREATE FUNCTION public.lock_yc_activation_authority(p_approval uuid,p_team uuid,p_region text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE a public.yc_company_activation_authority;
BEGIN
 SELECT * INTO a FROM public.yc_company_activation_authority WHERE approval_id=p_approval AND team_id=p_team AND home_region=p_region FOR SHARE;
 RETURN FOUND AND a.revoked_at IS NULL;
END $$;
REVOKE ALL ON FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['service_role','promotion_evidence_proxy'] LOOP
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('GRANT EXECUTE ON FUNCTION public.lock_yc_activation_authority(uuid,uuid,text) TO %I',r);END IF;
 END LOOP;
END $$;
-- Supabase may grant new functions to these roles via default privileges.
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
 EXECUTE format('REVOKE ALL ON FUNCTION public.guard_yc_company_activation_authority(),public.read_yc_activation_authority(text,uuid),public.reserve_yc_activation_authority(text,uuid,text,uuid,text,text,uuid),public.revoke_yc_activation_authority(uuid,uuid,uuid),public.lock_yc_activation_authority(uuid,uuid,text) FROM %I',r);
 END IF;
 END LOOP;
END $$;
