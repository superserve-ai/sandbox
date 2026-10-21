-- Read-lock exact historical prices without granting callers pricing write access.
CREATE FUNCTION public.lock_yc_accepted_offer_rates(acceptance uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE currency text; rate record; seen integer:=0; card text; rates jsonb; priced_at timestamptz;
BEGIN
 SELECT a.terms->>'rate_card_key',a.terms->'resource_rates',a.pricing_at INTO card,rates,priced_at
 FROM public.yc_offer_acceptance a WHERE a.id=acceptance AND a.accepted_at IS NOT NULL AND a.state NOT IN ('held','revoked');
 IF NOT FOUND THEN RETURN false; END IF;
 IF priced_at IS NULL OR jsonb_typeof(rates) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(rates)<>3 OR EXISTS(SELECT 1 FROM jsonb_array_elements(rates) x WHERE
  x->>'resource' NOT IN ('vcpu','memory_gib','storage_gib') OR x->>'unit' IS DISTINCT FROM 'second'
  OR x->>'currency' IS DISTINCT FROM 'USD' OR COALESCE(x->>'price_usd','') !~ '^[0-9]+([.][0-9]{1,12})?$' OR length(x->>'price_usd')>32)
 OR (SELECT count(DISTINCT value->>'id')<>3 OR count(DISTINCT value->>'resource')<>3 FROM jsonb_array_elements(rates)) THEN RETURN false; END IF;
 SELECT p.currency INTO currency FROM public.pricing_plan p WHERE p.key=card FOR SHARE;
 IF NOT FOUND OR currency<>'USD' THEN RETURN false; END IF;
 FOR rate IN SELECT r.*,x.resource AS wanted_resource,x.unit AS wanted_unit,x.price_usd AS wanted_price,x.currency AS wanted_currency
  FROM jsonb_to_recordset(rates) AS x(id uuid,resource text,unit text,price_usd numeric,currency text)
  JOIN public.pricing_rate r ON r.id=x.id ORDER BY r.id FOR SHARE OF r LOOP
  IF rate.plan_key IS DISTINCT FROM card
   OR rate.resource IS DISTINCT FROM rate.wanted_resource OR rate.unit IS DISTINCT FROM rate.wanted_unit
   OR rate.price_usd IS DISTINCT FROM rate.wanted_price OR rate.wanted_currency IS DISTINCT FROM currency
   OR rate.effective_from>priced_at OR (rate.effective_to IS NOT NULL AND rate.effective_to<=priced_at) THEN RETURN false; END IF;
  seen:=seen+1;
 END LOOP;
 RETURN seen=3 AND (SELECT count(DISTINCT value->>'id')=3 AND count(DISTINCT value->>'resource')=3 FROM jsonb_array_elements(rates));
END $$;
REVOKE ALL ON FUNCTION public.lock_yc_accepted_offer_rates(uuid) FROM PUBLIC;

CREATE TABLE public.yc_offer_acceptance (
 id uuid PRIMARY KEY,
 claim_id uuid NOT NULL UNIQUE,
 team_id uuid NOT NULL UNIQUE REFERENCES public.team(id),
 user_id uuid NOT NULL,
 home_region text NOT NULL,
 authority jsonb NOT NULL CHECK(jsonb_typeof(authority)='object'),
 terms jsonb NOT NULL CHECK(jsonb_typeof(terms)='object'),
 renewal_terms jsonb NOT NULL CHECK(jsonb_typeof(renewal_terms)='object'),
 terms_digest text NOT NULL CHECK(terms_digest ~ '^[a-f0-9]{64}$'),
 renewal_terms_digest text NOT NULL CHECK(renewal_terms_digest ~ '^[a-f0-9]{64}$'),
 pricing_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 request_id uuid UNIQUE,
 accepted_at timestamptz,
 assignment_id uuid UNIQUE,
 operation_id uuid UNIQUE,
 state text NOT NULL DEFAULT 'offered' CHECK(state IN ('offered','confirming','accepted','assignment_linked','dispatched','held','revoked')),
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0,
 lease_id uuid,
 lease_until timestamptz,
 last_error text,
 CHECK ((request_id IS NULL)=(accepted_at IS NULL)),
 CHECK (state='offered' OR accepted_at IS NOT NULL),
 CHECK (operation_id IS NULL OR assignment_id IS NOT NULL)
);
CREATE INDEX yc_offer_acceptance_pending ON public.yc_offer_acceptance(home_region,next_attempt_at)
 WHERE state IN ('confirming','accepted','assignment_linked','held');
CREATE TABLE public.yc_offer_acceptance_control (
 request_id uuid PRIMARY KEY,
 acceptance_id uuid NOT NULL REFERENCES public.yc_offer_acceptance(id),
 actor_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('hold','retry')),
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION public.yc_offer_acceptance_preserve() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' OR (NEW.id,NEW.claim_id,NEW.team_id,NEW.user_id,NEW.home_region,NEW.authority,NEW.terms,NEW.renewal_terms,NEW.terms_digest,NEW.renewal_terms_digest,NEW.pricing_at,NEW.created_at)
 IS DISTINCT FROM (OLD.id,OLD.claim_id,OLD.team_id,OLD.user_id,OLD.home_region,OLD.authority,OLD.terms,OLD.renewal_terms,OLD.terms_digest,OLD.renewal_terms_digest,OLD.pricing_at,OLD.created_at)
 OR (OLD.accepted_at IS NOT NULL AND (NEW.accepted_at,NEW.request_id) IS DISTINCT FROM (OLD.accepted_at,OLD.request_id))
 OR (OLD.assignment_id IS NOT NULL AND NEW.assignment_id IS DISTINCT FROM OLD.assignment_id)
 OR (OLD.operation_id IS NOT NULL AND NEW.operation_id IS DISTINCT FROM OLD.operation_id)
 OR (OLD.accepted_at IS NOT NULL AND NEW.state='offered') THEN
  RAISE EXCEPTION 'acceptance identity is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER yc_offer_acceptance_preserve BEFORE UPDATE OR DELETE ON public.yc_offer_acceptance
 FOR EACH ROW EXECUTE FUNCTION public.yc_offer_acceptance_preserve();
ALTER TABLE public.yc_offer_acceptance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.yc_offer_acceptance_control ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_offer_acceptance,public.yc_offer_acceptance_control FROM PUBLIC;
REVOKE ALL ON FUNCTION public.yc_offer_acceptance_preserve() FROM PUBLIC;
DO $$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.yc_offer_acceptance,public.yc_offer_acceptance_control FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.yc_offer_acceptance_preserve() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lock_yc_accepted_offer_rates(uuid) FROM %I',role_name);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  REVOKE ALL ON public.yc_offer_acceptance,public.yc_offer_acceptance_control FROM service_role;
  REVOKE ALL ON FUNCTION public.yc_offer_acceptance_preserve() FROM service_role;
  GRANT EXECUTE ON FUNCTION public.lock_yc_accepted_offer_rates(uuid) TO service_role;
  GRANT SELECT,INSERT,UPDATE ON public.yc_offer_acceptance TO service_role;
  CREATE POLICY service_access ON public.yc_offer_acceptance TO service_role USING(true) WITH CHECK(true);
  GRANT SELECT,INSERT ON public.yc_offer_acceptance_control TO service_role;
  CREATE POLICY service_access ON public.yc_offer_acceptance_control TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;
