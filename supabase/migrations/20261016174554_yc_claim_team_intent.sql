-- Local admission fence is committed before the shared company reservation.
-- Unknown shared outcomes retain it for exact retry or audited rejection.
CREATE TABLE public.yc_claim_team_intent (
 team_id uuid PRIMARY KEY REFERENCES public.team(id),
 claim_id uuid NOT NULL UNIQUE,
 user_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 released_at timestamptz
);
ALTER TABLE public.yc_claim_team_intent ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.yc_claim_team_intent FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON public.yc_claim_team_intent FROM %I',r);
   IF r='service_role' THEN
    GRANT SELECT,INSERT,UPDATE ON public.yc_claim_team_intent TO service_role;
    CREATE POLICY yc_claim_intent_backend ON public.yc_claim_team_intent TO service_role USING(true) WITH CHECK(true);
   END IF;
  END IF;
 END LOOP;
END $$;
CREATE FUNCTION public.yc_claim_guard_plan_choice() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN
 IF NEW.state<>'selecting' AND EXISTS(SELECT 1 FROM public.yc_claim_team_intent WHERE team_id=NEW.team_id AND released_at IS NULL) THEN
  RAISE EXCEPTION 'YC claim completion pending; resolve the claim before choosing another plan' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.yc_claim_guard_plan_choice() FROM PUBLIC;
CREATE TRIGGER yc_claim_plan_choice_guard BEFORE INSERT OR UPDATE OF state,offer_key ON public.billing_signup_choice
 FOR EACH ROW EXECUTE FUNCTION public.yc_claim_guard_plan_choice();

CREATE FUNCTION public.yc_claim_guard_checkout() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.yc_claim_team_intent WHERE team_id=NEW.team_id AND released_at IS NULL)
 AND ((NEW.checkout_initializing_at IS NOT NULL AND NEW.checkout_initializing_at IS DISTINCT FROM OLD.checkout_initializing_at)
 OR (NEW.stripe_activation_credit_reserved_at IS NOT NULL AND NEW.stripe_activation_credit_reserved_at IS DISTINCT FROM OLD.stripe_activation_credit_reserved_at)
 OR (NEW.stripe_activation_credit_grant_id IS NOT NULL AND NEW.stripe_activation_credit_grant_id IS DISTINCT FROM OLD.stripe_activation_credit_grant_id)) THEN
  RAISE EXCEPTION 'YC claim completion pending; conflicting checkout blocked' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.yc_claim_guard_checkout() FROM PUBLIC;
CREATE TRIGGER yc_claim_checkout_guard BEFORE UPDATE ON public.team_billing_account
 FOR EACH ROW EXECUTE FUNCTION public.yc_claim_guard_checkout();
