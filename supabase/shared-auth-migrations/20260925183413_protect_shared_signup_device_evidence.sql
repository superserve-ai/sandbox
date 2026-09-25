-- Supabase can grant tables directly to API roles even when PUBLIC is revoked.
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence FROM %I', r);
        END IF;
    END LOOP;
END $$;

CREATE FUNCTION public.protect_accepted_signup_device_attempt()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'accepted signup device evidence is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.verified_at IS NULL THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'accepted signup device evidence is immutable' USING ERRCODE = '55000';
    END IF;
    IF (NEW.attempt_id, NEW.challenge, NEW.created_at, NEW.event_id,
        NEW.fingerprint, NEW.event_at, NEW.verified_at)
       IS DISTINCT FROM
       (OLD.attempt_id, OLD.challenge, OLD.created_at, OLD.event_id,
        OLD.fingerprint, OLD.event_at, OLD.verified_at)
       OR NOT (
           (NEW.bound_user_id, NEW.bound_at) IS NOT DISTINCT FROM (OLD.bound_user_id, OLD.bound_at)
           OR (OLD.bound_user_id IS NULL AND OLD.bound_at IS NULL
               AND NEW.bound_user_id IS NOT NULL AND NEW.bound_at IS NOT NULL)
       ) THEN
        RAISE EXCEPTION 'accepted signup device evidence is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER signup_device_attempt_accepted_immutable BEFORE UPDATE OR DELETE
    ON public.signup_device_attempt FOR EACH ROW EXECUTE FUNCTION public.protect_accepted_signup_device_attempt();
CREATE TRIGGER signup_device_attempt_no_truncate BEFORE TRUNCATE
    ON public.signup_device_attempt FOR EACH STATEMENT EXECUTE FUNCTION public.protect_accepted_signup_device_attempt();

CREATE FUNCTION public.protect_signup_device_account_evidence()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'accepted signup device evidence is immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER signup_device_account_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON public.signup_device_account_evidence FOR EACH STATEMENT EXECUTE FUNCTION public.protect_signup_device_account_evidence();

REVOKE ALL ON FUNCTION public.protect_accepted_signup_device_attempt(),
    public.protect_signup_device_account_evidence() FROM PUBLIC;
