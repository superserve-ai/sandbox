-- Source: 20260925000000_signup_device_evidence.sql
-- Apply to the shared Auth project's PostgreSQL database, once. Regional
-- promotion migrations do not contain this source of original signup evidence.
CREATE TABLE public.signup_device_attempt (
    attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    event_id text UNIQUE,
    fingerprint text,
    event_at timestamptz,
    verified_at timestamptz,
    bound_user_id uuid,
    bound_at timestamptz,
    CHECK ((event_id IS NULL AND fingerprint IS NULL AND event_at IS NULL AND verified_at IS NULL)
        OR (event_id IS NOT NULL AND fingerprint IS NOT NULL AND event_at IS NOT NULL AND verified_at IS NOT NULL))
);
CREATE TABLE public.signup_device_account_evidence (
    user_id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL UNIQUE REFERENCES public.signup_device_attempt(attempt_id) ON DELETE RESTRICT,
    bound_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.signup_device_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signup_device_account_evidence ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence FROM PUBLIC;
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence FROM %I', r);
        END IF;
    END LOOP;
END $$;

CREATE FUNCTION public.create_signup_device_attempt()
RETURNS TABLE(attempt_id uuid, challenge uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    RETURN QUERY INSERT INTO public.signup_device_attempt DEFAULT VALUES
        RETURNING signup_device_attempt.attempt_id, signup_device_attempt.challenge;
END $$;

-- This operation accepts only a trusted Console attestation after its provider
-- lookup. The event ID and metadata alone are not an attestation.
CREATE FUNCTION public.verify_signup_device_attempt(p_attempt uuid, p_challenge uuid,
    p_event_id text, p_fingerprint text, p_event_at timestamptz)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE a public.signup_device_attempt; v_now timestamptz := clock_timestamp();
BEGIN
    IF p_attempt IS NULL OR p_challenge IS NULL OR p_event_id IS NULL OR p_fingerprint IS NULL
       OR length(p_event_id) NOT BETWEEN 1 AND 256 OR length(p_fingerprint) NOT BETWEEN 1 AND 256
       OR p_event_at IS NULL OR NOT isfinite(p_event_at) THEN
        RAISE EXCEPTION 'invalid signup device attestation' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO a FROM public.signup_device_attempt WHERE signup_device_attempt.attempt_id = p_attempt FOR UPDATE;
    IF NOT FOUND OR a.challenge <> p_challenge THEN
        RAISE EXCEPTION 'signup attempt challenge mismatch' USING ERRCODE = '22023';
    END IF;
    IF a.verified_at IS NOT NULL THEN
        IF a.event_id = p_event_id AND a.fingerprint = p_fingerprint AND a.event_at = p_event_at THEN
            RETURN 'replayed';
        END IF;
        RAISE EXCEPTION 'signup attempt already verified' USING ERRCODE = '23505';
    END IF;
    IF a.created_at < v_now - interval '30 minutes' OR a.created_at > v_now + interval '30 seconds'
       OR p_event_at < a.created_at - interval '30 seconds'
       OR p_event_at > v_now + interval '30 seconds'
       OR p_event_at < v_now - interval '5 minutes' THEN
        RAISE EXCEPTION 'stale signup device event' USING ERRCODE = '22023';
    END IF;
    UPDATE public.signup_device_attempt SET event_id = p_event_id, fingerprint = p_fingerprint,
        event_at = p_event_at, verified_at = v_now WHERE signup_device_attempt.attempt_id = p_attempt;
    RETURN 'verified';
END $$;

-- The caller must have obtained the newly created Auth user through its
-- server-side signup callback. Database checks also fence old-account rebinding.
CREATE FUNCTION public.bind_signup_device_account(p_attempt uuid, p_user uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, auth AS $$
DECLARE a public.signup_device_attempt; v_created timestamptz; v_existing uuid;
BEGIN
    IF p_attempt IS NULL OR p_user IS NULL THEN
        RAISE EXCEPTION 'invalid signup binding' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('signup-device-user:' || p_user::text)::bigint);
    SELECT * INTO a FROM public.signup_device_attempt WHERE attempt_id = p_attempt FOR UPDATE;
    IF NOT FOUND OR a.verified_at IS NULL THEN
        RAISE EXCEPTION 'signup evidence not verified' USING ERRCODE = '22023';
    END IF;
    IF a.bound_user_id IS NOT NULL AND a.bound_user_id <> p_user THEN
        RAISE EXCEPTION 'signup event belongs to another account' USING ERRCODE = '23505';
    END IF;
    SELECT created_at INTO v_created FROM auth.users WHERE id = p_user;
    IF v_created IS NULL OR v_created < a.created_at - interval '5 minutes'
       OR v_created > a.created_at + interval '30 minutes' THEN
        RAISE EXCEPTION 'signup provenance mismatch' USING ERRCODE = '22023';
    END IF;
    UPDATE public.signup_device_attempt SET bound_user_id = p_user,
        bound_at = COALESCE(bound_at, clock_timestamp()) WHERE attempt_id = p_attempt;
    SELECT attempt_id INTO v_existing FROM public.signup_device_account_evidence WHERE user_id = p_user;
    IF v_existing IS NOT NULL THEN
        IF v_existing = p_attempt THEN RETURN 'replayed'; END IF;
        RETURN 'first_evidence_retained';
    END IF;
    INSERT INTO public.signup_device_account_evidence(user_id, attempt_id) VALUES(p_user, p_attempt);
    RETURN 'bound';
END $$;

CREATE FUNCTION public.get_signup_device_account_evidence(p_user uuid)
RETURNS TABLE(attempt_id uuid, event_id text, fingerprint text, event_at timestamptz, bound_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.attempt_id, a.event_id, a.fingerprint, a.event_at, b.bound_at
    FROM public.signup_device_account_evidence b
    JOIN public.signup_device_attempt a USING(attempt_id)
    WHERE b.user_id = p_user;
$$;

REVOKE ALL ON FUNCTION public.create_signup_device_attempt(),
    public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
    public.bind_signup_device_account(uuid,uuid),
    public.get_signup_device_account_evidence(uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON FUNCTION public.create_signup_device_attempt(),
            public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
            public.bind_signup_device_account(uuid,uuid),
            public.get_signup_device_account_evidence(uuid) FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON FUNCTION public.create_signup_device_attempt(),
            public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
            public.bind_signup_device_account(uuid,uuid),
            public.get_signup_device_account_evidence(uuid) FROM authenticated;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION public.create_signup_device_attempt(),
            public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
            public.bind_signup_device_account(uuid,uuid),
            public.get_signup_device_account_evidence(uuid) TO service_role;
    END IF;
END $$;


-- Source: 20260925183413_protect_shared_signup_device_evidence.sql
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


-- Source: 20260925190000_promotion_evidence_proxy_role.sql
-- The regional control planes connect to shared Auth as this RPC-only role.
CREATE ROLE promotion_evidence_proxy LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

GRANT USAGE ON SCHEMA public TO promotion_evidence_proxy;
REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence
    FROM promotion_evidence_proxy;
GRANT EXECUTE ON FUNCTION public.create_signup_device_attempt(),
    public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
    public.bind_signup_device_account(uuid,uuid),
    public.get_signup_device_account_evidence(uuid) TO promotion_evidence_proxy;
