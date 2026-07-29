-- Keep host admission safe across control-plane rollbacks. A pre-drain-aware
-- binary can still issue the legacy sandbox/build SQL, so enforce the final
-- launch decision at the database boundary shared by every binary version.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE FUNCTION public.require_active_host_admission(
    requested_host_id text,
    workload_kind text
) RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    -- FOR SHARE serializes admission with the UPDATE that marks a host
    -- draining/unhealthy. If admission wins, the status update waits for the
    -- launch transaction to commit; if the status update wins, this predicate
    -- is rechecked after the wait and admission is rejected.
    PERFORM 1
    FROM public.host h
    WHERE h.id = requested_host_id
      AND h.status = 'active'
    FOR SHARE;

    IF FOUND THEN
        RETURN;
    END IF;

    -- Before the first host row is registered, legacy single-host
    -- installations route through their configured/default VMD without a
    -- registry entry. Retain only that whole-table-empty compatibility path:
    -- once any host is registered, missing and unavailable hosts fail closed.
    IF NOT EXISTS (SELECT 1 FROM public.host) THEN
        RETURN;
    END IF;

    RAISE EXCEPTION
        'host admission denied for % on host %: host is missing or not active',
        workload_kind,
        requested_host_id
        USING ERRCODE = 'SS006';
END;
$$;

CREATE FUNCTION public.enforce_sandbox_host_admission() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IN ('starting', 'active', 'resuming') THEN
            PERFORM public.require_active_host_admission(
                NEW.host_id,
                'sandbox'
            );
        END IF;
        RETURN NEW;
    END IF;

    -- A paused -> resuming transition owns a new launch attempt. A host move
    -- while already in a live launch state does too. Deliberately do not
    -- re-admit same-host starting/resuming -> active: that write completes a
    -- launch already admitted before a later drain began.
    IF (OLD.status = 'paused' AND NEW.status = 'resuming')
       OR (
           NEW.host_id IS DISTINCT FROM OLD.host_id
           AND NEW.status IN ('starting', 'active', 'resuming')
       )
    THEN
        PERFORM public.require_active_host_admission(
            NEW.host_id,
            'sandbox'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sandbox_host_admission_insert
    BEFORE INSERT ON public.sandbox
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_sandbox_host_admission();

CREATE TRIGGER trg_sandbox_host_admission_update
    BEFORE UPDATE OF status, host_id ON public.sandbox
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_sandbox_host_admission();

CREATE FUNCTION public.enforce_template_build_host_admission() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog
AS $$
BEGIN
    IF OLD.status = 'pending' AND NEW.status = 'building' THEN
        PERFORM public.require_active_host_admission(
            NEW.vmd_host_id,
            'template build'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_template_build_host_admission
    BEFORE UPDATE OF status, vmd_host_id ON public.template_build
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_template_build_host_admission();

-- These functions are trigger internals, not an application-callable API.
REVOKE ALL ON FUNCTION public.require_active_host_admission(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_sandbox_host_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_template_build_host_admission() FROM PUBLIC;

COMMIT;
