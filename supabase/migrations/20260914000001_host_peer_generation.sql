-- Legacy rows remain unbound until an incarnation-aware registration commits.
ALTER TABLE host ADD COLUMN incarnation_id uuid;
ALTER TABLE host ADD COLUMN peer_generation bigint;
ALTER TABLE host ADD CONSTRAINT host_peer_binding CHECK (
    (incarnation_id IS NULL AND peer_generation IS NULL) OR
    (incarnation_id IS NOT NULL AND incarnation_id <> '00000000-0000-0000-0000-000000000000'::uuid
     AND peer_generation IS NOT NULL AND peer_generation > 0)
);

-- Deliberately no cascading foreign keys: deleting a host cannot free its ID.
CREATE TABLE host_identity_registry (host_id text PRIMARY KEY, retired boolean NOT NULL DEFAULT false);
INSERT INTO host_identity_registry (host_id) SELECT id FROM host;
CREATE TABLE host_retired_incarnation (
    host_id text NOT NULL, incarnation_id uuid NOT NULL,
    successor_incarnation_id uuid NOT NULL,
    PRIMARY KEY (host_id, incarnation_id)
);
CREATE TABLE host_retired_address (
    host_id text NOT NULL, incarnation_id uuid NOT NULL, vmd_addr text NOT NULL,
    PRIMARY KEY (host_id, incarnation_id, vmd_addr)
);

-- The transaction-local claim also fences older SQL writers after binding.
CREATE FUNCTION prepare_host_heartbeat(p_host text, p_incarnation text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE current_incarnation uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_host, 719));
    IF EXISTS (SELECT 1 FROM host_identity_registry WHERE host_id = p_host AND retired) THEN
        RAISE EXCEPTION 'host ID retired' USING ERRCODE = 'P0001';
    END IF;
    SELECT incarnation_id INTO current_incarnation FROM host WHERE id = p_host FOR UPDATE;
    IF current_incarnation IS NOT NULL AND current_incarnation IS DISTINCT FROM NULLIF(p_incarnation, '')::uuid THEN
        RAISE EXCEPTION 'host incarnation conflict' USING ERRCODE = 'P0001';
    END IF;
    PERFORM set_config('sandbox.claim_host', p_host, true);
    PERFORM set_config('sandbox.claim_incarnation', p_incarnation, true);
END;
$$;

CREATE FUNCTION fence_host_peer_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE claim uuid; authorized boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE host_identity_registry SET retired = true WHERE host_id = OLD.id;
        RETURN OLD;
    END IF;
    claim := NULLIF(current_setting('sandbox.claim_incarnation', true), '')::uuid;
    IF current_setting('sandbox.claim_host', true) IS DISTINCT FROM NEW.id THEN
        claim := NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        INSERT INTO host_identity_registry (host_id) VALUES (NEW.id) ON CONFLICT DO NOTHING;
        IF EXISTS (SELECT 1 FROM host_identity_registry WHERE host_id = NEW.id AND retired) THEN
            RAISE EXCEPTION 'host ID retired';
        END IF;
        NEW.incarnation_id := claim;
        NEW.peer_generation := CASE WHEN claim IS NULL THEN NULL ELSE 1 END;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id THEN RAISE EXCEPTION 'host ID is immutable'; END IF;
    authorized := current_setting('sandbox.rebind_host', true) = NEW.id;
    IF OLD.incarnation_id IS NOT NULL AND (
        NEW.vmd_addr IS DISTINCT FROM OLD.vmd_addr OR
        NEW.proxy_addr IS DISTINCT FROM OLD.proxy_addr OR
        NEW.last_heartbeat_at IS DISTINCT FROM OLD.last_heartbeat_at OR
        NEW.identity_bound IS DISTINCT FROM OLD.identity_bound OR
        NEW.incarnation_id IS DISTINCT FROM OLD.incarnation_id OR
        NEW.peer_generation IS DISTINCT FROM OLD.peer_generation
    ) AND claim IS DISTINCT FROM OLD.incarnation_id AND NOT COALESCE(authorized, false) THEN
        RAISE EXCEPTION 'host incarnation conflict';
    END IF;
    IF NEW.incarnation_id IS DISTINCT FROM OLD.incarnation_id THEN
        IF NEW.incarnation_id IS NULL OR (OLD.incarnation_id IS NOT NULL AND NOT COALESCE(authorized, false)) THEN
            RAISE EXCEPTION 'operator rebind required';
        END IF;
        IF NEW.incarnation_id IS DISTINCT FROM claim THEN RAISE EXCEPTION 'missing incarnation claim'; END IF;
        IF EXISTS (SELECT 1 FROM host_retired_incarnation WHERE host_id = NEW.id AND incarnation_id = NEW.incarnation_id) THEN
            RAISE EXCEPTION 'incarnation permanently retired';
        END IF;
        IF OLD.incarnation_id IS NOT NULL THEN
            INSERT INTO host_retired_incarnation (host_id, incarnation_id, successor_incarnation_id)
            VALUES (NEW.id, OLD.incarnation_id, NEW.incarnation_id);
        END IF;
        NEW.peer_generation := COALESCE(OLD.peer_generation + 1, 1);
    ELSIF NEW.vmd_addr IS DISTINCT FROM OLD.vmd_addr AND OLD.incarnation_id IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM host_retired_address WHERE host_id = NEW.id AND incarnation_id = OLD.incarnation_id AND vmd_addr = NEW.vmd_addr) THEN
            RAISE EXCEPTION 'address retired for this incarnation';
        END IF;
        INSERT INTO host_retired_address VALUES (NEW.id, OLD.incarnation_id, OLD.vmd_addr);
        NEW.peer_generation := OLD.peer_generation + 1;
    ELSE
        NEW.peer_generation := OLD.peer_generation;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER host_peer_identity BEFORE INSERT OR UPDATE OR DELETE ON host
FOR EACH ROW EXECUTE FUNCTION fence_host_peer_identity();

CREATE FUNCTION rebind_host_incarnation(p_host text, p_expected uuid, p_new uuid) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE h host;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_host, 719));
    SELECT * INTO STRICT h FROM host WHERE id = p_host FOR UPDATE;
    IF p_expected IS NULL OR p_new IS NULL OR p_expected = p_new
       OR p_expected = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_new = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'distinct nonzero incarnation required';
    END IF;
    IF h.incarnation_id = p_new AND EXISTS (
        SELECT 1 FROM host_retired_incarnation
        WHERE host_id = p_host AND incarnation_id = p_expected AND successor_incarnation_id = p_new
    ) THEN RETURN h.peer_generation; END IF;
    IF h.incarnation_id IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'expected incarnation conflict'; END IF;
    PERFORM set_config('sandbox.claim_host', p_host, true);
    PERFORM set_config('sandbox.claim_incarnation', p_new::text, true);
    PERFORM set_config('sandbox.rebind_host', p_host, true);
    UPDATE host SET incarnation_id = p_new, status = 'provisioning', last_heartbeat_at = NULL,
        updated_at = now() WHERE id = p_host RETURNING peer_generation INTO h.peer_generation;
    DELETE FROM host_capability WHERE host_id = p_host;
    DELETE FROM host_pressure WHERE host_id = p_host;
    PERFORM set_config('sandbox.rebind_host', '', true);
    RETURN h.peer_generation;
END;
$$;

ALTER TABLE host_identity_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_retired_incarnation ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_retired_address ENABLE ROW LEVEL SECURITY;
