-- Hosted QM machine identity is deliberately separate from profiles and API
-- keys.  The provisioning owner stores credential material elsewhere; this
-- schema contains only durable references and revocation state.
CREATE TABLE machine_principal (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id            uuid NOT NULL REFERENCES team(id),
    hosted_tenant_id   uuid NOT NULL,
    status             text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'deleted')),
    generation         bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    approved_template_id uuid,
    restore_until      timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (hosted_tenant_id),
    UNIQUE (id, team_id)
);

CREATE TABLE machine_credential (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id         uuid NOT NULL REFERENCES machine_principal(id),
    lineage_id           uuid NOT NULL,
    state                text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'revoked')),
    expires_at           timestamptz NOT NULL,
    revocation_generation bigint NOT NULL CHECK (revocation_generation > 0),
    permissions          text[] NOT NULL DEFAULT '{}',
    audience             text NOT NULL,
    issued_at            timestamptz NOT NULL DEFAULT now(),
    revoked_at           timestamptz,
    UNIQUE (id, principal_id),
    CHECK (cardinality(permissions) > 0)
);

CREATE INDEX machine_credential_active_idx
    ON machine_credential(principal_id, state, expires_at)
    WHERE state = 'active';
CREATE INDEX machine_credential_lineage_idx
    ON machine_credential(lineage_id);

CREATE OR REPLACE FUNCTION prevent_machine_credential_reassignment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.principal_id IS DISTINCT FROM NEW.principal_id
       OR OLD.lineage_id IS DISTINCT FROM NEW.lineage_id THEN
        RAISE EXCEPTION 'machine credential lineage is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER machine_credential_lineage_immutable
    BEFORE UPDATE ON machine_credential
    FOR EACH ROW EXECUTE FUNCTION prevent_machine_credential_reassignment();

CREATE OR REPLACE FUNCTION prevent_machine_principal_reassignment() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.team_id IS DISTINCT FROM NEW.team_id
       OR OLD.hosted_tenant_id IS DISTINCT FROM NEW.hosted_tenant_id THEN
        RAISE EXCEPTION 'machine principal association is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER machine_principal_association_immutable
    BEFORE UPDATE ON machine_principal
    FOR EACH ROW EXECUTE FUNCTION prevent_machine_principal_reassignment();

-- Keep ownership in a companion table so existing human queries using
-- `sandbox.*` retain their result shape.  Machine creation writes the sandbox
-- and this row in one statement/transaction; ordinary historical rows remain
-- absent and therefore fail closed for machine callers.
CREATE TABLE sandbox_machine_owner (
    sandbox_id         uuid PRIMARY KEY REFERENCES sandbox(id) ON DELETE CASCADE,
    owner_principal_id uuid NOT NULL,
    team_id            uuid NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (owner_principal_id, team_id)
        REFERENCES machine_principal(id, team_id),
    UNIQUE (sandbox_id, team_id)
);

CREATE INDEX sandbox_machine_owner_idx
    ON sandbox_machine_owner(owner_principal_id, team_id, sandbox_id);

-- An ownership row is immutable and cannot be adopted by a second principal.
CREATE OR REPLACE FUNCTION prevent_machine_owner_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.sandbox_id IS DISTINCT FROM NEW.sandbox_id
       OR OLD.owner_principal_id IS DISTINCT FROM NEW.owner_principal_id
       OR OLD.team_id IS DISTINCT FROM NEW.team_id THEN
        RAISE EXCEPTION 'sandbox machine owner is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sandbox_machine_owner_immutable
    BEFORE UPDATE ON sandbox_machine_owner
    FOR EACH ROW EXECUTE FUNCTION prevent_machine_owner_change();

-- EnsurePrincipal is idempotent but never reassigns a tenant to another team.
CREATE OR REPLACE FUNCTION ensure_machine_principal(
    p_team_id uuid, p_hosted_tenant_id uuid, p_template_id uuid DEFAULT NULL
) RETURNS machine_principal
LANGUAGE plpgsql AS $$
DECLARE result machine_principal;
BEGIN
    INSERT INTO machine_principal(team_id, hosted_tenant_id, approved_template_id)
    VALUES (p_team_id, p_hosted_tenant_id, p_template_id)
    ON CONFLICT (hosted_tenant_id) DO UPDATE
      SET approved_template_id = COALESCE(machine_principal.approved_template_id, EXCLUDED.approved_template_id),
          updated_at = now()
      WHERE machine_principal.team_id = EXCLUDED.team_id
    RETURNING * INTO result;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'machine principal tenant/team association mismatch' USING ERRCODE = '42501';
    END IF;
    RETURN result;
END;
$$;

-- Deletion/restore fencing is bounded to the lifecycle owner's recovery
-- window. A restore outside this window must create a new tenant identity.
CREATE OR REPLACE FUNCTION disable_machine_principal(p_id uuid) RETURNS machine_principal
LANGUAGE plpgsql AS $$
DECLARE result machine_principal;
BEGIN
    UPDATE machine_principal
    SET status='disabled', generation=generation+1,
        restore_until=now() + interval '7 days', updated_at=now()
    WHERE id=p_id AND status='active'
    RETURNING * INTO result;
    IF NOT FOUND THEN RAISE EXCEPTION 'machine principal is not active' USING ERRCODE='42501'; END IF;
    UPDATE machine_credential SET state='revoked', revoked_at=COALESCE(revoked_at,now())
    WHERE principal_id=p_id AND state='active';
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION restore_machine_principal(p_id uuid) RETURNS machine_principal
LANGUAGE plpgsql AS $$
DECLARE result machine_principal;
BEGIN
    UPDATE machine_principal
    SET status='active', generation=generation+1, restore_until=NULL, updated_at=now()
    WHERE id=p_id AND status='disabled' AND restore_until IS NOT NULL AND restore_until > now()
    RETURNING * INTO result;
    IF NOT FOUND THEN RAISE EXCEPTION 'machine principal restore window expired' USING ERRCODE='42501'; END IF;
    RETURN result;
END;
$$;

-- Runtime credentials cannot call these functions: database grants remain
-- service-role-only and the control plane supplies the authorization fence.
REVOKE ALL ON machine_principal, machine_credential, sandbox_machine_owner FROM PUBLIC;
REVOKE ALL ON FUNCTION ensure_machine_principal(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION disable_machine_principal(uuid), restore_machine_principal(uuid) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT SELECT, INSERT, UPDATE ON machine_principal, machine_credential, sandbox_machine_owner TO service_role;
        GRANT EXECUTE ON FUNCTION ensure_machine_principal(uuid, uuid, uuid) TO service_role;
        GRANT EXECUTE ON FUNCTION disable_machine_principal(uuid), restore_machine_principal(uuid) TO service_role;
    END IF;
END;
$$;
