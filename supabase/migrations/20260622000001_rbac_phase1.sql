-- RBAC Phase 1: schema foundation, seed data, and legacy backfill.
--
-- This migration adds scoped roles/permissions, membership tracking, and an
-- append-only audit log table. It does not add application-level enforcement.

CREATE TABLE IF NOT EXISTS team_memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id    uuid NOT NULL REFERENCES team(id),
    user_id    uuid NOT NULL REFERENCES profile(id),
    status     text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT team_memberships_status_check
        CHECK (status IN ('active', 'inactive', 'invited'))
);

CREATE INDEX IF NOT EXISTS idx_team_memberships_team_user
    ON team_memberships(team_id, user_id);
CREATE INDEX IF NOT EXISTS idx_team_memberships_user
    ON team_memberships(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_team_memberships_active_team_user_unique
    ON team_memberships(team_id, user_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    scope_type  text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT roles_name_nonempty CHECK (name <> ''),
    CONSTRAINT roles_scope_type_check CHECK (scope_type IN ('platform', 'team'))
);

DO $$
BEGIN
    ALTER TABLE roles
        ADD CONSTRAINT roles_id_scope_unique UNIQUE (id, scope_type);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS permissions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT permissions_name_nonempty CHECK (name <> '')
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id  uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_role_assignments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES profile(id),
    role_id     uuid NOT NULL REFERENCES roles(id),
    scope_type  text NOT NULL,
    team_id     uuid REFERENCES team(id),
    granted_by  uuid REFERENCES profile(id),
    granted_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT user_role_assignments_scope_type_check
        CHECK (scope_type IN ('platform', 'team')),
    CONSTRAINT user_role_assignments_scope_team_check
        CHECK (
            (scope_type = 'platform' AND team_id IS NULL)
            OR (scope_type = 'team' AND team_id IS NOT NULL)
        )
);

DO $$
BEGIN
    ALTER TABLE user_role_assignments
        ADD CONSTRAINT user_role_assignments_role_scope_fk
        FOREIGN KEY (role_id, scope_type)
        REFERENCES roles(id, scope_type);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_user_role_assignments_user_scope_team
    ON user_role_assignments(user_id, scope_type, team_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_team
    ON user_role_assignments(team_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_role
    ON user_role_assignments(role_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_revoked
    ON user_role_assignments(revoked_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_role_assignments_platform_active_unique
    ON user_role_assignments(user_id, role_id)
    WHERE revoked_at IS NULL AND scope_type = 'platform';
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_role_assignments_team_active_unique
    ON user_role_assignments(user_id, role_id, team_id)
    WHERE revoked_at IS NULL AND scope_type = 'team';

CREATE OR REPLACE FUNCTION enforce_team_role_active_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.scope_type = 'team' AND NEW.revoked_at IS NULL THEN
        -- Lock the membership row while accepting the grant. This prevents a
        -- concurrent membership deactivation/delete from revoking only the
        -- assignments visible before this transaction commits.
        IF NOT EXISTS (
            SELECT 1
            FROM team_memberships m
            WHERE m.team_id = NEW.team_id
              AND m.user_id = NEW.user_id
              AND m.status = 'active'
            FOR UPDATE
        ) THEN
            RAISE EXCEPTION
                'active team role assignment requires active team membership for user % in team %',
                NEW.user_id,
                NEW.team_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_user_role_assignments_active_membership ON user_role_assignments;

CREATE TRIGGER trg_user_role_assignments_active_membership
    BEFORE INSERT OR UPDATE OF user_id, scope_type, team_id, revoked_at
    ON user_role_assignments
    FOR EACH ROW
    EXECUTE FUNCTION enforce_team_role_active_membership();

CREATE OR REPLACE FUNCTION prevent_team_membership_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.team_id IS DISTINCT FROM NEW.team_id
       OR OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION
            'team_memberships team_id and user_id are immutable; create a new membership instead';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_team_memberships_prevent_identity_update ON team_memberships;

CREATE TRIGGER trg_team_memberships_prevent_identity_update
    BEFORE UPDATE OF team_id, user_id
    ON team_memberships
    FOR EACH ROW
    EXECUTE FUNCTION prevent_team_membership_identity_update();

CREATE OR REPLACE FUNCTION revoke_team_role_assignments_on_membership_deactivation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE user_role_assignments
        SET revoked_at = COALESCE(revoked_at, now()),
            updated_at = now()
        WHERE scope_type = 'team'
          AND team_id = NEW.team_id
          AND user_id = NEW.user_id
          AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_team_memberships_revoke_assignments ON team_memberships;

CREATE TRIGGER trg_team_memberships_revoke_assignments
    AFTER UPDATE OF status
    ON team_memberships
    FOR EACH ROW
    EXECUTE FUNCTION revoke_team_role_assignments_on_membership_deactivation();

CREATE OR REPLACE FUNCTION revoke_team_role_assignments_on_membership_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE user_role_assignments
    SET revoked_at = COALESCE(revoked_at, now()),
        updated_at = now()
    WHERE scope_type = 'team'
      AND team_id = OLD.team_id
      AND user_id = OLD.user_id
      AND revoked_at IS NULL;

    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_team_memberships_revoke_assignments_on_delete ON team_memberships;

CREATE TRIGGER trg_team_memberships_revoke_assignments_on_delete
    AFTER DELETE
    ON team_memberships
    FOR EACH ROW
    EXECUTE FUNCTION revoke_team_role_assignments_on_membership_delete();

CREATE TABLE IF NOT EXISTS audit_logs (
    id             bigserial PRIMARY KEY,
    actor_user_id  uuid,
    target_user_id uuid,
    team_id        uuid,
    event_type     text NOT NULL,
    old_value      jsonb,
    new_value      jsonb,
    metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT audit_logs_event_type_nonempty CHECK (event_type <> '')
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_team_created_at
    ON audit_logs(team_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created_at
    ON audit_logs(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target_created_at
    ON audit_logs(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_created_at
    ON audit_logs(event_type, created_at DESC);

CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; update/delete is not allowed';
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_logs_prevent_mutation ON audit_logs;

CREATE TRIGGER trg_audit_logs_prevent_mutation
    BEFORE UPDATE OR DELETE
    ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_mutation();

-- Fail closed until Phase 2 adds service-owned access paths and explicit
-- policies. The API uses the service role for these internal RBAC tables.
ALTER TABLE public.team_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.permissions      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs       ENABLE ROW LEVEL SECURITY;

INSERT INTO roles (name, scope_type, description)
VALUES
    ('platform_admin', 'platform', 'Superserve internal platform administrator'),
    ('team_owner', 'team', 'Team owner with full team-scoped privileges'),
    ('team_admin', 'team', 'Team administrator with delegated management privileges'),
    ('billing_admin', 'team', 'Team billing administrator'),
    ('user_admin', 'team', 'Team user administrator'),
    ('viewer', 'team', 'Read-only team member')
ON CONFLICT (name) DO UPDATE
SET scope_type = EXCLUDED.scope_type,
    description = EXCLUDED.description,
    updated_at = now();

INSERT INTO permissions (name, description)
VALUES
    ('billing:read', 'Read billing state'),
    ('billing:write', 'Mutate billing state'),
    ('users:read', 'Read team users'),
    ('users:write', 'Mutate team users'),
    ('roles:read', 'Read roles and role assignments'),
    ('roles:write', 'Mutate roles and role assignments'),
    ('settings:read', 'Read team settings'),
    ('settings:write', 'Mutate team settings'),
    ('audit_logs:read', 'Read audit logs'),
    ('platform:teams:read', 'Read platform teams'),
    ('platform:team_users:write', 'Mutate platform team users'),
    ('platform:team_roles:write', 'Mutate platform team roles'),
    ('platform:billing:write', 'Mutate platform billing state')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description,
    updated_at = now();

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON (
      (r.name = 'platform_admin' AND p.name IN (
          'platform:teams:read',
          'platform:team_users:write',
          'platform:team_roles:write',
          'platform:billing:write',
          'billing:read',
          'billing:write',
          'users:read',
          'users:write',
          'roles:read',
          'roles:write',
          'settings:read',
          'settings:write',
          'audit_logs:read'
      ))
      OR (r.name = 'team_owner' AND p.name IN (
          'billing:read',
          'billing:write',
          'users:read',
          'users:write',
          'roles:read',
          'roles:write',
          'settings:read',
          'settings:write',
          'audit_logs:read'
      ))
      OR (r.name = 'team_admin' AND p.name IN (
          'users:read',
          'users:write',
          'roles:read',
          'settings:read',
          'settings:write',
          'billing:read'
      ))
      OR (r.name = 'billing_admin' AND p.name IN (
          'billing:read',
          'billing:write'
      ))
      OR (r.name = 'user_admin' AND p.name IN (
          'users:read',
          'users:write',
          'roles:read'
      ))
      OR (r.name = 'viewer' AND p.name IN (
          'billing:read',
          'users:read',
          'settings:read'
      ))
  )
ON CONFLICT DO NOTHING;

-- Backfill memberships from the legacy team_member table. Users may belong to
-- multiple teams, so every legacy row is preserved as an active membership.
INSERT INTO team_memberships (team_id, user_id, status, created_at, updated_at)
SELECT
    tm.team_id,
    tm.profile_id,
    'active',
    COALESCE(tm.joined_at, now()),
    COALESCE(tm.joined_at, now())
FROM team_member tm
WHERE NOT EXISTS (
    SELECT 1
    FROM team_memberships m
    WHERE m.team_id = tm.team_id
      AND m.user_id = tm.profile_id
      AND m.status = 'active'
);

WITH legacy_memberships AS (
    SELECT
        tm.team_id,
        tm.profile_id AS user_id,
        COALESCE(tm.joined_at, now()) AS created_at,
        LOWER(COALESCE(tm.role, '')) AS legacy_role,
        BOOL_OR(LOWER(COALESCE(tm.role, '')) IN ('owner', 'team_owner'))
            OVER (PARTITION BY tm.team_id) AS has_explicit_owner,
        ROW_NUMBER() OVER (
            PARTITION BY tm.team_id
            ORDER BY COALESCE(tm.joined_at, 'infinity'::timestamptz), tm.profile_id
        ) AS owner_rank
    FROM team_member tm
)
INSERT INTO user_role_assignments (
    user_id, role_id, scope_type, team_id,
    granted_by, granted_at, revoked_at, created_at, updated_at
)
SELECT
    lm.user_id,
    r.id,
    'team',
    lm.team_id,
    NULL,
    lm.created_at,
    NULL,
    lm.created_at,
    lm.created_at
FROM legacy_memberships lm
    JOIN roles r
      ON r.scope_type = 'team'
     AND r.name = CASE
        WHEN lm.legacy_role IN ('owner', 'team_owner') THEN 'team_owner'
        WHEN NOT lm.has_explicit_owner AND lm.owner_rank = 1 THEN 'team_owner'
        WHEN lm.legacy_role IN ('admin', 'team_admin') THEN 'team_admin'
        ELSE 'viewer'
     END
WHERE NOT EXISTS (
    SELECT 1
    FROM user_role_assignments a
    WHERE a.user_id = lm.user_id
      AND a.role_id = r.id
      AND a.scope_type = 'team'
      AND a.team_id = lm.team_id
      AND a.revoked_at IS NULL
);

DO $$
DECLARE
    orphan_count integer;
BEGIN
    SELECT COUNT(*)
    INTO orphan_count
    FROM profile p
    WHERE EXISTS (
        SELECT 1
        FROM team_member tm
        WHERE tm.profile_id = p.id
    )
      AND NOT EXISTS (
        SELECT 1
        FROM team_memberships m
        WHERE m.user_id = p.id
          AND m.status = 'active'
    );

    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'rbac backfill failed: % legacy profile rows have no active team membership',
            orphan_count;
    END IF;
END $$;

-- Platform admin assignment remains explicit. A bootstrap admin can be
-- granted manually with an INSERT like:
--   INSERT INTO user_role_assignments (user_id, role_id, scope_type, granted_by)
--   SELECT $USER_ID, r.id, 'platform', NULL
--   FROM roles r
--   WHERE r.name = 'platform_admin';
