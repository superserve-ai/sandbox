-- RBAC Phase 2: indexes for permission and audit lookups.
--
-- These are additive only and keep phase 1 semantics intact.

CREATE INDEX IF NOT EXISTS idx_user_role_assignments_team_lookup
    ON user_role_assignments(user_id, team_id)
    WHERE scope_type = 'team' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_role_assignments_platform_lookup
    ON user_role_assignments(user_id)
    WHERE scope_type = 'platform' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission
    ON role_permissions(permission_id);
