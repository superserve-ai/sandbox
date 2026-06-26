# RBAC Phase 1 Notes

## Schema Added

- `team_memberships` to track active/inactive/invited membership state per user and team.
- Users may belong to multiple teams.
- `roles` with a `scope_type` of `platform` or `team`.
- `permissions` as a global permission catalog.
- `role_permissions` as the join table between roles and permissions.
- `user_role_assignments` for scoped role grants with explicit platform/team scope.
- `audit_logs` as an append-only event log foundation with database-level UPDATE/DELETE protection.

## Seed Data Added

- Roles:
  - `platform_admin`
  - `team_owner`
  - `team_admin`
  - `billing_admin`
  - `user_admin`
  - `viewer`
- Permissions:
  - `billing:read`
  - `billing:write`
  - `users:read`
  - `users:write`
  - `roles:read`
  - `roles:write`
  - `settings:read`
  - `settings:write`
  - `audit_logs:read`
  - `platform:teams:read`
  - `platform:team_users:write`
  - `platform:team_roles:write`
  - `platform:billing:write`
- Role-to-permission mappings follow the phase-1 brief.

## Backfill Behavior

- Legacy `team_member` rows are copied into `team_memberships` as active memberships.
- Legacy users may appear in multiple teams, and the migration preserves every membership row.
- Existing single-user teams are granted `team_owner`.
- If a legacy row explicitly looks like an owner/admin, that legacy hint is used after the single-member owner case.
- If a team has multiple members and no explicit owner hint, the earliest legacy member by `joined_at` and profile ID is granted `team_owner`; remaining members fall back to `viewer` unless their legacy role maps to `team_admin`.
- Platform admin is never auto-granted.
- The orphan check is scoped to profiles represented in legacy `team_member`; profiles without a legacy membership are left for a later explicit user-state cleanup.

## Assumptions

- Existing user-to-team relationships that should be active are represented in `team_member`.
- The schema allows a user to hold active memberships in multiple teams.
- The new RBAC tables are internal and will be accessed by the service role in later phases.
- RLS is intentionally fail-closed in this migration. Customer-facing policies are deferred until the application has explicit RBAC-aware access paths.

## Ambiguity

- If a team has multiple members and no legacy owner/admin hint, ownership is ambiguous.
- In that case the migration chooses a deterministic fallback owner using earliest `joined_at`, then profile ID.

## Team Model

- New signup may create a personal/default team.
- Joining another team should not delete or inactivate the personal team.
- Resources remain scoped to the team where they were created.
- Future UI/session work needs explicit team selection and current-team handling.

## Manual Platform Admin Bootstrap

Run a one-time SQL grant after choosing the user:

```sql
INSERT INTO user_role_assignments (user_id, role_id, scope_type, granted_by)
SELECT $USER_ID, r.id, 'platform', NULL
FROM roles r
WHERE r.name = 'platform_admin';
```

## Delete Semantics

RBAC tables intentionally use `NO ACTION` foreign keys for `profile`, `team`, and role assignment references. Normal lifecycle should use team/member inactive states and role revocation rather than hard deletes. This preserves membership, role, and audit context.

If a service-role path hard-deletes a membership row, the database revokes that user's active team-scoped role assignments for the deleted membership. Membership `team_id` and `user_id` are immutable; moving a user requires creating a new membership rather than rewriting the old row.

## Phase 2 Leftovers

- Authorization helpers.
- Endpoint/middleware enforcement.
- UI for customer role management.
- Billing authorization enforcement.
- Step-up authentication.
- Custom roles.
