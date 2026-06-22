# RBAC Phase 2b

## Endpoints Added

- `GET /teams/:team_id/members`
- `POST /teams/:team_id/members`
- `DELETE /teams/:team_id/members/:user_id`
- `GET /teams/:team_id/roles`
- `POST /teams/:team_id/roles`
- `DELETE /teams/:team_id/roles/:assignment_id`
- `GET /internal/teams/:team_id/members`
- `POST /internal/teams/:team_id/members`
- `DELETE /internal/teams/:team_id/members/:user_id`
- `GET /internal/teams/:team_id/roles`
- `POST /internal/teams/:team_id/roles`
- `DELETE /internal/teams/:team_id/roles/:assignment_id`
- `POST /internal/teams/:team_id/recover`

## Permissions Enforced

- Customer team member reads require `users:read`
- Customer team member writes require `users:write`
- Customer role reads require `roles:read`
- Customer role writes require `roles:write`
- Internal team reads require `platform:teams:read`
- Internal team member writes require `platform:team_users:write`
- Internal team role writes require `platform:team_roles:write`

## Audit Events Written

- `team_member_added`
- `team_member_deactivated`
- `team_role_assigned`
- `team_role_revoked`
- `platform_team_member_added`
- `platform_team_member_deactivated`
- `platform_team_role_assigned`
- `platform_team_role_revoked`
- `platform_team_recovered`

## Platform Recovery Behavior

- Internal recovery requires the shared internal auth token and an explicit `X-Actor-User-Id` header.
- The actor must already hold explicit platform RBAC permissions.
- Recovery only proceeds when the team has no active owner.
- Recovery reactivates or creates membership for the target user and grants `team_owner`.

## Known Limitations

- The HTTP stack still does not expose Google SSO session claims to the platform RBAC handlers.
- Until that exists, internal platform actions are authenticated by the internal service token plus an explicit actor UUID header, and the handlers enforce explicit platform RBAC assignment in the database.
- Customer member add/remove and role assign/revoke remain backend-only; no UI flows were added.

## What Remains

- UI for customer team user management.
- UI for platform recovery.
- Phase 3 endpoint hardening and any remaining high-risk surfaces.
- A future session middleware path that can validate Google/Superserve claims directly in HTTP.
