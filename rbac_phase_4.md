# RBAC Phase 4

## What Changed

- Added `GET /teams/:team_id/management` as the customer UI read model for team member and role management.
- The endpoint returns team members, role assignments when the actor has `roles:read`, and backend-derived capability flags for customer UI controls.
- Mutation options are omitted for read-only actors, so viewers can inspect team membership without seeing invite/deactivate/role-assignment controls.
- Existing Phase 2 mutation endpoints remain the only write path:
  - `POST /teams/:team_id/members`
  - `DELETE /teams/:team_id/members/:user_id`
  - `POST /teams/:team_id/roles`
  - `DELETE /teams/:team_id/roles/:assignment_id`
- No Phase 1 schema changes were made.
- Phase 3 sandbox/template/secret/billing API protections are unchanged.

## Customer Route Behavior

`GET /teams/:team_id/management` is authenticated by the customer API key and requires the path `team_id` to match the authenticated team. It does not read or trust `X-Actor-User-Id`; the actor is derived from the API key creator in the request context.

The response includes:

- `members`: all memberships for the authenticated team, including `active`, `inactive`, and `invited` statuses.
- `assignments`: role assignment history only when the actor has `roles:read`; otherwise an empty array.
- `capabilities`: booleans derived from backend RBAC checks (`users:write`, `roles:read`, `roles:write`). These are UI hints, not authorization decisions.
- `mutation_options`: omitted unless the actor has at least one mutation capability. When present, it includes valid membership statuses and, for role writers, assignable team role names loaded from the database.

## Security Notes

- Viewers receive no mutation options and all mutation capability flags are false.
- Customer UI must still call the Phase 2 mutation endpoints for writes; those handlers remain authoritative for 403, 404, 409, last-owner protection, inactive/invited-member handling, and privileged reactivation checks.
- Internal platform recovery and platform team administration remain under `/internal/...`, protected by internal auth and platform permissions.
- The customer summary endpoint never exposes platform actor headers, sandbox access tokens, or users from other teams.

## Testing

- Added integration coverage for team owner versus viewer management responses.
- Added a cross-team access assertion for the new customer read model.

## OpenAPI

- `GET /teams/:team_id/management` is documented in `api/openapi.yaml`.
- The documented response shape is `TeamManagementResponse`. this endpoint should stay customer-facing only. Do not add `/internal/teams/{team_id}/management`.
