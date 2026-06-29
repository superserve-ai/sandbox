# RBAC Phase 2

## What Changed

- Added `internal/authz` as the reusable RBAC helper layer.
- Added team-scoped and platform-scoped permission checks.
- Added platform-admin session eligibility validation for Google / `@superserve.ai` sessions.
- Added a transactional audit-log write helper for sensitive backend mutations.
- Enforced `billing:read` on `GET /billing/pricing`.
- Added RBAC lookup indexes for permission checks and role-permission joins.

## Enforcement Model

- Team checks require `team_id` and active `team_memberships` rows.
- Platform checks require `platform:*` permissions and active platform assignments.
- Revoked assignments do not grant access.
- Inactive memberships do not grant access.
- Platform admin sessions must be Google SSO, `@superserve.ai`, and verified when an email-verification claim is present.

## Assumptions

- Current HTTP requests only expose a user identity through `api_key.created_by`.
- There is no existing user-session middleware in this branch, so platform admin enforcement is implemented as a reusable helper rather than an active HTTP middleware.
- Billing-pricing requests are authorized via the API-key creator's team membership and team role.

## Remaining Phase 2 Work

- Wire the helper package into any future customer-facing team member / role-management handlers.
- Add a real session middleware before exposing platform-admin endpoints.
- Add platform recovery endpoints when the product surface exists.
- Add audit-log writes to the first sensitive mutation handlers once they exist.
## Rollout Prerequisite

Before enabling protected billing and team-management endpoints, every active API key that will call these endpoints must have `api_key.created_by` set to the profile that owns the key, and that profile must have an active membership in the key's team. Legacy keys without an actor are intentionally denied on protected endpoints rather than accepting caller-supplied actor headers.

