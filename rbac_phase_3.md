# RBAC Phase 3

## What Changed

- Added customer-facing RBAC guards for sandbox, template, secret, and billing pricing handlers.
- Kept the Phase 1 and Phase 2 migrations unchanged.
- Added a small API-local authorization helper in `internal/api/rbac_phase3.go`.
- Added phase-specific integration tests for allow/deny behavior.

## Permission Map

- `settings:read`:
  - list sandboxes
  - view sandbox details without sandbox access tokens
  - view templates
  - list template builds and logs
  - view secrets and secret audit/sandbox usage
  - view sandbox network logs
- `settings:write`:
  - create, resume, activate, pause, patch, and delete sandboxes
  - receive sandbox access tokens from sandbox detail responses
  - list sandbox files when the handler may transparently resume the sandbox
  - attach and detach sandbox secrets
  - create and delete templates
  - create and cancel template builds
  - create, rotate, and delete secrets
- `billing:read`:
  - team billing pricing
- `users:read` / `users:write`:
  - reserved for Phase 2 user and role management APIs, not sandbox lifecycle control

## Access Matrix Decision

Phase 3 intentionally uses `settings:*` as the customer-facing resource-management permission family for sandboxes, templates, secrets, secret audit, and sandbox network logs. This keeps the rollout small and matches the predefined Phase 1 roles, but it has important visible behavior:

- `billing_admin` and `user_admin` do not receive `settings:read`, so they cannot list or inspect sandbox, template, or secret surfaces unless they are also granted a settings-capable role.
- `viewer` receives `settings:read`, so viewers can read sandbox/template metadata, secret metadata, secret audit usage, sandbox secret bindings, and sandbox network logs.
- Viewers cannot receive sandbox access tokens from sandbox detail responses and cannot call write paths that create, mutate, resume, pause, or delete resources.

If the product needs narrower visibility later, split `settings:*` into resource-specific permissions such as `sandboxes:*`, `templates:*`, and `secrets:*` in a follow-up phase instead of changing this rollout in place.

## Notes

- Keys without a creator are denied on protected endpoints because the RBAC layer cannot verify the actor.
- Team owner fixtures now back the main integration helpers so the existing high-risk endpoint tests continue to exercise valid access paths.
- No new schema was required for this phase.

## Remaining Work

- Add any future platform-admin-only handlers behind the same explicit permission model.
- Introduce platform session middleware when the product exposes platform-facing endpoints.
