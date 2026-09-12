-- name: SetQMTeamScope :exec
-- Declares the team every qm.* query in this transaction is scoped to.
-- qm_api's row-level policies key on this setting; the third argument makes
-- it transaction-local so it cannot leak across pooled connections.
SELECT set_config('qm.team_id', sqlc.arg(team_id)::text, true);

-- name: CreateQMTenant :one
INSERT INTO qm.tenants (
    team_id, slug, org_name, admin_email, sign_in, model_provider, harness, created_by
)
VALUES (
    $1, $2, $3, $4, $5, $6, COALESCE(sqlc.narg('harness')::text, 'pi'), sqlc.narg('created_by')
)
RETURNING *;

-- name: GetQMTenant :one
SELECT * FROM qm.tenants
WHERE id = $1 AND team_id = $2;

-- name: GetQMTenantBySlug :one
SELECT * FROM qm.tenants
WHERE slug = $1 AND team_id = $2;

-- name: ListQMTenantsByTeam :many
SELECT * FROM qm.tenants
WHERE team_id = $1 AND status <> 'deleted'
ORDER BY created_at DESC;

-- name: UpdateQMTenantStatus :one
-- deleted is terminal: a racing worker must not resurrect a retired tenant.
UPDATE qm.tenants
SET status = $3, updated_at = now()
WHERE id = $1 AND team_id = $2 AND status <> 'deleted'
RETURNING *;

-- name: UpdateQMTenantResources :one
-- Records what provisioning created. Every field is optional so each
-- provisioning step can persist only what it produced.
UPDATE qm.tenants
SET public_url         = COALESCE(sqlc.narg('public_url'), public_url),
    image_tag          = COALESCE(sqlc.narg('image_tag'), image_tag),
    cloud_run_service  = COALESCE(sqlc.narg('cloud_run_service'), cloud_run_service),
    db_name            = COALESCE(sqlc.narg('db_name'), db_name),
    bucket_name        = COALESCE(sqlc.narg('bucket_name'), bucket_name),
    service_account    = COALESCE(sqlc.narg('service_account'), service_account),
    sandbox_api_key_id = COALESCE(sqlc.narg('sandbox_api_key_id'), sandbox_api_key_id),
    updated_at         = now()
WHERE id = $1 AND team_id = $2 AND status <> 'deleted'
RETURNING *;

-- name: SoftDeleteQMTenant :one
UPDATE qm.tenants
SET status = 'deleted', updated_at = now()
WHERE id = $1 AND team_id = $2 AND status <> 'deleted'
RETURNING *;

-- name: IsQMSlugAvailable :one
-- Answers across every team (see qm.slug_available); the UNIQUE constraint
-- on slug remains the authoritative guard at insert time.
SELECT qm.slug_available($1)::boolean AS available;

-- name: SetQMTenantSecretRef :exec
INSERT INTO qm.tenant_secrets (tenant_id, name, secret_ref)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, name) DO UPDATE SET secret_ref = EXCLUDED.secret_ref;

-- name: GetQMTenantSecretRef :one
SELECT secret_ref FROM qm.tenant_secrets
WHERE tenant_id = $1 AND name = $2;

-- name: ListQMTenantSecretRefs :many
SELECT * FROM qm.tenant_secrets
WHERE tenant_id = $1
ORDER BY name;

-- name: DeleteQMTenantSecretRef :exec
DELETE FROM qm.tenant_secrets
WHERE tenant_id = $1 AND name = $2;
