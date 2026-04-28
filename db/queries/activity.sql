-- name: CreateActivity :one
-- Generic insert: caller sets resource_type + the matching FK (sandbox_id or
-- template_id). The CHECK constraint on the table enforces that exactly one
-- FK is populated and matches resource_type.
INSERT INTO activity (
  sandbox_id, template_id, resource_type,
  team_id, actor_id,
  category, action, status,
  sandbox_name, duration_ms, error, metadata
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: ListActivityBySandbox :many
SELECT * FROM activity
WHERE sandbox_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: ListActivityByTemplate :many
SELECT * FROM activity
WHERE template_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: ListActivityByTeam :many
SELECT * FROM activity
WHERE team_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: ListActivityByCategory :many
SELECT * FROM activity
WHERE team_id = $1 AND category = $2
ORDER BY created_at DESC
LIMIT $3;
