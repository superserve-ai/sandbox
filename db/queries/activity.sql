-- name: CreateActivity :one
INSERT INTO activity (sandbox_id, team_id, actor_id, category, action, status, sandbox_name, duration_ms, error, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: ListActivityBySandbox :many
SELECT * FROM activity
WHERE sandbox_id = $1
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
