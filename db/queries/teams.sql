-- name: CreateTeam :one
INSERT INTO team (name)
VALUES ($1)
RETURNING *;

-- name: GetTeam :one
SELECT * FROM team
WHERE id = $1;

-- name: GetTeamByName :one
SELECT * FROM team
WHERE name = $1;

-- name: ListTeams :many
SELECT * FROM team
ORDER BY created_at DESC;

-- name: UpdateTeamName :one
UPDATE team
SET name = $2, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteTeam :exec
DELETE FROM team
WHERE id = $1;

-- name: GetTeamBuildConcurrency :one
-- Per-team max concurrent template builds. Used by the build supervisor.
SELECT build_concurrency FROM team WHERE id = $1;
