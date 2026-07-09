-- name: CreateActivity :one
-- Generic insert: caller sets resource_type + the matching FK (sandbox_id,
-- template_id, or secret_id with snapshot secret_name). The CHECK constraint
-- on the table enforces that the right field combo for each resource_type.
INSERT INTO activity (
  sandbox_id, template_id, secret_id, secret_name, resource_type,
  team_id, actor_id,
  category, action, status,
  sandbox_name, duration_ms, error, metadata
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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

-- name: ListActivityBySecret :many
SELECT * FROM activity
WHERE secret_id = $1 AND team_id = $2
ORDER BY created_at DESC
LIMIT $3;

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

-- name: ListActivityByTeamPaged :many
-- Paginated, filterable team activity list backing the console audit log.
--
-- Filters (all optional, AND'd): category equality, status equality (the
-- console sends status='error' for the Errors tab), a case-insensitive
-- substring across sandbox_name/secret_name/action/category, and a created_at
-- window. Sort is created_at only (asc via the guarded CASE, otherwise the
-- created_at DESC default + stable tiebreaker). A NULL @row_limit returns all
-- rows, preserving the pre-pagination "return everything" default so
-- unpaginated callers are unaffected.
SELECT * FROM activity
WHERE team_id = @team_id
  AND (sqlc.narg('category')::text IS NULL OR category = sqlc.narg('category')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('search')::text IS NULL
       OR sandbox_name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR secret_name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR action ILIKE '%' || sqlc.narg('search')::text || '%'
       OR category ILIKE '%' || sqlc.narg('search')::text || '%')
  AND (sqlc.narg('created_after')::timestamptz IS NULL OR created_at >= sqlc.narg('created_after')::timestamptz)
  AND (sqlc.narg('created_before')::timestamptz IS NULL OR created_at <= sqlc.narg('created_before')::timestamptz)
ORDER BY
  CASE WHEN @sort_by::text = 'created_at' AND @sort_dir::text = 'asc' THEN created_at END ASC,
  created_at DESC,
  -- id is a stable final tiebreaker so rows sharing a created_at (bulk events
  -- written in one operation) keep a deterministic order across page boundaries.
  id DESC
LIMIT sqlc.narg('row_limit')::bigint
OFFSET COALESCE(sqlc.narg('row_offset')::bigint, 0);

-- name: CountActivityByTeamPaged :one
-- Total rows matching the same filters as ListActivityByTeamPaged (ignoring
-- pagination). Backs the X-Total-Count response header.
SELECT COUNT(*) FROM activity
WHERE team_id = @team_id
  AND (sqlc.narg('category')::text IS NULL OR category = sqlc.narg('category')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('search')::text IS NULL
       OR sandbox_name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR secret_name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR action ILIKE '%' || sqlc.narg('search')::text || '%'
       OR category ILIKE '%' || sqlc.narg('search')::text || '%')
  AND (sqlc.narg('created_after')::timestamptz IS NULL OR created_at >= sqlc.narg('created_after')::timestamptz)
  AND (sqlc.narg('created_before')::timestamptz IS NULL OR created_at <= sqlc.narg('created_before')::timestamptz);
