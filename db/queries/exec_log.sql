-- name: CreateExecLog :one
INSERT INTO exec_log (vm_id, command)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateExecLog :exec
UPDATE exec_log
SET exit_code = $2, completed_at = $3
WHERE id = $1;

-- name: ListExecLogByVM :many
SELECT * FROM exec_log
WHERE vm_id = $1
ORDER BY started_at DESC;
