-- name: CreateActivity :exec
INSERT INTO activity (vm_id, category, action, metadata)
VALUES ($1, $2, $3, $4);
