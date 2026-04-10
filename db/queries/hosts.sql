-- name: GetHost :one
SELECT * FROM host WHERE id = $1;

-- name: ListActiveHosts :many
SELECT * FROM host
WHERE status = 'active'
ORDER BY created_at ASC;

-- name: ListHosts :many
SELECT * FROM host
ORDER BY created_at ASC;

-- name: CreateHost :one
INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateHostStatus :exec
UPDATE host
SET status = $2, updated_at = now()
WHERE id = $1;

-- name: UpdateHostHeartbeat :exec
UPDATE host
SET last_heartbeat_at = now(), updated_at = now()
WHERE id = $1;
