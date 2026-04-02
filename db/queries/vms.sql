-- name: CreateVM :one
INSERT INTO vms (name, status, vcpu_count, mem_size_mib, ip_address, host_id, parent_vm_id, forked_from_checkpoint_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetVM :one
SELECT * FROM vms
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListVMs :many
SELECT * FROM vms
WHERE deleted_at IS NULL
ORDER BY created_at DESC;

-- name: ListVMsByStatus :many
SELECT * FROM vms
WHERE status = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: UpdateVMStatus :exec
UPDATE vms
SET status = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateVMIP :exec
UPDATE vms
SET ip_address = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: SoftDeleteVM :exec
UPDATE vms
SET deleted_at = now(), status = 'dead', updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetVMsByParent :many
SELECT * FROM vms
WHERE parent_vm_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: GetVMStatus :one
SELECT status FROM vms
WHERE id = $1 AND deleted_at IS NULL;

-- name: VMExists :one
SELECT EXISTS(SELECT 1 FROM vms WHERE id = $1 AND deleted_at IS NULL);

-- name: UpdateVMStatusAndIP :exec
UPDATE vms
SET status = $2, ip_address = $3, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: PauseVM :exec
UPDATE vms
SET status = 'paused', snapshot_path = $2, mem_file_path = $3, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: ResumeVM :exec
UPDATE vms
SET status = 'running', ip_address = $2, snapshot_path = NULL, mem_file_path = NULL, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetVMPauseState :one
SELECT snapshot_path, mem_file_path FROM vms
WHERE id = $1 AND deleted_at IS NULL;
