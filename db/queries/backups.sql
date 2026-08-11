-- name: RecordBackupGeneration :execrows
-- Idempotent by construction: reports are delivered at least once from
-- the host's outbox, and the partial unique indexes turn redeliveries
-- into no-ops. Returns the number of rows written (0 = already known).
INSERT INTO backup_generation (sandbox_id, template_id, build_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT DO NOTHING;

-- name: LatestSandboxBackup :one
SELECT generation, bucket, completed_at
FROM backup_generation
WHERE sandbox_id = $1
ORDER BY completed_at DESC
LIMIT 1;

-- name: LockSandboxRow :one
-- Serializes the backup report's snapshot-size sync against FinalizePause,
-- which takes the same row lock: the vmstate match below stays true for
-- the duration of the transaction or the sync is skipped.
SELECT id FROM sandbox WHERE id = $1 FOR UPDATE;

-- name: LatestSnapshotVMState :one
-- The sandbox's newest snapshot row and the vmstate digest its pause-time
-- manifest recorded. The digest is the join point between a backup report
-- and the snapshot row it describes: pause-time manifests are
-- vmstate-only, so a matching vmstate sha proves the report covers
-- exactly this pause.
SELECT s.id AS snapshot_id,
       COALESCE((SELECT am.sha256 FROM artifact_manifest am
         WHERE am.snapshot_id = s.id AND am.file_name = 'vmstate.snap'), '') AS vmstate_sha256
FROM snapshot s
WHERE s.sandbox_id = $1
ORDER BY s.generation DESC
LIMIT 1;

-- name: SetSnapshotSizeBytes :exec
UPDATE snapshot SET size_bytes = $2 WHERE id = $1;
