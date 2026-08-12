-- name: RecordSandboxBackupGeneration :execrows
-- Idempotent by construction: reports are delivered at least once from
-- the host's outbox. A conflict refreshes completed_at only when the
-- report carries a strictly newer verification (an unchanged re-pause
-- re-verifies the same content-addressed generation later, and
-- freshness checks must see the current pause as covered), so an exact
-- redelivery affects zero rows.
INSERT INTO backup_generation (sandbox_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (sandbox_id, bucket, generation) WHERE sandbox_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(), files = excluded.files
WHERE excluded.completed_at > backup_generation.completed_at;

-- name: RecordTemplateBackupGeneration :execrows
-- Template variant of RecordSandboxBackupGeneration; the two exist
-- because each conflict target must name its own partial unique index.
INSERT INTO backup_generation (template_id, build_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (template_id, build_id, bucket, generation) WHERE template_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(), files = excluded.files
WHERE excluded.completed_at > backup_generation.completed_at;

-- name: LatestSandboxBackup :one
-- Freshness bounds future timestamps at read instead of rewriting them
-- at insert: completed_at is stored exactly as the host verified it, so
-- redeliveries stay idempotent under the strictly-newer upsert guard and
-- the host's own ordering survives. A skewed-ahead clock's rows cap at
-- now() for ranking (they cannot outrank indefinitely), the raw
-- timestamp breaks ties preserving the host's relative order, and the
-- true order re-emerges as wall time passes the stamps.
SELECT generation, bucket, completed_at
FROM backup_generation
WHERE sandbox_id = $1
ORDER BY LEAST(completed_at, now()) DESC, completed_at DESC
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
