-- name: RecordSandboxBackupGeneration :execrows
-- Idempotent by construction: reports are delivered at least once from
-- the host's outbox. A conflict refreshes completed_at only when the
-- report carries a strictly newer verification (an unchanged re-pause
-- re-verifies the same content-addressed generation later, and
-- freshness checks must see the current pause as covered), so an exact
-- redelivery affects zero rows. The second refresh arm lets a corrected
-- clock repair its own damage: a stored future value (provably bogus,
-- it exceeds now()) yields to a sane incoming one, while redelivery of
-- either report matches neither arm and stays a no-op.
INSERT INTO backup_generation (sandbox_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (sandbox_id, bucket, generation) WHERE sandbox_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(), files = excluded.files
WHERE excluded.completed_at > backup_generation.completed_at
   OR (backup_generation.completed_at > now() AND excluded.completed_at <= now());

-- name: RecordTemplateBackupGeneration :execrows
-- Template variant of RecordSandboxBackupGeneration; the two exist
-- because each conflict target must name its own partial unique index.
INSERT INTO backup_generation (template_id, build_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (template_id, build_id, bucket, generation) WHERE template_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(), files = excluded.files
WHERE excluded.completed_at > backup_generation.completed_at
   OR (backup_generation.completed_at > now() AND excluded.completed_at <= now());

-- name: LatestSandboxBackup :one
-- Freshness bounds future timestamps at read instead of rewriting them
-- at insert: completed_at is stored exactly as the host verified it, so
-- redeliveries stay idempotent under the strictly-newer upsert guard.
-- The cap is reported_at, the server-side receive instant fixed at
-- insert: a skewed-ahead row ranks no later than when the control plane
-- actually learned of it, so any subsequently completed legitimate
-- generation outranks it (a now() cap would keep tying the skewed row
-- to the query clock and it would win every read until wall time passed
-- the stamp). The returned completed_at is bounded the same way so
-- freshness consumers never see an unbounded future value; the raw
-- column breaks ranking ties, preserving the host's own order.
SELECT generation, bucket, LEAST(completed_at, reported_at)::timestamptz AS completed_at
FROM backup_generation
WHERE sandbox_id = $1
ORDER BY LEAST(completed_at, reported_at) DESC, completed_at DESC
LIMIT 1;

-- name: LockSandboxRow :one
-- Serializes the backup report's snapshot-size sync against FinalizePause,
-- which takes the same row lock: the vmstate match below stays true for
-- the duration of the transaction or the sync is skipped. Status rides
-- along because 'pausing' marks a finalize that has not committed yet:
-- a fast upload's report arriving in that window must retry rather than
-- silently miss its size sync.
SELECT id, status, updated_at FROM sandbox WHERE id = $1 FOR UPDATE;

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
