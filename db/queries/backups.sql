-- name: RecordSandboxBackupGeneration :execrows
-- Idempotent by construction: reports are delivered at least once from
-- the host's outbox. A conflict refreshes completed_at only when the
-- report carries a strictly newer verification (an unchanged re-pause
-- re-verifies the same content-addressed generation later, and
-- freshness checks must see the current pause as covered), so an exact
-- redelivery affects zero rows. The second refresh arm lets a corrected
-- clock repair its own damage: a stored future value (provably bogus,
-- it exceeds now()) yields to ANY smaller incoming one, sane or merely
-- less skewed, so repair is monotone even when the correction lands
-- while some skew remains; redelivery of either report matches neither
-- arm and stays a no-op.
INSERT INTO backup_generation (sandbox_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (sandbox_id, bucket, generation) WHERE sandbox_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(),
  -- A coverage-only report (empty files: the outbox seed reconstructs
  -- no manifest) must never erase a recorded manifest; richer reports
  -- refresh it.
  files = CASE WHEN jsonb_array_length(excluded.files) = 0
               THEN backup_generation.files ELSE excluded.files END
WHERE excluded.completed_at > backup_generation.completed_at
   OR (backup_generation.completed_at > now() AND excluded.completed_at < backup_generation.completed_at);

-- name: RecordTemplateBackupGeneration :execrows
-- Template variant of RecordSandboxBackupGeneration; the two exist
-- because each conflict target must name its own partial unique index.
INSERT INTO backup_generation (template_id, build_id, generation, bucket, completed_at, files)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (template_id, build_id, bucket, generation) WHERE template_id IS NOT NULL
DO UPDATE SET completed_at = excluded.completed_at, reported_at = now(),
  -- A coverage-only report (empty files: the outbox seed reconstructs
  -- no manifest) must never erase a recorded manifest; richer reports
  -- refresh it.
  files = CASE WHEN jsonb_array_length(excluded.files) = 0
               THEN backup_generation.files ELSE excluded.files END
WHERE excluded.completed_at > backup_generation.completed_at
   OR (backup_generation.completed_at > now() AND excluded.completed_at < backup_generation.completed_at);

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
-- Future-stamped rows (completed_at > reported_at) all rank at the
-- sandbox's EARLIEST future receive instant rather than each at its
-- own, so their order among themselves comes from the raw tie-break
-- (the host's own clock) instead of delivery order, while the class
-- still cannot outrank any legitimately later completion.
SELECT generation, bucket, LEAST(completed_at, reported_at)::timestamptz AS completed_at
FROM (
  SELECT generation, bucket, completed_at, reported_at,
    CASE WHEN completed_at > reported_at
      THEN MIN(reported_at) FILTER (WHERE completed_at > reported_at) OVER ()
      ELSE completed_at END AS effective_at
  FROM backup_generation
  WHERE sandbox_id = $1
) ranked
ORDER BY effective_at DESC, completed_at DESC
LIMIT 1;

-- name: LockSandboxRow :one
-- Serializes the backup report's snapshot-size sync against FinalizePause,
-- which takes the same row lock: the vmstate match below stays true for
-- the duration of the transaction or the sync is skipped. Status rides
-- along because 'pausing' marks a finalize that has not committed yet:
-- a fast upload's report arriving in that window must retry rather than
-- silently miss its size sync.
SELECT id, status, updated_at FROM sandbox WHERE id = $1 FOR UPDATE;

-- name: LatestSnapshotManifest :many
-- The sandbox's newest snapshot row with every digest its pause-time
-- manifest recorded. The full recorded set is the join point between a
-- backup report and the snapshot row it describes: vmstate alone is not
-- a unique pause identity (identical vmstate bytes with different disk
-- contents are possible), so the report must match EVERY recorded row.
-- Pause-time manifests are vmstate-only today; rows tighten the match
-- automatically as richer manifests appear.
SELECT s.id AS snapshot_id, am.file_name, am.sha256
FROM snapshot s
JOIN artifact_manifest am ON am.snapshot_id = s.id
WHERE s.sandbox_id = $1
  AND s.generation = (SELECT MAX(generation) FROM snapshot WHERE sandbox_id = $1)
ORDER BY am.file_name;

-- name: SetSnapshotSizeBytes :exec
UPDATE snapshot SET size_bytes = $2 WHERE id = $1;
