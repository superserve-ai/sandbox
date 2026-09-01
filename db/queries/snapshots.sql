-- name: CreateSnapshot :one
INSERT INTO snapshot (sandbox_id, team_id, path, mem_path, size_bytes, trigger)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSnapshot :one
-- Team-scoped snapshot lookup for user-facing handlers. The join on
-- team_id enforces tenant isolation at the SQL layer so callers cannot
-- accidentally leak another team's snapshot metadata by forgetting the
-- in-Go team check.
SELECT * FROM snapshot
WHERE id = $1 AND team_id = $2;

-- name: GetSnapshotByID :one
-- Unscoped snapshot lookup for internal (host-scoped) code paths such as
-- the VMD reconciler. DO NOT call from user-facing handlers.
SELECT * FROM snapshot
WHERE id = $1;

-- name: GetSnapshotForResume :one
-- GetSnapshot's resume-path variant: the same team-scoped snapshot row,
-- plus the sandbox's backup generation VERIFIED to cover this exact
-- snapshot, in one round trip rather than a second query on resume's
-- latency-sensitive path.
--
-- CoveredBackupGeneration is deliberately NOT "the sandbox's latest
-- backup" (that can be a stale, unrelated generation from a pause the
-- current one has already superseded — see paused_unbacked_count's
-- identical join in hosts.sql for the same reasoning). The
-- covered_snapshot_id/covered_snapshot_generation link is written by the
-- report handler under the sandbox row lock only once a report's
-- manifest is verified against THIS snapshot row, so a match here names
-- a generation actually safe to restore for it. NULL — no report has
-- verified coverage of this pause yet — is the common case and means
-- fetch-before-resume has nothing to offer for this resume, not an
-- error.
--
-- Scalar subquery, not a JOIN: backup_generation's real uniqueness is
-- (sandbox_id, bucket, generation), not the covered_snapshot link, so a
-- JOIN could in principle multiply this :one query's row count; LIMIT 1
-- keeps the contract regardless. COALESCE to '' rather than leaving the
-- subquery NULL: sqlc can't infer this expression's nullability, so an
-- un-coalesced NULL would generate a non-pointer string field pgx then
-- fails to scan a NULL into — '' is also this codebase's existing "no
-- generation" sentinel, so callers need no NULL-specific handling.
--
-- Not filtered by bucket: a covered generation reported under a bucket
-- other than the one the target vmd host currently reads from (a cell's
-- BACKUP_BUCKET rotated since that report landed) can still be named
-- here even though that host cannot fetch it. This is an accepted, known
-- gap — cells are architecturally single-bucket for their lifetime today
-- (see the multi-region cell design), so a rotation is a rare, deliberate
-- operation, and the failure mode is a clean, already-understood
-- FailedPrecondition on the fetch attempt (see fetchResumeError), not a
-- silent wrong restore. Closing it properly needs the resume RPC to
-- carry the covered bucket too and vmd to validate against its own
-- configured one — worth doing if bucket rotation becomes a real
-- occurrence, not attempted here.
SELECT s.id, s.sandbox_id, s.team_id, s.path, s.size_bytes, s.trigger,
       s.created_at, s.mem_path, s.generation, s.name, s.pause_token,
       COALESCE((SELECT bg.generation FROM backup_generation bg
        WHERE bg.sandbox_id = s.sandbox_id
          AND bg.covered_snapshot_id = s.id
          AND bg.covered_snapshot_generation = s.generation
        ORDER BY bg.reported_at DESC
        LIMIT 1), ''::text)::text AS covered_backup_generation
FROM snapshot s
WHERE s.id = $1 AND s.team_id = $2;

-- name: ListSnapshotsBySandbox :many
SELECT * FROM snapshot
WHERE sandbox_id = $1
ORDER BY created_at DESC;

-- name: ListSnapshotsByTeam :many
SELECT * FROM snapshot
WHERE team_id = $1
ORDER BY created_at DESC;

-- name: DeleteSnapshot :exec
-- Invariant: only delete snapshots of destroyed sandboxes. fk_sandbox_snapshot
-- is ON DELETE SET NULL, so deleting a live/paused sandbox's snapshot silently
-- nulls its restore pointer (unrestorable) instead of erroring.
DELETE FROM snapshot
WHERE id = $1;

-- name: DeleteSnapshotsOfDestroyedSandboxes :execrows
-- Backstop for destroy teardown that never ran (crash/shutdown before
-- cleanupSandboxSnapshots). Driven from snapshot (joined to sandbox by PK) so
-- it scans only un-cleaned rows, not every accumulating soft-deleted sandbox.
-- Files fall to the vm reconciler's disk scan.
DELETE FROM snapshot s
USING sandbox sb
WHERE s.sandbox_id = sb.id
  AND sb.destroyed_at IS NOT NULL
  AND sb.destroyed_at < now() - interval '1 hour';
