-- name: CreateTemplate :one
-- Insert a new template row in 'pending' status. The actual build is kicked
-- off later by POST /templates/:id/build, which inserts into template_build.
-- ID is generated SQL-side (defaulted) since template create has no parallel
-- VMD call to coordinate with — unlike CreateSandbox.
INSERT INTO template (team_id, alias, build_spec, vcpu, memory_mib, disk_mib)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetTemplate :one
-- Fetch a template visible to the caller: either owned by the caller's team
-- or by the system team (system_team_id param — pass uuid.Nil to disable).
-- Returns 0 rows if the template isn't visible, doesn't exist, or is deleted.
SELECT * FROM template
WHERE id = $1
  AND deleted_at IS NULL
  AND (team_id = $2 OR team_id = $3);

-- name: GetTemplateForOwner :one
-- Fetch a template owned by this team. Used for write paths (build, delete)
-- where system-team visibility is irrelevant — only the owner can mutate.
SELECT * FROM template
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: GetTemplateByAlias :one
-- Resolve alias to a template visible to the caller. Aliases are unique per
-- team, so the same alias can exist in both the caller's team and the system
-- team — prefer the caller's own (ORDER BY) so overrides work naturally.
SELECT * FROM template
WHERE alias = $1
  AND deleted_at IS NULL
  AND (team_id = $2 OR team_id = $3)
ORDER BY (team_id = $2) DESC
LIMIT 1;

-- name: ListTemplatesForTeam :many
-- Return the caller's team's templates plus all system-team templates
-- (curated base set visible to everyone). Ordered by created_at desc.
SELECT * FROM template
WHERE deleted_at IS NULL
  AND (team_id = $1 OR team_id = $2)
ORDER BY created_at DESC;

-- name: ListTemplatesForTeamFiltered :many
-- Same as ListTemplatesForTeam with an optional alias prefix filter. Pass
-- NULL to get the unfiltered list (but prefer the unfiltered query then).
SELECT * FROM template
WHERE deleted_at IS NULL
  AND (team_id = $1 OR team_id = $2)
  AND (sqlc.narg('alias_prefix')::text IS NULL
       OR alias LIKE sqlc.narg('alias_prefix') || '%')
ORDER BY created_at DESC;

-- name: SoftDeleteTemplate :execrows
-- Soft-delete a template owned by this team. Returns row count so the caller
-- can distinguish "not found / not yours" (0) from success (1). Does NOT
-- check for active sandboxes referencing this template — that check is done
-- in Go before this call (returns 409 to the user).
UPDATE template
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: CountLiveSandboxesForTemplate :one
-- Used before SoftDeleteTemplate to enforce 409-on-in-use. Counts every
-- sandbox referencing this template that has not been hard-destroyed —
-- including paused and failed sandboxes, not just 'active'. A paused
-- sandbox still has a snapshot bundle dependent on the template's
-- rootfs/snapshot files, so deletion would orphan it. The user must
-- destroy these sandboxes (DELETE /sandboxes/:id) before the template
-- can be removed.
SELECT COUNT(*) FROM sandbox
WHERE template_id = $1 AND destroyed_at IS NULL;

-- name: CreateTemplateBuild :one
-- Insert a new build row. Will fail with a unique-violation if there is
-- already an in-flight build for this (template_id, build_spec_hash) — the
-- caller (handler) catches that and returns the existing build id instead,
-- giving idempotent submits.
INSERT INTO template_build (template_id, team_id, build_spec_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetExistingInflightBuild :one
-- Fetch the existing in-flight build for this (template_id, build_spec_hash),
-- used after a unique-violation from CreateTemplateBuild to return the
-- pre-existing build id to the caller.
SELECT * FROM template_build
WHERE template_id = $1
  AND build_spec_hash = $2
  AND status IN ('pending', 'building', 'snapshotting');

-- name: GetTemplateBuild :one
-- Fetch a build visible to the caller's team. Read-only path; team scope only.
SELECT * FROM template_build
WHERE id = $1 AND team_id = $2;

-- name: ListBuildsForTemplate :many
-- Recent builds for a template. Used by the SDK to inspect build history.
SELECT * FROM template_build
WHERE template_id = $1 AND team_id = $2
ORDER BY created_at DESC
LIMIT $3;

-- name: CountInFlightBuildsForTeam :one
-- Used by the build supervisor to enforce team.build_concurrency before
-- dispatching a pending build. Counts builds that are not in terminal state.
SELECT COUNT(*) FROM template_build
WHERE team_id = $1 AND status IN ('pending', 'building', 'snapshotting');

-- name: ClaimPendingBuilds :many
-- Atomically claim pending builds for dispatch. FOR UPDATE SKIP LOCKED makes
-- this safe with multiple control plane replicas — concurrent supervisors
-- skip rows another replica already has. Limit caps how many we work per tick.
WITH claimed AS (
  SELECT id FROM template_build
  WHERE status = 'pending'
  ORDER BY created_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED
)
UPDATE template_build
SET status = 'building',
    started_at = now(),
    updated_at = now(),
    vmd_host_id = $2
FROM claimed
WHERE template_build.id = claimed.id
RETURNING template_build.*;

-- name: ListPendingBuildsOrdered :many
-- Read-only scan of pending builds in FIFO order. Used by the supervisor's
-- per-tick dispatch loop to evaluate admission (host capacity + per-team
-- concurrency) before transitioning any rows. Kept separate from
-- ClaimPendingBuilds so the supervisor can skip individual rows (e.g. a
-- team already at its concurrency limit) without locking them out of a
-- later tick.
SELECT * FROM template_build
WHERE status = 'pending'
ORDER BY created_at ASC
LIMIT $1;

-- name: TryDispatchBuild :execrows
-- Atomic status transition from 'pending' to 'building', stamping the host
-- and start timestamp. Returns rows affected — 1 if we successfully claimed
-- the row, 0 if another supervisor tick (or another replica) already took
-- it. Callers on the 0 path skip; callers on the 1 path dispatch to vmd.
UPDATE template_build
SET status = 'building',
    started_at = now(),
    updated_at = now(),
    vmd_host_id = $2
WHERE id = $1 AND status = 'pending';

-- name: ListActiveBuilds :many
-- Read-only: builds the supervisor is currently watching. Used per tick to
-- poll vmd for status. No row-level lock — these are already past 'pending'.
SELECT * FROM template_build
WHERE status IN ('building', 'snapshotting')
ORDER BY started_at ASC NULLS LAST;

-- name: AttachBuildVM :exec
-- Record the vmd-side build VM id once vmd.BuildTemplate has returned it.
-- Lets the supervisor (and cancel path) call vmd.GetBuildStatus / CancelBuild
-- by VM id rather than re-derive it.
UPDATE template_build
SET vmd_build_vm_id = $2, updated_at = now()
WHERE id = $1;

-- name: AdvanceBuildStatus :exec
-- Used by the supervisor to walk a build through transient statuses
-- (building → snapshotting). Terminal transitions go through FinalizeBuild
-- or FailBuild instead.
UPDATE template_build
SET status = $2, updated_at = now()
WHERE id = $1 AND status IN ('pending', 'building', 'snapshotting');

-- name: FinalizeBuild :one
-- Atomically transition template_build → ready and template → ready with
-- the snapshot paths populated. Mirrors the FinalizePause CTE pattern in
-- sandboxes.sql: one roundtrip, no torn states. Returns the template row
-- so the caller can log the outcome.
WITH build_done AS (
  UPDATE template_build
  SET status = 'ready',
      finalized_at = now(),
      updated_at = now()
  WHERE template_build.id = $1 AND status IN ('building', 'snapshotting')
  RETURNING template_id
)
UPDATE template
SET status = 'ready',
    rootfs_path = $2,
    snapshot_path = $3,
    mem_path = $4,
    size_bytes = $5,
    built_at = now(),
    updated_at = now(),
    error_message = NULL
FROM build_done
WHERE template.id = build_done.template_id
RETURNING template.*;

-- name: FailBuild :one
-- Atomic terminal-failure transition. Same shape as FinalizeBuild; sets
-- error_message on the template so users see a useful message.
WITH build_done AS (
  UPDATE template_build
  SET status = 'failed',
      finalized_at = now(),
      updated_at = now(),
      error_message = $2
  WHERE template_build.id = $1 AND status IN ('pending', 'building', 'snapshotting')
  RETURNING template_id
)
UPDATE template
SET status = 'failed',
    error_message = $2,
    updated_at = now()
FROM build_done
WHERE template.id = build_done.template_id
RETURNING template.*;

-- name: CancelBuild :execrows
-- User-initiated cancellation of a build. Only succeeds while the build is
-- still in a non-terminal state. Caller is responsible for calling
-- vmd.CancelBuild before this; this just records the terminal status.
UPDATE template_build
SET status = 'cancelled',
    finalized_at = now(),
    updated_at = now(),
    error_message = 'cancelled by user'
WHERE id = $1
  AND team_id = $2
  AND status IN ('pending', 'building', 'snapshotting');

-- name: ReapStaleBuilds :many
-- Mark builds failed if they have stayed in pending past pending_timeout, or
-- in building/snapshotting past build_timeout. Returns affected rows so the
-- caller can call vmd.CancelBuild for orphan VM cleanup. Same idempotent
-- pattern as ClaimExpiredSandboxes.
WITH stale AS (
  SELECT id, vmd_host_id, vmd_build_vm_id FROM template_build
  WHERE
    (status = 'pending' AND created_at < now() - (sqlc.arg('pending_timeout_seconds')::int || ' seconds')::interval)
    OR
    (status IN ('building', 'snapshotting') AND COALESCE(started_at, created_at) < now() - (sqlc.arg('build_timeout_seconds')::int || ' seconds')::interval)
  ORDER BY created_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED
)
UPDATE template_build
SET status = 'failed',
    finalized_at = now(),
    updated_at = now(),
    error_message = 'build timed out'
FROM stale
WHERE template_build.id = stale.id
RETURNING template_build.id, stale.vmd_host_id, stale.vmd_build_vm_id;
