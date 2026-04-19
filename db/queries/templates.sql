-- name: CreateTemplate :one
-- Insert a new template row in 'pending' status (no build attached). Kept
-- for ops-side seeding that wants to stage rows without triggering builds;
-- the public API uses CreateTemplateWithBuild to auto-enqueue the first
-- build in a single transaction.
INSERT INTO template (team_id, alias, build_spec, vcpu, memory_mib, disk_mib)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: CreateTemplateWithBuild :one
-- Atomically create a template and its first build in one round-trip.
-- Used by POST /templates so users don't have to make two calls. Template
-- starts at 'building' (not 'pending') because the build row is already
-- queued at insert time; the supervisor picks it up within one tick.
--
-- build_spec_hash is computed in Go before the call and passed in so the
-- idempotency index on template_build catches duplicate submits. Returns
-- the template row plus the build id so the handler can echo both.
WITH new_template AS (
  INSERT INTO template (team_id, alias, build_spec, vcpu, memory_mib, disk_mib, status)
  VALUES ($1, $2, $3, $4, $5, $6, 'building')
  RETURNING id, team_id, alias, status, build_spec, vcpu, memory_mib, disk_mib,
            rootfs_path, snapshot_path, mem_path, size_bytes, error_message,
            created_at, updated_at, built_at, deleted_at
),
new_build AS (
  INSERT INTO template_build (template_id, team_id, build_spec_hash)
  SELECT id, team_id, $7 FROM new_template
  RETURNING id AS build_id
)
SELECT new_template.*, new_build.build_id::uuid AS build_id
FROM new_template, new_build;

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

-- name: SoftDeleteTemplateIfUnused :one
-- Soft-deletes a template only if no live sandbox still references it.
-- FOR UPDATE here serializes with the FOR KEY SHARE in CreateSandbox.
WITH locked AS (
  SELECT t.id AS tpl_id FROM template t
  WHERE t.id = $1 AND t.team_id = $2 AND t.deleted_at IS NULL
  FOR UPDATE
),
counted AS (
  SELECT COUNT(*)::bigint AS live_count
  FROM sandbox
  WHERE template_id = $1 AND destroyed_at IS NULL
),
deleted AS (
  UPDATE template t
  SET deleted_at = now(), updated_at = now()
  WHERE t.id IN (SELECT tpl_id FROM locked)
    AND (SELECT live_count FROM counted) = 0
  RETURNING t.id
)
SELECT
  EXISTS(SELECT 1 FROM locked)  AS found,
  (SELECT live_count FROM counted) AS live_count,
  EXISTS(SELECT 1 FROM deleted) AS deleted;

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
-- Counts builds actively consuming host resources (building or capturing
-- a snapshot). Pending rows are excluded — they haven't claimed a slot
-- yet and including them would cause a deadlock: submit the limit's
-- worth of builds at once and the count itself blocks any from starting.
SELECT COUNT(*) FROM template_build
WHERE team_id = $1 AND status IN ('building', 'snapshotting');

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
-- Claims a pending row for dispatch. Stamps host + caller-generated
-- build_vm_id up front so a timed-out BuildTemplate RPC can still be
-- reconciled by GetBuildStatus on the next tick.
UPDATE template_build
SET status = 'building',
    started_at = now(),
    updated_at = now(),
    vmd_host_id = $2,
    vmd_build_vm_id = $3
WHERE id = $1 AND status = 'pending';

-- name: ListActiveBuilds :many
-- Read-only: builds the supervisor is currently watching. Used per tick to
-- poll vmd for status. No row-level lock — these are already past 'pending'.
SELECT * FROM template_build
WHERE status IN ('building', 'snapshotting')
ORDER BY started_at ASC NULLS LAST;

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
