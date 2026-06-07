-- name: CreateSandbox :one
-- ID is supplied by the caller (generated in Go via uuid.New()) rather
-- than defaulted in SQL, so the caller can parallelize this INSERT with
-- the VMD CreateVM call — both need the same sandbox_id and generating
-- it client-side lets them run concurrently instead of strictly serially.
-- template_id is optional (NULL when sandbox is not derived from a template).
-- snapshot_path / mem_path / base_path / delta_path pin the sandbox to a
-- specific build's artifacts so a later template rebuild can't corrupt it.
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id, snapshot_path, mem_path, base_path, delta_path)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
RETURNING *;

-- name: CreateSandboxFromTemplate :one
-- CreateSandbox variant that holds FOR KEY SHARE on the template row
-- during the INSERT, serializing with SoftDeleteTemplateIfUnused's FOR
-- UPDATE. Returns 0 rows if the template is missing, deleted, or not
-- visible to the caller.
WITH tpl AS (
  SELECT t.id AS tpl_id FROM template t
  WHERE t.id = $13
    AND t.deleted_at IS NULL
    AND (t.team_id = $14 OR t.team_id = $15)
  FOR KEY SHARE
)
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id, snapshot_path, mem_path, base_path, delta_path)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, tpl_id, $16, $17, $18, $19 FROM tpl
RETURNING *;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: CountActiveSandboxesAtBasePath :one
-- Count of non-destroyed sandboxes still referencing this base_path. Used at
-- destroy time to decide whether the per-build artifact dir is safe to GC.
SELECT COUNT(*)::bigint FROM sandbox
WHERE base_path = $1 AND destroyed_at IS NULL;

-- name: ListPinnedBuildPaths :many
-- Reconciler input: distinct base_path values held by non-destroyed
-- sandboxes. Their builds must survive even if the template moved on.
SELECT DISTINCT base_path FROM sandbox
WHERE base_path IS NOT NULL AND destroyed_at IS NULL;

-- name: ListSandboxesByTeam :many
SELECT * FROM sandbox
WHERE team_id = $1 AND destroyed_at IS NULL
ORDER BY created_at DESC;

-- name: ListSandboxesByTeamWithFilter :many
-- Same as ListSandboxesByTeam but additionally filters rows whose metadata
-- contains every key/value pair in $2 (jsonb @> containment). Pass an empty
-- object '{}'::jsonb to match everything — but prefer ListSandboxesByTeam
-- in that case so we don't pay the (still tiny) cost of the @> evaluation.
SELECT * FROM sandbox
WHERE team_id = $1
  AND destroyed_at IS NULL
  AND metadata @> $2
ORDER BY created_at DESC;

-- name: UpdateSandboxStatus :exec
UPDATE sandbox
SET status = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: UpdateSandboxHost :exec
UPDATE sandbox
SET host_id = $2, ip_address = $3, pid = $4, updated_at = now()
WHERE id = $1 AND team_id = $5 AND destroyed_at IS NULL;

-- name: ActivateSandbox :exec
-- Atomic status → active AND open of a sandbox_active_interval row. Bundling
-- the interval open into the activation statement guarantees that any
-- sandbox observable as active has a matching open interval — otherwise a
-- crash/timeout between the two writes would leave the sandbox active with
-- no interval, undercounting WAU until the next state transition.
--
-- A leftover open interval must not fail the activation, so ON CONFLICT keeps
-- the existing open row — an orphaned interval can never block a resumed VM.
-- (Creation has no prior interval; this reuse only ever applies on resume.)
WITH activated AS (
  UPDATE sandbox
  SET status = 'active',
      vcpu_count = $2,
      memory_mib = $3,
      ip_address = $4,
      updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.team_id = $5 AND sandbox.destroyed_at IS NULL
  RETURNING id, team_id
)
INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at)
SELECT a.id, a.team_id, $6, now()
FROM activated a
ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING;

-- name: SetSandboxSnapshot :exec
UPDATE sandbox
SET snapshot_id = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: DestroySandbox :exec
-- Atomic soft-delete AND close of any open sandbox_active_interval row, so
-- a crash/timeout after the destroy can't leave an open interval that
-- causes weekly_user_metrics to count the actor as active forever. If the
-- WHERE clause matches 0 rows (already-deleted sandbox), the close CTE
-- also matches 0 rows via the empty `destroyed` subquery → no-op.
WITH destroyed AS (
  UPDATE sandbox
  SET destroyed_at = now(), status = 'deleted', updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
  RETURNING id
)
UPDATE sandbox_active_interval
SET ended_at = now(), end_reason = 'deleted'
WHERE sandbox_id IN (SELECT id FROM destroyed)
  AND ended_at IS NULL;

-- name: SandboxExists :one
SELECT EXISTS(SELECT 1 FROM sandbox WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL);

-- name: ListSandboxesByHost :many
-- Used by the VMD reconciler. snapshot_path is joined so the paused-sandbox
-- drift check can stat the file without a per-row snapshot lookup.
SELECT sqlc.embed(s), snap.path AS snapshot_path
FROM sandbox s
LEFT JOIN snapshot snap ON snap.id = s.snapshot_id
WHERE s.host_id = $1 AND s.destroyed_at IS NULL;

-- name: MarkSandboxFailed :exec
-- Used by the reconciler to mark a sandbox failed when VMD detects it is
-- actually gone. No team_id filter — the reconciler runs with host scope,
-- not team scope. The CTE bundles the active-interval close into the same
-- statement so a crash/timeout between the two writes can't leave the
-- interval open and have analytics count the actor as active forever.
WITH failed AS (
  UPDATE sandbox
  SET status = 'failed', updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.destroyed_at IS NULL
  RETURNING id
)
UPDATE sandbox_active_interval
SET ended_at = now(), end_reason = 'failed'
WHERE sandbox_id IN (SELECT id FROM failed)
  AND ended_at IS NULL;

-- name: MarkSandboxFailedInTeam :exec
-- Like MarkSandboxFailed but with a team_id tenant check, used by handler
-- and reaper paths that know which team owns the sandbox. Same atomic
-- bundling of the active-interval close.
WITH failed AS (
  UPDATE sandbox
  SET status = 'failed', updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
  RETURNING id
)
UPDATE sandbox_active_interval
SET ended_at = now(), end_reason = 'failed'
WHERE sandbox_id IN (SELECT id FROM failed)
  AND ended_at IS NULL;

-- name: BeginPause :one
-- Atomic ownership + state check + transition to 'pausing' AND close of any
-- open sandbox_active_interval row, all in one statement so the "sandbox
-- left active" and "interval closed" facts commit together. If the handler
-- dies between status update and a separate interval close, the analytics
-- view would count the actor as active forever — bundling them into one
-- statement makes that gap unreachable.
--
-- A 0-row result still means "no such sandbox OR wrong team OR not
-- currently active", and the caller disambiguates via a fallback
-- GetSandbox in the rare error path.
WITH paused AS (
  UPDATE sandbox
  SET status = 'pausing', updated_at = now()
  WHERE sandbox.id = $1
    AND sandbox.team_id = $2
    AND sandbox.destroyed_at IS NULL
    AND sandbox.status = 'active'
  RETURNING *
),
closed_interval AS (
  UPDATE sandbox_active_interval
  SET ended_at = now(), end_reason = 'paused'
  WHERE sandbox_id IN (SELECT id FROM paused)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
SELECT p.*
FROM paused p
LEFT JOIN closed_interval ci ON ci.sandbox_id = p.id;

-- name: BeginResume :one
-- Atomic claim for resume: transitions 'paused' to 'resuming' in one
-- statement. A 0-row result means another resume (explicit or auto) has
-- already claimed the sandbox, or it's not in paused state. Used to
-- serialize concurrent /exec and /resume requests.
UPDATE sandbox
SET status = 'resuming', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL AND status = 'paused'
RETURNING *;

-- name: RevertResumeToPaused :exec
-- Compensate a failed resume attempt by flipping status back to 'paused'.
-- Guarded on status = 'resuming' so we never clobber a concurrent transition
-- (e.g., ActivateSandbox has already flipped to 'active').
UPDATE sandbox
SET status = 'paused', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL AND status = 'resuming';

-- name: FinalizePause :one
-- Upsert the sandbox's live snapshot row and flip status to 'paused'.
-- Returns 0 rows if the sandbox is missing or soft-deleted (→ ErrSandboxGone).
-- One snapshot per sandbox; the unique index on snapshot.sandbox_id keys
-- the UPSERT.
WITH target AS (
  SELECT id, team_id FROM sandbox
  WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL
),
upserted AS (
  INSERT INTO snapshot (sandbox_id, team_id, path, mem_path, size_bytes, trigger)
  SELECT target.id, target.team_id, $3, $4, $5, $6 FROM target
  ON CONFLICT (sandbox_id)
  DO UPDATE SET
    path = EXCLUDED.path,
    mem_path = EXCLUDED.mem_path,
    size_bytes = EXCLUDED.size_bytes,
    trigger = EXCLUDED.trigger
  RETURNING snapshot.id AS snap_id
)
UPDATE sandbox
SET snapshot_id = (SELECT snap_id FROM upserted),
    status = 'paused',
    updated_at = now()
FROM upserted
WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
RETURNING upserted.snap_id::uuid AS snapshot_id;

-- name: UpdateSandboxNetworkConfig :exec
UPDATE sandbox
SET network_config = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: UpdateSandboxMetadata :exec
UPDATE sandbox
SET metadata = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: GetSandboxNetworkConfig :one
SELECT network_config FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: ClaimExpiredSandboxes :many
-- Atomically claims active sandboxes whose hard timeout has elapsed and marks
-- them as 'pausing'. FOR UPDATE SKIP LOCKED lets concurrent reaper replicas
-- skip rows already being processed, so multi-replica Cloud Run deployments
-- do not double-process the same sandbox.
--
-- Only 'active' sandboxes are claimed — paused sandboxes are already stopped,
-- and transient states (starting, pausing) are skipped to avoid racing with
-- in-progress operations. The 60-second grace window prevents reaping a sandbox
-- that was just created with a very short timeout before it finishes starting up.
WITH expired AS (
  SELECT id, team_id, name, snapshot_id, host_id
  FROM sandbox
  WHERE destroyed_at IS NULL
    AND timeout_seconds IS NOT NULL
    AND status = 'active'
    AND created_at + (timeout_seconds || ' seconds')::interval < now()
    AND created_at < now() - interval '60 seconds'
  ORDER BY created_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED
),
paused AS (
  UPDATE sandbox
  SET status = 'pausing', updated_at = now()
  FROM expired
  WHERE sandbox.id = expired.id
  RETURNING expired.id, expired.team_id, expired.name, expired.snapshot_id, expired.host_id
),
closed_intervals AS (
  -- Same atomicity story as BeginPause: bundle the active-interval close
  -- into the claim statement so the reaper can't crash between claiming a
  -- sandbox (status active → pausing) and closing its interval. Without
  -- this, a crashed claim would leave the interval open forever and the
  -- analytics view would keep counting the actor as active.
  UPDATE sandbox_active_interval
  SET ended_at = now(), end_reason = 'timeout_paused'
  WHERE sandbox_id IN (SELECT id FROM paused)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
SELECT p.id, p.team_id, p.name, p.snapshot_id, p.host_id
FROM paused p
LEFT JOIN closed_intervals ci ON ci.sandbox_id = p.id;
