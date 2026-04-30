-- name: CreateSandbox :one
-- ID is supplied by the caller (generated in Go via uuid.New()) rather
-- than defaulted in SQL, so the caller can parallelize this INSERT with
-- the VMD CreateVM call — both need the same sandbox_id and generating
-- it client-side lets them run concurrently instead of strictly serially.
-- template_id is optional (NULL when sandbox is not derived from a template).
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, tpl_id FROM tpl
RETURNING *;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: CountActiveSandboxesForTeam :one
-- Active = consumes host resources. Excludes failed (VM is gone) and
-- destroyed (row is dead). Includes starting/active/pausing/paused/resuming.
SELECT COUNT(*)::bigint FROM sandbox
WHERE team_id = $1 AND destroyed_at IS NULL AND status != 'failed';

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
UPDATE sandbox
SET status = 'active',
    vcpu_count = $2,
    memory_mib = $3,
    ip_address = $4,
    updated_at = now()
WHERE id = $1 AND team_id = $5 AND destroyed_at IS NULL;

-- name: SetSandboxSnapshot :exec
UPDATE sandbox
SET snapshot_id = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: DestroySandbox :exec
UPDATE sandbox
SET destroyed_at = now(), status = 'deleted', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

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
-- not team scope.
UPDATE sandbox
SET status = 'failed', updated_at = now()
WHERE id = $1 AND destroyed_at IS NULL;

-- name: BeginPause :one
-- Atomic ownership + state check + transition to 'pausing'. Replaces the
-- GetSandbox → check status → UpdateSandboxStatus sequence on the pause
-- hot path, collapsing two DB roundtrips into one. The WHERE clause
-- enforces the invariant (only active, non-deleted sandboxes owned by
-- this team can be paused); a 0-row result means "no such sandbox OR
-- wrong team OR not currently active", and the caller disambiguates via
-- a fallback GetSandbox in the rare error path.
UPDATE sandbox
SET status = 'pausing', updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL AND status = 'active'
RETURNING *;

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
)
UPDATE sandbox
SET status = 'pausing', updated_at = now()
FROM expired
WHERE sandbox.id = expired.id
RETURNING expired.id, expired.team_id, expired.name, expired.snapshot_id, expired.host_id;
