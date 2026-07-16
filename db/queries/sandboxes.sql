-- name: CreateSandbox :one
-- ID is supplied by the caller (generated in Go via uuid.New()) rather
-- than defaulted in SQL, so the caller can parallelize this INSERT with
-- the VMD CreateVM call — both need the same sandbox_id and generating
-- it client-side lets them run concurrently instead of strictly serially.
-- template_id is optional (NULL when sandbox is not derived from a template).
-- snapshot_path / mem_path / base_path / delta_path pin the sandbox to a
-- specific build's artifacts so a later template rebuild can't corrupt it.
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id, snapshot_path, mem_path, base_path, delta_path, auto_delete_seconds)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING *;

-- name: CreateSandboxFromTemplate :one
-- CreateSandbox variant that holds FOR KEY SHARE on the template row
-- during the INSERT, serializing with SoftDeleteTemplateIfUnused's FOR
-- UPDATE. Returns 0 rows if the template is missing, deleted, or not
-- visible to the caller.
WITH tpl AS (
  SELECT t.id AS tpl_id, t.disk_mib FROM template t
  WHERE t.id = $13
    AND t.deleted_at IS NULL
    AND (t.team_id = $14 OR t.team_id = $15)
  FOR KEY SHARE
)
INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address, pid, snapshot_id, timeout_seconds, metadata, template_id, snapshot_path, mem_path, base_path, delta_path, disk_mib, auto_delete_seconds)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, tpl_id, $16, $17, $18, $19, disk_mib, $20 FROM tpl
RETURNING *;

-- name: CreateSandboxFromSnapshot :one
-- Fork insert. The saved snapshot row is locked against leaf deletion and is
-- re-validated as ready/team-owned/feature-enabled in the same statement that
-- creates the durable child reference. Immutable resource shape and pinned
-- template-build paths always come from the snapshot. Policy fields use an
-- explicit inherit bit so NULL can remain a meaningful full replacement.
WITH snap AS (
  SELECT s.*
  FROM snapshot s
  WHERE s.id = sqlc.arg(source_snapshot_id)
    AND s.team_id = sqlc.arg(team_id)
    AND s.kind = 'saved'
    AND s.status = 'ready'
    AND s.deleted_at IS NULL
    AND feature_enabled('sandbox_snapshots_v1', s.team_id)
    AND admit_saved_snapshot_host(s.host_id, s.vcpu_count, s.memory_mib)
  FOR KEY SHARE
)
INSERT INTO sandbox (
  id, team_id, name, status, vcpu_count, memory_mib, disk_mib, host_id,
  ip_address, pid, timeout_seconds, metadata, template_id, snapshot_path,
  mem_path, base_path, delta_path, auto_delete_seconds, network_config,
  source_snapshot_id, secret_env_keys
)
SELECT
  sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(status),
  snap.vcpu_count, snap.memory_mib, snap.disk_mib, snap.host_id,
  sqlc.narg(ip_address), sqlc.narg(pid),
  CASE WHEN sqlc.arg(inherit_timeout_seconds)::boolean
       THEN snap.timeout_seconds ELSE sqlc.narg(timeout_seconds)::int END,
  sqlc.arg(metadata), snap.template_id, snap.template_snapshot_path,
  snap.template_mem_path, snap.base_path, snap.delta_path,
  CASE WHEN sqlc.arg(inherit_auto_delete_seconds)::boolean
       THEN snap.auto_delete_seconds ELSE sqlc.narg(auto_delete_seconds)::int END,
  CASE WHEN sqlc.arg(inherit_network_config)::boolean
       THEN snap.network_config ELSE sqlc.narg(network_config)::jsonb END,
  snap.id, snap.secret_env_keys
FROM snap
RETURNING sandbox.*;

-- name: GetSandbox :one
SELECT * FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: LockSandboxForCapturedMutation :one
-- Call after LockSandboxForSecretWrites in the same transaction. The advisory
-- lock serializes with secret binding changes and saved-snapshot admission;
-- this row lock additionally excludes pause/resume/delete while a live policy
-- is applied and persisted.
SELECT * FROM sandbox
WHERE id = sqlc.arg(id)
  AND team_id = sqlc.arg(team_id)
  AND destroyed_at IS NULL
FOR UPDATE;

-- name: GetSandboxSnapshotDependencyCounts :one
-- Saved snapshots owned by this sandbox block ordinary sandbox deletion. Child
-- sandboxes created from one of those snapshots are reported separately by the
-- snapshot dependency methods.
SELECT count(*)::bigint AS saved_snapshot_count
FROM sandbox source
JOIN snapshot saved ON saved.sandbox_id = source.id
WHERE source.id = sqlc.arg(sandbox_id)
  AND source.team_id = sqlc.arg(team_id)
  AND source.destroyed_at IS NULL
  AND saved.kind = 'saved'
  AND saved.deleted_at IS NULL;

-- name: CountActiveSandboxesAtBasePath :one
-- Count all live references to this build path. Saved snapshots pin their
-- exact template base even after their source sandbox stops using it.
SELECT (
  (SELECT count(*) FROM sandbox
   WHERE sandbox.base_path = $1 AND sandbox.destroyed_at IS NULL)
  +
  (SELECT count(*) FROM snapshot
   WHERE snapshot.base_path = $1
     AND snapshot.kind = 'saved'
     AND snapshot.deleted_at IS NULL)
)::bigint;

-- name: ListPinnedBuildPaths :many
-- Reconciler input: every build path pinned by a live sandbox or saved
-- snapshot. Their builds must survive even if the template moves on.
SELECT DISTINCT pins.base_path
FROM (
  SELECT base_path FROM sandbox
  WHERE base_path IS NOT NULL AND destroyed_at IS NULL
  UNION
  SELECT base_path FROM snapshot
  WHERE base_path IS NOT NULL
    AND kind = 'saved'
    AND deleted_at IS NULL
) pins;

-- name: ListSandboxesByTeamPaged :many
-- Paginated, sortable, filterable team sandbox list backing the console.
--
-- Filters (all optional, AND'd): metadata containment (@> — pass '{}'::jsonb
-- to match everything), status equality, and a case-insensitive name
-- substring. Sort column/direction come from @sort_by + @sort_dir: exactly one
-- guarded CASE term is active per query (the sort params are constant across
-- rows, so every other term evaluates to NULL for all rows and acts as a
-- no-op), with created_at DESC as the stable tiebreaker and default. A NULL
-- @row_limit returns all rows, preserving the pre-pagination "return
-- everything" default so unpaginated SDK/MCP callers are unaffected.
SELECT * FROM sandbox
WHERE team_id = @team_id
  AND destroyed_at IS NULL
  AND metadata @> @metadata
  AND (sqlc.narg('status')::text IS NULL OR status::text = sqlc.narg('status')::text)
  AND (sqlc.narg('name_search')::text IS NULL
       OR name ILIKE '%' || sqlc.narg('name_search')::text || '%')
ORDER BY
  CASE WHEN @sort_by::text = 'name'   AND @sort_dir::text = 'asc'  THEN name END ASC,
  CASE WHEN @sort_by::text = 'name'   AND @sort_dir::text = 'desc' THEN name END DESC,
  CASE WHEN @sort_by::text = 'status' AND @sort_dir::text = 'asc'  THEN status::text END ASC,
  CASE WHEN @sort_by::text = 'status' AND @sort_dir::text = 'desc' THEN status::text END DESC,
  CASE WHEN @sort_by::text = 'created_at' AND @sort_dir::text = 'asc' THEN created_at END ASC,
  created_at DESC
LIMIT sqlc.narg('row_limit')::bigint
OFFSET COALESCE(sqlc.narg('row_offset')::bigint, 0);

-- name: CountSandboxesByTeamPaged :one
-- Total rows matching the same filters as ListSandboxesByTeamPaged (ignoring
-- pagination + sort). Backs the X-Total-Count response header.
SELECT COUNT(*) FROM sandbox
WHERE team_id = @team_id
  AND destroyed_at IS NULL
  AND metadata @> @metadata
  AND (sqlc.narg('status')::text IS NULL OR status::text = sqlc.narg('status')::text)
  AND (sqlc.narg('name_search')::text IS NULL
       OR name ILIKE '%' || sqlc.narg('name_search')::text || '%');

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
  RETURNING id, team_id, vcpu_count, memory_mib, disk_mib,
            source_snapshot_id
),
opened_compute AS (
  INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at)
  SELECT a.id, a.team_id, $6, now()
  FROM activated a
  ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING
  RETURNING sandbox_id
),
opened_billing_compute AS (
  INSERT INTO sandbox_compute_billing_interval (
    sandbox_id, team_id, vcpu_count, memory_mib, started_at
  )
  SELECT a.id, a.team_id, a.vcpu_count, a.memory_mib, now()
  FROM activated a
  WHERE feature_enabled('billing_metrics_write', a.team_id)
  ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING
  RETURNING sandbox_id
)
INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib, started_at)
SELECT a.id, a.team_id, a.disk_mib, now()
FROM activated a
WHERE a.source_snapshot_id IS NULL
  AND feature_enabled('billing_metrics_write', a.team_id)
ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING;

-- name: ListDestroyedSnapshotForksPendingPinRelease :many
-- A destroyed fork keeps its saved-snapshot dependency until exact-host VM
-- teardown succeeds. Reconciliation consumes this bounded queue and releases
-- the pin only after that host-side outcome is known.
SELECT id, team_id, host_id, base_path, template_id, source_snapshot_id
FROM sandbox
WHERE destroyed_at IS NOT NULL
  AND source_snapshot_id IS NOT NULL
ORDER BY destroyed_at ASC, id ASC
LIMIT sqlc.arg(batch_size);

-- name: ReleaseDestroyedSandboxSnapshotPin :one
-- The expected snapshot guards a stale reconciliation result. A live sandbox
-- can never lose its lineage through this cleanup path.
UPDATE sandbox
SET source_snapshot_id = NULL,
    updated_at = now()
WHERE id = sqlc.arg(sandbox_id)
  AND team_id = sqlc.arg(team_id)
  AND source_snapshot_id = sqlc.arg(source_snapshot_id)
  AND destroyed_at IS NOT NULL
RETURNING id;

-- name: DestroySandbox :one
-- Atomic, guarded soft-delete. Claims the sandbox from a quiescent state
-- (active/paused/failed) or from a transitional state (starting/resuming/pausing)
-- whose owning worker is provably gone — updated_at older than
-- stale_transitional_before. It never claims a live transition, so it serializes
-- against a concurrent resume/pause (this CAS and BeginResume target the same row,
-- only one wins) while still letting a crash-wedged sandbox be deleted. Writes the
-- revocation row and closes open billing/active intervals in the same statement,
-- so a crash after the claim can't strand a deleted sandbox with a live JWT or an
-- open interval. Returns the claimed id; 0 rows means already-deleted or a still-live
-- transition — the caller distinguishes the two with a re-read.
--
-- The revocation + interval-close CTEs are mirrored in ClaimAutoDeleteSandboxes;
-- keep the side effects of both in sync.
WITH destroyed AS (
  UPDATE sandbox
  SET destroyed_at = now(), status = 'deleted', updated_at = now()
  WHERE sandbox.id = sqlc.arg(id) AND sandbox.team_id = sqlc.arg(team_id)
    AND sandbox.destroyed_at IS NULL
    AND sandbox.snapshot_operation_id IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM snapshot saved
      WHERE saved.sandbox_id = sandbox.id
        AND saved.kind = 'saved'
        AND saved.deleted_at IS NULL
    )
    AND (
      sandbox.status IN ('active', 'paused', 'failed')
      OR (sandbox.status IN ('starting', 'resuming', 'pausing')
          AND sandbox.updated_at < sqlc.arg(stale_transitional_before))
    )
  RETURNING id
),
revoked AS (
  INSERT INTO sandbox_revocation (sandbox_id, expires_at)
  SELECT id, sqlc.arg(revocation_expires_at) FROM destroyed
  ON CONFLICT (sandbox_id) DO NOTHING
),
closed_compute AS (
  UPDATE sandbox_active_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_billing_compute AS (
  UPDATE sandbox_compute_billing_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_storage AS (
  UPDATE sandbox_storage_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
SELECT id FROM destroyed;

-- name: SandboxExists :one
SELECT EXISTS(SELECT 1 FROM sandbox WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL);

-- name: ListSandboxesByHost :many
-- Used by the VMD reconciler. snapshot_path is joined so the paused-sandbox
-- drift check can stat the file without a per-row snapshot lookup.
SELECT sqlc.embed(s), snap.path AS snapshot_path
FROM sandbox s
LEFT JOIN snapshot snap
  ON snap.id = s.snapshot_id AND snap.kind = 'runtime_checkpoint'
WHERE s.host_id = $1 AND s.destroyed_at IS NULL;

-- name: ListRecentlyDestroyedSandboxIDsByHost :many
-- Used by the VMD disk reconciler so a sandbox destroyed within the grace
-- window — whose on-disk cleanup may still be in flight — is kept out of the
-- orphan set rather than raced.
SELECT id
FROM sandbox
WHERE host_id = sqlc.arg(host_id)
  AND destroyed_at IS NOT NULL
  AND destroyed_at > sqlc.arg(destroyed_after);

-- name: MarkSandboxFailed :exec
-- Used by the reconciler to mark a sandbox failed when VMD detects it is
-- actually gone. No team_id filter — the reconciler runs with host scope,
-- not team scope. The CTE bundles the active-interval close into the same
-- statement so a crash/timeout between the two writes can't leave the
-- interval open and have analytics count the actor as active forever.
WITH failed AS (
  UPDATE sandbox
  -- auto_delete_at is cleared: the deadline is only meaningful in 'paused',
  -- and a stale one would resurface (or instantly fire) if the sandbox is
  -- ever returned to 'paused' by a recovery path.
  SET status = 'failed', auto_delete_at = NULL, updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.destroyed_at IS NULL
    AND sandbox.snapshot_operation_id IS NULL
  RETURNING id
),
closed_active AS (
  UPDATE sandbox_active_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'failed'
  WHERE sandbox_id IN (SELECT id FROM failed)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
UPDATE sandbox_compute_billing_interval
SET ended_at = GREATEST(now(), started_at), end_reason = 'failed'
WHERE sandbox_id IN (SELECT id FROM failed)
  AND ended_at IS NULL;

-- name: MarkSandboxFailedInTeam :exec
-- Like MarkSandboxFailed but with a team_id tenant check, used by handler
-- and reaper paths that know which team owns the sandbox. Same atomic
-- bundling of the active-interval close.
WITH failed AS (
  UPDATE sandbox
  SET status = 'failed', auto_delete_at = NULL, updated_at = now()
  WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
    AND sandbox.snapshot_operation_id IS NULL
  RETURNING id
),
closed_active AS (
  UPDATE sandbox_active_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'failed'
  WHERE sandbox_id IN (SELECT id FROM failed)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
UPDATE sandbox_compute_billing_interval
SET ended_at = GREATEST(now(), started_at), end_reason = 'failed'
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
    AND sandbox.snapshot_operation_id IS NULL
  RETURNING *
),
closed_interval AS (
  UPDATE sandbox_active_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'paused'
  WHERE sandbox_id IN (SELECT id FROM paused)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_billing_compute AS (
  UPDATE sandbox_compute_billing_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'paused'
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
-- serialize concurrent /exec and /resume requests. Snapshot-derived sandboxes
-- additionally lock and re-check their pinned host capacity; this is the same
-- host-row admission boundary used by initial fan-out.
WITH candidate AS (
  SELECT s.*
  FROM sandbox s
  WHERE s.id = $1 AND s.team_id = $2 AND s.destroyed_at IS NULL
    AND s.status = 'paused'
    AND s.snapshot_operation_id IS NULL
  FOR UPDATE
),
admitted AS (
  SELECT candidate.id
  FROM candidate
  WHERE candidate.source_snapshot_id IS NULL
     OR admit_saved_snapshot_host(
          candidate.host_id, candidate.vcpu_count, candidate.memory_mib
        )
)
UPDATE sandbox
SET status = 'resuming', auto_delete_at = NULL, updated_at = now()
FROM admitted
WHERE sandbox.id = admitted.id
RETURNING sandbox.*;

-- name: RevertResumeToPaused :exec
-- Compensate a failed resume attempt by flipping status back to 'paused'.
-- Guarded on status = 'resuming' so we never clobber a concurrent transition
-- (e.g., ActivateSandbox has already flipped to 'active').
UPDATE sandbox
SET status = 'paused',
    -- Re-arm the auto-delete deadline cleared by BeginResume; the sandbox is
    -- paused again, so it gets a fresh window.
    auto_delete_at = now() + make_interval(secs => auto_delete_seconds),
    updated_at = now()
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL AND status = 'resuming';

-- name: FinalizePause :one
-- Upsert the sandbox's live snapshot row and flip status to 'paused'.
-- Returns 0 rows if the sandbox is missing, soft-deleted, or no longer in a
-- pause-eligible transition (→ ErrSandboxGone). The status guard keeps a
-- stale or duplicate finalize from clobbering a terminal state — without it,
-- a late-landing write could flip a 'failed' sandbox back to 'paused' and
-- arm its auto-delete deadline.
-- One snapshot per sandbox; the unique index on snapshot.sandbox_id keys
-- the UPSERT.
WITH target AS (
  SELECT id, team_id FROM sandbox
  WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL
    AND status IN ('pausing', 'resuming')
),
upserted AS (
  INSERT INTO snapshot (
    sandbox_id, team_id, path, mem_path, size_bytes, trigger, kind, status
  )
  SELECT target.id, target.team_id, $3, $4, $5, $6,
         'runtime_checkpoint', 'ready'
  FROM target
  ON CONFLICT (sandbox_id) WHERE kind = 'runtime_checkpoint'
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
    -- Arm the auto-delete deadline as the sandbox lands in 'paused'.
    -- make_interval(NULL) propagates NULL, so an unset auto_delete_seconds
    -- leaves the deadline NULL (never deleted).
    auto_delete_at = now() + make_interval(secs => sandbox.auto_delete_seconds),
    updated_at = now()
FROM upserted
WHERE sandbox.id = $1 AND sandbox.team_id = $2 AND sandbox.destroyed_at IS NULL
  AND sandbox.status IN ('pausing', 'resuming')
RETURNING upserted.snap_id::uuid AS snapshot_id;

-- name: UpdateSandboxNetworkConfig :execrows
UPDATE sandbox
SET network_config = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL
  AND snapshot_operation_id IS NULL;

-- name: UpdateSandboxMetadata :exec
UPDATE sandbox
SET metadata = $2, updated_at = now()
WHERE id = $1 AND team_id = $3 AND destroyed_at IS NULL;

-- name: GetSandboxNetworkConfig :one
SELECT network_config FROM sandbox
WHERE id = $1 AND team_id = $2 AND destroyed_at IS NULL;

-- name: GetSandboxEgressContext :one
SELECT s.network_config, t.unmatched_host_policy
FROM sandbox s
JOIN team t ON s.team_id = t.id
WHERE s.id = $1 AND s.destroyed_at IS NULL;

-- name: ClaimExpiredSandboxes :many
-- Atomically claims active sandboxes past their timeout and marks them 'pausing'.
-- FOR UPDATE OF s SKIP LOCKED lets concurrent reaper replicas skip in-flight rows.
--
-- timeout_seconds bounds an active session, not total lifetime, so the window is
-- anchored on the current session start (the open sandbox_active_interval row,
-- reopened on resume) — each resume re-arms it. Anchoring on created_at would
-- instead keep a sandbox that ever exceeded its timeout permanently eligible.
--
-- COALESCE falls back to created_at when interval bookkeeping (best-effort) leaves
-- an active sandbox with no open interval; otherwise the NULL comparison would
-- silently exempt it from the timeout.
--
-- Only 'active' rows are eligible; the 60s grace floor spares freshly started or
-- resumed sandboxes with very short timeouts.
WITH open_sessions AS (
  -- Current session start per sandbox: the open interval, computed once.
  SELECT sandbox_id, max(started_at) AS session_start
  FROM sandbox_active_interval
  WHERE ended_at IS NULL
  GROUP BY sandbox_id
),
expired AS (
  SELECT s.id, s.team_id, s.name, s.snapshot_id, s.host_id
  FROM sandbox s
  LEFT JOIN open_sessions os ON os.sandbox_id = s.id
  WHERE s.destroyed_at IS NULL
    AND s.timeout_seconds IS NOT NULL
    AND s.status = 'active'
    AND s.snapshot_operation_id IS NULL
    AND COALESCE(os.session_start, s.created_at) + (s.timeout_seconds || ' seconds')::interval < now()
    AND COALESCE(os.session_start, s.created_at) < now() - interval '60 seconds'
  ORDER BY s.created_at ASC
  LIMIT $1
  FOR UPDATE OF s SKIP LOCKED
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
  SET ended_at = GREATEST(now(), started_at), end_reason = 'timeout_paused'
  WHERE sandbox_id IN (SELECT id FROM paused)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_billing_compute AS (
  UPDATE sandbox_compute_billing_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'timeout_paused'
  WHERE sandbox_id IN (SELECT id FROM paused)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
SELECT p.id, p.team_id, p.name, p.snapshot_id, p.host_id
FROM paused p
LEFT JOIN closed_intervals ci ON ci.sandbox_id = p.id;

-- name: UpdateSandboxAutoDelete :execrows
-- Set or clear (NULL) the auto-delete window. The deadline counts continuous
-- paused time since the setting was applied: on an already-paused sandbox it
-- is armed from now() — never retroactively from the pause — so applying a
-- window can never destroy the sandbox in the same instant. On a non-paused
-- sandbox the deadline stays NULL and FinalizePause arms it at the next pause.
-- Keep the ::int::double precision cast: the param is used as both the integer
-- column and make_interval's double arg; without it Postgres errors 42P08.
UPDATE sandbox
SET auto_delete_seconds = sqlc.narg(auto_delete_seconds),
    auto_delete_at = CASE WHEN status = 'paused'
      THEN now() + make_interval(secs => sqlc.narg(auto_delete_seconds)::int::double precision)
      ELSE NULL
    END,
    updated_at = now()
WHERE id = $1 AND team_id = sqlc.arg(team_id) AND destroyed_at IS NULL
  AND snapshot_operation_id IS NULL;

-- name: UpdateSandboxTimeout :execrows
-- Set or clear (NULL) the auto-pause timeout. Takes effect on the reaper's
-- next tick: the window is evaluated against the current active session
-- start, so lowering it below already-elapsed session time pauses the
-- sandbox on the next sweep. On a paused sandbox it applies to the next
-- active session after resume.
UPDATE sandbox
SET timeout_seconds = sqlc.narg(timeout_seconds),
    updated_at = now()
WHERE id = $1 AND team_id = sqlc.arg(team_id) AND destroyed_at IS NULL
  AND snapshot_operation_id IS NULL;

-- name: ClaimAutoDeleteSandboxes :many
-- Atomically soft-deletes paused sandboxes whose auto-delete deadline has
-- passed. Deliberately narrower than DestroySandbox: it claims from 'paused'
-- only, with the deadline re-checked under the row lock, so a concurrent
-- BeginResume (also guarded on 'paused') and this claim can never both win
-- the same row. FOR UPDATE SKIP LOCKED lets concurrent reaper replicas skip
-- in-flight rows.
--
-- Mirrors DestroySandbox's side effects: writes the revocation row and closes
-- any open active/billing/storage intervals in the same statement, so a crash
-- after the claim can't strand a deleted sandbox with a live JWT or an open
-- interval. Returns the columns the caller needs for VM/artifact teardown.
WITH due AS (
  SELECT s.id
  FROM sandbox s
  WHERE s.destroyed_at IS NULL
    AND s.status = 'paused'
    AND s.snapshot_operation_id IS NULL
    AND s.auto_delete_at IS NOT NULL
    AND s.auto_delete_at < now()
    AND NOT EXISTS (
      SELECT 1 FROM snapshot saved
      WHERE saved.sandbox_id = s.id
        AND saved.kind = 'saved'
        AND saved.deleted_at IS NULL
    )
  ORDER BY s.auto_delete_at ASC
  LIMIT sqlc.arg(batch_size)
  FOR UPDATE OF s SKIP LOCKED
),
destroyed AS (
  UPDATE sandbox
  SET destroyed_at = now(), status = 'deleted', updated_at = now()
  FROM due
  WHERE sandbox.id = due.id
  RETURNING sandbox.id, sandbox.team_id, sandbox.name, sandbox.host_id,
            sandbox.base_path, sandbox.template_id,
            sandbox.source_snapshot_id
),
revoked AS (
  INSERT INTO sandbox_revocation (sandbox_id, expires_at)
  SELECT id, sqlc.arg(revocation_expires_at) FROM destroyed
  ON CONFLICT (sandbox_id) DO NOTHING
),
closed_compute AS (
  UPDATE sandbox_active_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_billing_compute AS (
  UPDATE sandbox_compute_billing_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
),
closed_storage AS (
  UPDATE sandbox_storage_interval
  SET ended_at = GREATEST(now(), started_at), end_reason = 'deleted'
  WHERE sandbox_id IN (SELECT id FROM destroyed)
    AND ended_at IS NULL
  RETURNING sandbox_id
)
SELECT d.id, d.team_id, d.name, d.host_id, d.base_path, d.template_id,
       d.source_snapshot_id
FROM destroyed d;
