-- name: CreateSandboxSnapshot :one
-- The row exists as creating before the host is asked, under the id the
-- host's capture is keyed by, so an answer lost on the way back is settled
-- later from the host (see the snapshot sweep). What the row records of its
-- source is read here, from a source still live, held shared so a destroy
-- of it lands before or after this row and never between: a template
-- reclaim then always sees the sandbox or the snapshot pinning its build.
-- The trigger counts the limits on insert; a retry carrying an idempotency
-- key already on file is refused by the unique index and re-read by the
-- caller.
INSERT INTO sandbox_snapshot (
    id, team_id, sandbox_id, template_id, kind, status, name, idempotency_key,
    host_id, vcpu_count, memory_mib, disk_mib, base_path,
    timeout_seconds, network_config, secret_bindings, sweep_after
)
SELECT @id::uuid, s.team_id, s.id, s.template_id, @kind::text, 'creating', sqlc.narg('name')::text, sqlc.narg('idempotency_key')::text,
    s.host_id, s.vcpu_count, s.memory_mib, s.disk_mib, s.base_path,
    s.timeout_seconds, COALESCE(s.network_config, '{}'::jsonb), @secret_bindings::jsonb, @sweep_after::timestamptz
FROM sandbox s
WHERE s.id = @sandbox_id AND s.team_id = @team_id AND s.destroyed_at IS NULL
  AND s.status IN ('active', 'paused') AND s.host_id <> '' AND s.base_path IS NOT NULL
FOR SHARE OF s
RETURNING *;

-- name: GetSandboxSnapshot :one
-- Team-scoped: another team's row and a deleted row are the same 404.
SELECT * FROM sandbox_snapshot
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL;

-- name: GetSandboxSnapshotUnscoped :one
-- Any team, any state: for settling a host's answer against the row.
SELECT * FROM sandbox_snapshot WHERE id = $1;

-- name: GetSandboxSnapshotByIdempotencyKey :one
-- Deleted rows included: the request that made a since-deleted snapshot is
-- told so, not given a second capture.
SELECT * FROM sandbox_snapshot
WHERE team_id = $1 AND sandbox_id = $2 AND idempotency_key = $3;

-- name: ListSandboxSnapshots :many
SELECT * FROM sandbox_snapshot
WHERE team_id = $1 AND sandbox_id = $2 AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT sqlc.narg('row_limit')::bigint OFFSET sqlc.arg('row_offset')::bigint;

-- name: CountSandboxSnapshots :one
SELECT count(*) FROM sandbox_snapshot
WHERE team_id = $1 AND sandbox_id = $2 AND deleted_at IS NULL;

-- name: MarkSandboxSnapshotReady :one
-- Only a row still creating becomes ready: the request that started the
-- capture and the sweep may both carry the host's answer.
UPDATE sandbox_snapshot
SET status = 'ready', ready_at = now(),
    base_mem_path = sqlc.narg('base_mem_path'), snapshot_path = sqlc.narg('snapshot_path'),
    mem_path = sqlc.narg('mem_path'), overlay_path = @overlay_path,
    size_bytes = @size_bytes, fc_build_sha = sqlc.narg('fc_build_sha')
WHERE id = @id AND status = 'creating'
RETURNING *;

-- name: MarkSandboxSnapshotFailed :execrows
UPDATE sandbox_snapshot SET status = 'failed'
WHERE id = $1 AND status = 'creating';

-- name: ScheduleSandboxSnapshotSweep :execrows
-- A capture whose answer was lost is the sweep's to settle now, not when
-- the row ages out.
UPDATE sandbox_snapshot SET sweep_after = now()
WHERE id = $1 AND status = 'creating';

-- name: RenameSandboxSnapshot :one
UPDATE sandbox_snapshot SET name = $3
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: BeginSandboxSnapshotDelete :one
-- A row still creating is left to its capture and the sweep unless it has
-- been creating since before @stale_before, when its host has stopped
-- answering and the delete is what retires it: the host refuses the id
-- from then on. A row already deleting is driven again.
UPDATE sandbox_snapshot SET status = 'deleting', sweep_after = now()
WHERE id = $1 AND team_id = $2 AND deleted_at IS NULL
  AND (status <> 'creating' OR created_at < @stale_before)
RETURNING *;

-- name: MarkSandboxSnapshotDeleted :execrows
-- The host has confirmed it holds nothing and will commit nothing for the
-- id again, so nothing is owed to the sweep.
UPDATE sandbox_snapshot SET deleted_at = now(), sweep_after = NULL
WHERE id = $1 AND status = 'deleting' AND deleted_at IS NULL;

-- name: ClaimStuckSandboxSnapshots :many
-- Rows a capture or a delete left behind, due for the sweep. Each claimed
-- row is pushed out to @retry_at, so a host that does not answer holds back
-- nothing but its own rows and another replica's sweep passes over them.
UPDATE sandbox_snapshot SET sweep_after = sqlc.arg('retry_at')::timestamptz
WHERE id IN (
    SELECT id FROM sandbox_snapshot
    WHERE deleted_at IS NULL
      AND status IN ('creating', 'deleting')
      AND sweep_after <= now()
    ORDER BY sweep_after
    LIMIT sqlc.arg('row_limit')::bigint
    FOR UPDATE SKIP LOCKED
)
RETURNING *;
