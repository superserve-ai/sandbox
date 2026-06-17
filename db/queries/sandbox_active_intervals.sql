-- name: OpenSandboxActiveInterval :exec
-- Opens an interval row when a sandbox transitions into 'active' (created or
-- resumed). A dangling open row from a prior transition is recoverable, so
-- ON CONFLICT makes this a no-op rather than a unique-violation the caller
-- would have to special-case.
WITH target AS (
    SELECT s.id, s.team_id, s.vcpu_count, s.memory_mib
    FROM sandbox s
    WHERE s.id = sqlc.arg(sandbox_id)
      AND s.team_id = sqlc.arg(team_id)
      AND s.destroyed_at IS NULL
),
opened_active AS (
    INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at)
    SELECT t.id, t.team_id, sqlc.arg(actor_id), now()
    FROM target t
    ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING
    RETURNING sandbox_id
)
INSERT INTO sandbox_compute_billing_interval (
    sandbox_id, team_id, vcpu_count, memory_mib, started_at
)
SELECT t.id, t.team_id, t.vcpu_count, t.memory_mib, now()
FROM opened_active oa
JOIN target t ON t.id = oa.sandbox_id
WHERE feature_enabled('billing_metrics_write', t.team_id)
ON CONFLICT (sandbox_id) WHERE ended_at IS NULL DO NOTHING;

-- name: CloseSandboxActiveInterval :exec
-- Closes the currently-open interval for a sandbox. The WHERE ended_at IS NULL
-- filter is load-bearing: if the sandbox transitions out of 'active' twice
-- without an intervening open (e.g. 'paused' followed later by 'deleted'),
-- only the first call closes the row — the second is a no-op so we don't
-- over-report active time.
WITH closed_active AS (
    UPDATE sandbox_active_interval
    SET ended_at = now(),
        end_reason = sqlc.arg(end_reason)::text
    WHERE sandbox_id = sqlc.arg(sandbox_id)::uuid
      AND ended_at IS NULL
    RETURNING sandbox_id
)
UPDATE sandbox_compute_billing_interval
SET ended_at = now(),
    end_reason = sqlc.arg(end_reason)::text
WHERE sandbox_id = sqlc.arg(sandbox_id)::uuid
  AND ended_at IS NULL;

-- name: GetMostRecentClosedSandboxIntervalActor :one
-- Returns the actor_id of the most recently closed interval for a sandbox.
-- Used by openSandboxInterval as a fallback when a reopen would otherwise
-- have actor_id = NULL (e.g. reaper revert after a failed pause). Without
-- this fallback, the analytics view's "actor_id IS NOT NULL" filter would
-- drop the sandbox from WAU for the rest of its run.
SELECT actor_id
FROM sandbox_active_interval
WHERE sandbox_id = $1 AND ended_at IS NOT NULL
ORDER BY ended_at DESC
LIMIT 1;

-- name: CloseOrphanedActiveIntervals :execrows
-- Defense-in-depth sweep: close interval rows left open while their sandbox is
-- no longer active (a transition whose close didn't land). Left alone they
-- count the sandbox active in WAU forever. end_reason mirrors the terminal
-- state; the settle window avoids racing a transiently non-active sandbox.
WITH closed_active AS (
  UPDATE sandbox_active_interval sai
  SET ended_at = now(),
      end_reason = CASE s.status
          WHEN 'failed'  THEN 'failed'
          WHEN 'deleted' THEN 'deleted'
          ELSE 'paused'
      END
  FROM sandbox s
  WHERE sai.sandbox_id = s.id
    AND sai.ended_at IS NULL
    AND s.status IN ('paused', 'failed', 'deleted')
    AND s.updated_at < now() - interval '5 minutes'
  RETURNING sai.sandbox_id, sai.end_reason
)
UPDATE sandbox_compute_billing_interval bi
SET ended_at = now(),
    end_reason = ca.end_reason
FROM closed_active ca
WHERE bi.sandbox_id = ca.sandbox_id
  AND bi.ended_at IS NULL;
