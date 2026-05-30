-- name: OpenSandboxActiveInterval :exec
-- Opens an interval row when a sandbox transitions into 'active' (created or
-- resumed). The partial unique index sandbox_active_interval(sandbox_id) WHERE
-- ended_at IS NULL guarantees at most one open row per sandbox at any time;
-- in the unlikely event a prior open row was left dangling, the caller should
-- treat the unique-violation as recoverable (sandbox is already considered
-- running) rather than a hard error.
INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at)
VALUES ($1, $2, $3, now());

-- name: CloseSandboxActiveInterval :exec
-- Closes the currently-open interval for a sandbox. The WHERE ended_at IS NULL
-- filter is load-bearing: if the sandbox transitions out of 'active' twice
-- without an intervening open (e.g. 'paused' followed later by 'deleted'),
-- only the first call closes the row — the second is a no-op so we don't
-- over-report active time.
UPDATE sandbox_active_interval
SET ended_at = now(),
    end_reason = $2
WHERE sandbox_id = $1
  AND ended_at IS NULL;
