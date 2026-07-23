-- name: ListTeamQuotaUsage :many
-- Per-team sandbox + template usage and limits, restricted to teams with any
-- usage (an empty team can't be near a threshold). Used by the quota watcher.
-- Sandbox counts come from the sharded-counter view; team.active_sandbox_count
-- is no longer written.
SELECT
    t.id,
    t.name,
    COALESCE(sc.active_sandbox_count, 0)::int AS active_sandbox_count,
    t.max_sandboxes,
    t.max_templates,
    COALESCE(tpl.cnt, 0)::int AS template_count
FROM team t
LEFT JOIN team_active_sandbox_counts sc ON sc.team_id = t.id
LEFT JOIN (
    SELECT team_id, COUNT(*) AS cnt
    FROM template
    WHERE deleted_at IS NULL
    GROUP BY team_id
) tpl ON tpl.team_id = t.id
WHERE COALESCE(sc.active_sandbox_count, 0) > 0 OR COALESCE(tpl.cnt, 0) > 0;

-- name: ListQuotaCounterDrift :many
-- Teams whose shard sum disagrees with a recount of the counted set. Both
-- aggregates read one snapshot (single statement), so in-flight admissions
-- are invisible to both sides and any nonzero difference is real drift —
-- the triggers can't cause it, but row surgery on sandbox can, and a
-- low-biased sum silently widens the team's quota. Raw SUM, not the floored
-- view: flooring would hide a negative sum on a team with no live sandboxes
-- (still-dormant undercount). FULL JOIN catches both directions: shard rows
-- with no live sandboxes and vice versa.
SELECT
    COALESCE(sc.team_id, tc.team_id)::uuid AS team_id,
    COALESCE(sc.raw_sum, 0)::int AS shard_sum,
    COALESCE(tc.cnt, 0)::int AS true_count
FROM (
    SELECT team_id, SUM(cnt)::int AS raw_sum
    FROM team_sandbox_counter
    GROUP BY team_id
) sc
FULL JOIN (
    SELECT team_id, COUNT(*)::int AS cnt
    FROM sandbox
    WHERE sandbox_quota_counted(destroyed_at, status)
    GROUP BY team_id
) tc ON tc.team_id = sc.team_id
WHERE COALESCE(sc.raw_sum, 0) <> COALESCE(tc.cnt, 0);

-- name: ClaimQuotaAlert :execrows
-- Atomically record that (team, quota_type, channel) has been alerted. Affects 1
-- row when this caller wins the claim, 0 when the channel was already alerted
-- this episode (or is still within the cooldown window). The row's created_at is
-- the last-alerted time the cooldown sweep reads.
INSERT INTO quota_alert_state (team_id, quota_type, channel)
VALUES ($1, $2, $3)
ON CONFLICT (team_id, quota_type, channel) DO NOTHING;

-- name: ListQuotaAlertState :many
SELECT team_id, quota_type, channel, created_at FROM quota_alert_state;

-- name: ClearQuotaAlert :exec
DELETE FROM quota_alert_state
WHERE team_id = $1 AND quota_type = $2 AND channel = $3;

-- name: GetTeamNotifyEmail :one
-- The team owner's email for the quota notification. No row (caller skips) when
-- the team has no owner, so the email never goes to a non-owner member.
SELECT p.email
FROM team_member tm
JOIN profile p ON p.id = tm.profile_id
WHERE tm.team_id = $1 AND tm.role = 'owner'
ORDER BY tm.joined_at ASC
LIMIT 1;
