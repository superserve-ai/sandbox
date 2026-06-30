-- name: ListTeamQuotaUsage :many
-- Per-team sandbox + template usage and limits, restricted to teams with any
-- usage (an empty team can't be near a threshold). Used by the quota watcher.
SELECT
    t.id,
    t.name,
    t.active_sandbox_count,
    t.max_sandboxes,
    t.max_templates,
    COALESCE(tpl.cnt, 0)::int AS template_count
FROM team t
LEFT JOIN (
    SELECT team_id, COUNT(*) AS cnt
    FROM template
    WHERE deleted_at IS NULL
    GROUP BY team_id
) tpl ON tpl.team_id = t.id
WHERE t.active_sandbox_count > 0 OR COALESCE(tpl.cnt, 0) > 0;

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
