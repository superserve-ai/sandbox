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
-- Atomically record that (team, quota_type) has been alerted. Affects 1 row when
-- this caller wins the claim, 0 when another replica already alerted.
INSERT INTO quota_alert_state (team_id, quota_type)
VALUES ($1, $2)
ON CONFLICT (team_id, quota_type) DO NOTHING;

-- name: ListQuotaAlertState :many
SELECT team_id, quota_type FROM quota_alert_state;

-- name: ClearQuotaAlert :exec
DELETE FROM quota_alert_state WHERE team_id = $1 AND quota_type = $2;
