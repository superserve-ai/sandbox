-- Excludes teams no longer attached to this cell from the per-team
-- analytics views.
--
-- When a team migrates between cells, cmd/migrate-team's detach step
-- deletes the team's membership rows here (team_member, team_memberships,
-- user_role_assignments -- see membershipTables in cmd/migrate-team/tables.go)
-- but deliberately retains the team row and its historical usage/sandbox
-- rows as a cold fallback until purge. team.home_region is not part of
-- that detach step and does not reflect the move. Membership presence is
-- the same "is this team still live here" signal cmd/migrate-team's own
-- sourceDetached helper checks, so it's the correct filter: without it, a
-- detached team's pre-cutover usage keeps getting ranked on this cell's
-- dashboards even after it's live on another cell.
--
-- All three membership tables have to be checked, matching sourceDetached
-- exactly, not just team_member: the current membership-management path
-- (upsertMembership, internal/api/rbac_phase2b.go) only writes
-- team_memberships, so a live team can have rows there and nothing in the
-- legacy team_member table. Requiring team_member alone would exclude
-- that team's real, current usage, not just a detached team's stale
-- history.
DROP VIEW IF EXISTS analytics.team_hourly_spend;
DROP VIEW IF EXISTS analytics.team_sandbox_events;

CREATE OR REPLACE VIEW analytics.team_hourly_spend AS
SELECT t.name AS team_name,
       u.hour_start,
       (CASE WHEN u.hour_start < pl.at THEN 0
             WHEN vcpu_rate.price_usd IS NOT NULL THEN u.vcpu_seconds * vcpu_rate.price_usd
             ELSE NULL END
        + CASE WHEN u.hour_start < pl.at THEN 0
             WHEN mem_rate.price_usd IS NOT NULL THEN u.memory_mib_seconds / 1024 * mem_rate.price_usd
             ELSE NULL END
        + CASE WHEN u.hour_start < pl.at THEN 0
             WHEN storage_rate.price_usd IS NOT NULL THEN u.storage_mib_seconds / 1024 * storage_rate.price_usd
             ELSE NULL END
       )::numeric(14,6) AS spend_usd
FROM team_billing_usage_hourly u
JOIN team t ON t.id = u.team_id
CROSS JOIN (SELECT '2026-06-17 00:00:00+00'::timestamptz AS at) pl
CROSS JOIN LATERAL (
    SELECT COALESCE((
        SELECT tpp.plan_key
        FROM team_pricing_plan tpp
        JOIN pricing_plan p ON p.key = tpp.plan_key
        WHERE tpp.team_id = u.team_id
          AND tpp.effective_from <= u.hour_start
          AND (tpp.effective_to IS NULL OR tpp.effective_to > u.hour_start)
        ORDER BY tpp.effective_from DESC
        LIMIT 1
    ), 'payg') AS plan_key
) tp
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'vcpu'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) vcpu_rate ON true
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'memory_gib'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) mem_rate ON true
LEFT JOIN LATERAL (
    SELECT r.price_usd FROM pricing_rate r
    WHERE r.plan_key = tp.plan_key AND r.resource = 'storage_gib'
      AND r.effective_from <= u.hour_start
      AND (r.effective_to IS NULL OR r.effective_to > u.hour_start)
    ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC LIMIT 1
) storage_rate ON true
WHERE EXISTS (SELECT 1 FROM team_member tm WHERE tm.team_id = t.id)
   OR EXISTS (SELECT 1 FROM team_memberships tm WHERE tm.team_id = t.id)
   OR EXISTS (SELECT 1 FROM user_role_assignments ura WHERE ura.team_id = t.id);

CREATE OR REPLACE VIEW analytics.team_sandbox_events AS
SELECT t.name AS team_name,
       s.created_at
FROM sandbox s
JOIN team t ON t.id = s.team_id
WHERE EXISTS (SELECT 1 FROM team_member tm WHERE tm.team_id = t.id)
   OR EXISTS (SELECT 1 FROM team_memberships tm WHERE tm.team_id = t.id)
   OR EXISTS (SELECT 1 FROM user_role_assignments ura WHERE ura.team_id = t.id);
