-- name: ListActivePricingRatesForTeamCurrent :many
WITH selected_time AS (
    SELECT now() AS effective_at
),
selected_plan AS (
    SELECT
        COALESCE((
            SELECT tpp.plan_key
            FROM team_pricing_plan tpp
            JOIN pricing_plan p ON p.key = tpp.plan_key
            WHERE tpp.team_id = sqlc.arg(team_id)
              AND p.active
              AND tpp.effective_from <= st.effective_at
              AND (tpp.effective_to IS NULL OR tpp.effective_to > st.effective_at)
            ORDER BY tpp.effective_from DESC
            LIMIT 1
        ), 'payg')::text AS plan_key,
        st.effective_at
    FROM selected_time st
),
ranked_rates AS (
    SELECT
        r.plan_key,
        p.name AS plan_name,
        p.currency,
        r.resource,
        r.unit,
        r.price_usd,
        r.effective_from,
        row_number() OVER (
            PARTITION BY r.resource, r.unit
            ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC
        ) AS rate_rank
    FROM selected_plan sp
    JOIN pricing_rate r ON r.plan_key = sp.plan_key
    JOIN pricing_plan p ON p.key = r.plan_key
    WHERE p.active
      AND r.effective_from <= sp.effective_at
      AND (r.effective_to IS NULL OR r.effective_to > sp.effective_at)
)
SELECT
    plan_key,
    plan_name,
    currency,
    resource,
    unit,
    price_usd,
    effective_from
FROM ranked_rates
WHERE rate_rank = 1
ORDER BY resource, unit;
