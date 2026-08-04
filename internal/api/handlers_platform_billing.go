package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/authz"
)

const (
	platformBillingReadPermission = "platform:billing:read"
	platformBillingDefaultLimit   = int64(50)
)

var platformBillingSortColumns = []string{
	"team_name",
	"created_at",
	"current_charges_usd",
	"expected_invoice_amount_usd",
	"credits_remaining_usd",
}

type platformBillingParams struct {
	Limit   int64
	Offset  int64
	SortBy  string
	SortDir string
	Search  string
}

func parsePlatformBillingParams(c *gin.Context) (platformBillingParams, error) {
	page, err := parsePageParams(c, platformBillingSortColumns, "team_name")
	if err != nil {
		return platformBillingParams{}, err
	}
	params := platformBillingParams{
		Limit:   platformBillingDefaultLimit,
		SortBy:  page.SortBy,
		SortDir: page.SortDir,
	}
	if page.Limit != nil {
		params.Limit = *page.Limit
	}
	if page.Offset != nil {
		params.Offset = *page.Offset
	}
	search := strings.TrimSpace(c.Query("search"))
	if utf8.RuneCountInString(search) > 200 {
		return platformBillingParams{}, errors.New("search must be at most 200 characters")
	}
	if escaped := searchTerm(search); escaped != nil {
		params.Search = *escaped
	}
	return params, nil
}

func (h *Handlers) requirePlatformBillingRead(c *gin.Context) bool {
	actorID, err := internalActorID(c)
	if err != nil {
		return false
	}
	if err := h.requirePlatformAdminGoogleSession(c.Request.Context(), h.Pool, actorID); err != nil {
		if errors.Is(err, authz.ErrSessionNotEligible) || errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrForbidden)
			return false
		}
		log.Error().Err(err).Msg("platform billing session validation failed")
		respondError(c, ErrInternal)
		return false
	}
	svc := h.rbacService()
	if svc == nil {
		respondError(c, ErrInternal)
		return false
	}
	if err := svc.RequirePlatformPermission(c.Request.Context(), actorID, platformBillingReadPermission); err != nil {
		if errors.Is(err, authz.ErrPermissionDenied) || errors.Is(err, authz.ErrScopeMismatch) {
			respondError(c, ErrForbidden)
			return false
		}
		log.Error().Err(err).Msg("platform billing authorization failed")
		respondError(c, ErrInternal)
		return false
	}
	return true
}

// ListPlatformBilling returns billing summaries for every matching team in one
// set-based query. A team's unavailable pricing is represented as an error on
// that row so it does not make the whole platform response fail.
func (h *Handlers) ListPlatformBilling(c *gin.Context) {
	if !h.requirePlatformBillingRead(c) {
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	params, err := parsePlatformBillingParams(c)
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	var payload json.RawMessage
	var queryErr error
	if h.Now != nil {
		payload, queryErr = h.queryPlatformBillingWithClock(c.Request.Context(), platformBillingQueryForSort(params.SortBy), params.Search, params.SortBy, params.SortDir, params.Limit, params.Offset)
	} else {
		queryErr = h.Pool.QueryRow(
			c.Request.Context(),
			platformBillingQueryForSort(params.SortBy),
			params.Search,
			params.SortBy,
			params.SortDir,
			params.Limit,
			params.Offset,
		).Scan(&payload)
	}
	if queryErr != nil {
		log.Error().Err(queryErr).Msg("platform billing query failed")
		respondError(c, ErrInternal)
		return
	}

	c.Header("Cache-Control", "private, no-store")
	c.Header("Vary", "Authorization, X-Actor-User-Id")
	c.Data(http.StatusOK, "application/json; charset=utf-8", payload)
}

func (h *Handlers) queryPlatformBillingWithClock(ctx context.Context, query, search, sortBy, sortDir string, limit, offset int64) (json.RawMessage, error) {
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, `SELECT set_config('superserve.billing_now', $1, true)`, h.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}

	var payload json.RawMessage
	if err := tx.QueryRow(ctx, query, search, sortBy, sortDir, limit, offset).Scan(&payload); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return payload, nil
}

func platformBillingQueryForSort(sortBy string) string {
	switch sortBy {
	case "team_name", "created_at":
		return platformBillingMetadataQuery
	default:
		return platformBillingChargesQuery
	}
}

const platformBillingChargesQuery = `
WITH request_time AS (
	SELECT billing_request_now() AS calculated_at
),
team_periods AS (
	SELECT
		t.id AS team_id,
		t.name AS team_name,
		t.created_at,
		COALESCE(bp.period_start, date_trunc('month', rt.calculated_at)) AS period_start,
		COALESCE(bp.period_end, date_trunc('month', rt.calculated_at) + interval '1 month') AS period_end,
		rt.calculated_at
	FROM team t
	CROSS JOIN request_time rt
	LEFT JOIN LATERAL (
		SELECT p.period_start, p.period_end
		FROM team_billing_period p
		WHERE p.team_id = t.id
		  AND p.finalized_at IS NULL
		ORDER BY p.period_start DESC
		LIMIT 1
	) bp ON true
	WHERE $1::text = ''
	   OR t.name ILIKE '%' || $1 || '%' ESCAPE '\'
	   OR t.id::text ILIKE '%' || $1 || '%' ESCAPE '\'
),
selected_plans AS (
	SELECT
		tp.*,
		COALESCE((
			SELECT tpp.plan_key
			FROM team_pricing_plan tpp
			JOIN pricing_plan pp ON pp.key = tpp.plan_key AND pp.active
			WHERE tpp.team_id = tp.team_id
			  AND tpp.effective_from <= tp.calculated_at
			  AND (tpp.effective_to IS NULL OR tpp.effective_to > tp.calculated_at)
			ORDER BY tpp.effective_from DESC
			LIMIT 1
		), 'payg') AS plan_key
	FROM team_periods tp
),
ranked_rates AS (
	SELECT
		sp.team_id,
		pp.name AS plan_name,
		pp.currency,
		pr.resource,
		pr.unit,
		pr.price_usd,
		row_number() OVER (
			PARTITION BY sp.team_id, pr.resource, pr.unit
			ORDER BY pr.effective_from DESC, pr.created_at DESC, pr.id DESC
		) AS rate_rank
	FROM selected_plans sp
	JOIN pricing_plan pp ON pp.key = sp.plan_key AND pp.active
	JOIN pricing_rate pr ON pr.plan_key = sp.plan_key
		AND pr.effective_from <= sp.calculated_at
		AND (pr.effective_to IS NULL OR pr.effective_to > sp.calculated_at)
),
rates AS (
	SELECT
		team_id,
		max(plan_name) AS plan_name,
		max(currency) AS currency,
		count(*) FILTER (
			WHERE rate_rank = 1
			  AND unit = 'second'
			  AND resource IN ('vcpu', 'memory_gib', 'storage_gib')
		) AS rate_count,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'vcpu') AS vcpu_rate,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'memory_gib') AS memory_rate,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'storage_gib') AS storage_rate
	FROM ranked_rates
	GROUP BY team_id
),
compute_usage AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.vcpu_count
		), 0)::numeric AS vcpu_seconds,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.memory_mib
		), 0)::numeric AS memory_mib_seconds
	FROM selected_plans sp
	LEFT JOIN sandbox_compute_billing_interval i
	  ON i.team_id = sp.team_id
	 AND sp.period_start < LEAST(sp.calculated_at, sp.period_end)
	 AND i.started_at < LEAST(sp.calculated_at, sp.period_end)
	 AND COALESCE(i.ended_at, LEAST(sp.calculated_at, sp.period_end)) > sp.period_start
	GROUP BY sp.team_id
),
storage_usage AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.disk_mib
		), 0)::numeric AS storage_mib_seconds
	FROM selected_plans sp
	LEFT JOIN sandbox_storage_interval i
	  ON i.team_id = sp.team_id
	 AND sp.period_start < LEAST(sp.calculated_at, sp.period_end)
	 AND i.started_at < LEAST(sp.calculated_at, sp.period_end)
	 AND COALESCE(i.ended_at, LEAST(sp.calculated_at, sp.period_end)) > sp.period_start
	GROUP BY sp.team_id
),
credits AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(g.remaining_usd) FILTER (
			WHERE g.remaining_usd > 0
			  AND (g.expires_at IS NULL OR g.expires_at > sp.calculated_at)
		), 0)::numeric AS available_usd
	FROM selected_plans sp
	LEFT JOIN team_credit_grant g ON g.team_id = sp.team_id
	GROUP BY sp.team_id
),
current_period_ledger AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(l.amount_usd) FILTER (WHERE l.amount_usd > 0), 0)::numeric AS applied_usd
	FROM selected_plans sp
	LEFT JOIN team_credit_ledger l
	  ON l.team_id = sp.team_id
	 AND l.billing_period_start = sp.period_start
	 AND l.billing_period_end = sp.period_end
	GROUP BY sp.team_id
),
available_credits AS (
	SELECT
		sp.team_id,
		(credits.available_usd + COALESCE(current_period_ledger.applied_usd, 0)) AS available_usd
	FROM selected_plans sp
	JOIN credits ON credits.team_id = sp.team_id
	LEFT JOIN current_period_ledger ON current_period_ledger.team_id = sp.team_id
),
costed AS (
	SELECT
		sp.*,
		r.plan_name,
		r.currency,
		ac.available_usd,
		(cu.vcpu_seconds * r.vcpu_rate) AS compute_usd,
		((cu.memory_mib_seconds / 1024.0) * r.memory_rate) AS memory_usd,
		((su.storage_mib_seconds / 1024.0) * r.storage_rate) AS storage_usd,
		CASE
			WHEN COALESCE(r.rate_count, 0) <> 3
			  OR r.vcpu_rate IS NULL
			  OR r.memory_rate IS NULL
			  OR r.storage_rate IS NULL
			THEN 'pricing_unavailable'
		END AS error_code
	FROM selected_plans sp
	LEFT JOIN rates r ON r.team_id = sp.team_id
	JOIN available_credits ac ON ac.team_id = sp.team_id
	JOIN compute_usage cu ON cu.team_id = sp.team_id
	JOIN storage_usage su ON su.team_id = sp.team_id
),
billed AS (
	SELECT
		costed.*,
		(compute_usd + memory_usd + storage_usd) AS current_charges_usd,
		LEAST(compute_usd + memory_usd + storage_usd, available_usd) AS credits_applied_usd,
		GREATEST(available_usd - (compute_usd + memory_usd + storage_usd), 0) AS credits_remaining_usd,
		GREATEST((compute_usd + memory_usd + storage_usd) - available_usd, 0) AS expected_invoice_amount_usd
	FROM costed
),
ordered AS (
	SELECT
		billed.*,
		row_number() OVER (ORDER BY
			CASE WHEN $2 = 'team_name' AND $3 = 'asc' THEN lower(team_name) END ASC,
			CASE WHEN $2 = 'team_name' AND $3 = 'desc' THEN lower(team_name) END DESC,
			CASE WHEN $2 = 'created_at' AND $3 = 'asc' THEN created_at END ASC,
			CASE WHEN $2 = 'created_at' AND $3 = 'desc' THEN created_at END DESC,
			CASE WHEN $2 = 'current_charges_usd' AND $3 = 'asc' THEN current_charges_usd END ASC NULLS LAST,
			CASE WHEN $2 = 'current_charges_usd' AND $3 = 'desc' THEN current_charges_usd END DESC NULLS LAST,
			CASE WHEN $2 = 'expected_invoice_amount_usd' AND $3 = 'asc' THEN expected_invoice_amount_usd END ASC NULLS LAST,
			CASE WHEN $2 = 'expected_invoice_amount_usd' AND $3 = 'desc' THEN expected_invoice_amount_usd END DESC NULLS LAST,
			CASE WHEN $2 = 'credits_remaining_usd' AND $3 = 'asc' THEN credits_remaining_usd END ASC NULLS LAST,
			CASE WHEN $2 = 'credits_remaining_usd' AND $3 = 'desc' THEN credits_remaining_usd END DESC NULLS LAST,
			CASE WHEN error_code IS NOT NULL THEN 1 ELSE 0 END ASC,
			lower(team_name) ASC,
			team_id ASC
		) AS row_num
	FROM billed
),
paged AS (
	SELECT *
	FROM ordered
	WHERE row_num > $5
	  AND row_num <= $5 + $4
),
response_rows AS (
	SELECT
		row_num,
		jsonb_build_object(
			'team_id', team_id,
			'team_name', team_name,
			'summary', CASE WHEN error_code IS NULL THEN jsonb_build_object(
				'current_charges_usd', current_charges_usd,
				'credits_applied_usd', credits_applied_usd,
				'credits_remaining_usd', credits_remaining_usd,
				'expected_invoice_amount_usd', expected_invoice_amount_usd,
				'cost_breakdown_usd', jsonb_build_object(
					'compute', compute_usd,
					'memory', memory_usd,
					'storage', storage_usd
				),
				'billing_period', jsonb_build_object('start', period_start, 'end', period_end),
				'pricing_tier', jsonb_build_object(
					'plan_key', plan_key,
					'plan_name', plan_name,
					'currency', currency
				),
				'calculated_at', calculated_at
			) END,
			'error', CASE WHEN error_code IS NOT NULL THEN jsonb_build_object(
				'code', error_code,
				'message', 'Billing pricing is not available for this team'
			) END
		) AS value
	FROM paged
)
SELECT jsonb_build_object(
	'rows', COALESCE(
		(SELECT jsonb_agg(value ORDER BY row_num) FROM response_rows),
		'[]'::jsonb
	),
	'pagination', jsonb_build_object(
		'limit', $4,
		'offset', $5,
		'total', (SELECT count(*) FROM billed)
	),
	'totals', jsonb_build_object(
		'teams', (SELECT count(*) FROM billed),
		'succeeded', (SELECT count(*) FROM billed WHERE error_code IS NULL),
		'failed', (SELECT count(*) FROM billed WHERE error_code IS NOT NULL),
		'current_charges_usd', COALESCE((SELECT SUM(current_charges_usd) FROM billed WHERE error_code IS NULL), 0),
		'credits_applied_usd', COALESCE((SELECT SUM(credits_applied_usd) FROM billed WHERE error_code IS NULL), 0),
		'credits_remaining_usd', COALESCE((SELECT SUM(credits_remaining_usd) FROM billed WHERE error_code IS NULL), 0),
		'expected_invoice_amount_usd', COALESCE((SELECT SUM(expected_invoice_amount_usd) FROM billed WHERE error_code IS NULL), 0)
	)
)
`

const platformBillingMetadataQuery = `
WITH request_time AS (
	SELECT billing_request_now() AS calculated_at
),
team_periods AS (
	SELECT
		t.id AS team_id,
		t.name AS team_name,
		t.created_at,
		COALESCE(bp.period_start, date_trunc('month', rt.calculated_at)) AS period_start,
		COALESCE(bp.period_end, date_trunc('month', rt.calculated_at) + interval '1 month') AS period_end,
		rt.calculated_at
	FROM team t
	CROSS JOIN request_time rt
	LEFT JOIN LATERAL (
		SELECT p.period_start, p.period_end
		FROM team_billing_period p
		WHERE p.team_id = t.id
		  AND p.finalized_at IS NULL
		ORDER BY p.period_start DESC
		LIMIT 1
	) bp ON true
	WHERE $1::text = ''
	   OR t.name ILIKE '%' || $1 || '%' ESCAPE '\'
	   OR t.id::text ILIKE '%' || $1 || '%' ESCAPE '\'
),
selected_plans AS (
	SELECT
		tp.*,
		COALESCE((
			SELECT tpp.plan_key
			FROM team_pricing_plan tpp
			JOIN pricing_plan pp ON pp.key = tpp.plan_key AND pp.active
			WHERE tpp.team_id = tp.team_id
			  AND tpp.effective_from <= tp.calculated_at
			  AND (tpp.effective_to IS NULL OR tpp.effective_to > tp.calculated_at)
			ORDER BY tpp.effective_from DESC
			LIMIT 1
		), 'payg') AS plan_key
	FROM team_periods tp
),
ranked_rates AS (
	SELECT
		sp.team_id,
		pp.name AS plan_name,
		pp.currency,
		pr.resource,
		pr.unit,
		pr.price_usd,
		row_number() OVER (
			PARTITION BY sp.team_id, pr.resource, pr.unit
			ORDER BY pr.effective_from DESC, pr.created_at DESC, pr.id DESC
		) AS rate_rank
	FROM selected_plans sp
	JOIN pricing_plan pp ON pp.key = sp.plan_key AND pp.active
	JOIN pricing_rate pr ON pr.plan_key = sp.plan_key
		AND pr.effective_from <= sp.calculated_at
		AND (pr.effective_to IS NULL OR pr.effective_to > sp.calculated_at)
),
rates AS (
	SELECT
		team_id,
		max(plan_name) AS plan_name,
		max(currency) AS currency,
		count(*) FILTER (
			WHERE rate_rank = 1
			  AND unit = 'second'
			  AND resource IN ('vcpu', 'memory_gib', 'storage_gib')
		) AS rate_count,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'vcpu') AS vcpu_rate,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'memory_gib') AS memory_rate,
		max(price_usd) FILTER (WHERE rate_rank = 1 AND unit = 'second' AND resource = 'storage_gib') AS storage_rate
	FROM ranked_rates
	GROUP BY team_id
),
compute_usage AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.vcpu_count
		), 0)::numeric AS vcpu_seconds,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.memory_mib
		), 0)::numeric AS memory_mib_seconds
	FROM selected_plans sp
	LEFT JOIN sandbox_compute_billing_interval i
	  ON i.team_id = sp.team_id
	 AND sp.period_start < LEAST(sp.calculated_at, sp.period_end)
	 AND i.started_at < LEAST(sp.calculated_at, sp.period_end)
	 AND COALESCE(i.ended_at, LEAST(sp.calculated_at, sp.period_end)) > sp.period_start
	GROUP BY sp.team_id
),
storage_usage AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(
			EXTRACT(EPOCH FROM (
				LEAST(COALESCE(i.ended_at, sp.calculated_at), sp.period_end)
				- GREATEST(i.started_at, sp.period_start)
			)) * i.disk_mib
		), 0)::numeric AS storage_mib_seconds
	FROM selected_plans sp
	LEFT JOIN sandbox_storage_interval i
	  ON i.team_id = sp.team_id
	 AND sp.period_start < LEAST(sp.calculated_at, sp.period_end)
	 AND i.started_at < LEAST(sp.calculated_at, sp.period_end)
	 AND COALESCE(i.ended_at, LEAST(sp.calculated_at, sp.period_end)) > sp.period_start
	GROUP BY sp.team_id
),
credits AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(g.remaining_usd) FILTER (
			WHERE g.remaining_usd > 0
			  AND (g.expires_at IS NULL OR g.expires_at > sp.calculated_at)
		), 0)::numeric AS available_usd
	FROM selected_plans sp
	LEFT JOIN team_credit_grant g ON g.team_id = sp.team_id
	GROUP BY sp.team_id
),
current_period_ledger AS (
	SELECT
		sp.team_id,
		COALESCE(SUM(l.amount_usd) FILTER (WHERE l.amount_usd > 0), 0)::numeric AS applied_usd
	FROM selected_plans sp
	LEFT JOIN team_credit_ledger l
	  ON l.team_id = sp.team_id
	 AND l.billing_period_start = sp.period_start
	 AND l.billing_period_end = sp.period_end
	GROUP BY sp.team_id
),
available_credits AS (
	SELECT
		sp.team_id,
		(credits.available_usd + COALESCE(current_period_ledger.applied_usd, 0)) AS available_usd
	FROM selected_plans sp
	JOIN credits ON credits.team_id = sp.team_id
	LEFT JOIN current_period_ledger ON current_period_ledger.team_id = sp.team_id
),
costed AS (
	SELECT
		sp.*,
		r.plan_name,
		r.currency,
		ac.available_usd,
		(cu.vcpu_seconds * r.vcpu_rate) AS compute_usd,
		((cu.memory_mib_seconds / 1024.0) * r.memory_rate) AS memory_usd,
		((su.storage_mib_seconds / 1024.0) * r.storage_rate) AS storage_usd,
		CASE
			WHEN COALESCE(r.rate_count, 0) <> 3
			  OR r.vcpu_rate IS NULL
			  OR r.memory_rate IS NULL
			  OR r.storage_rate IS NULL
			THEN 'pricing_unavailable'
		END AS error_code
	FROM selected_plans sp
	LEFT JOIN rates r ON r.team_id = sp.team_id
	JOIN available_credits ac ON ac.team_id = sp.team_id
	JOIN compute_usage cu ON cu.team_id = sp.team_id
	JOIN storage_usage su ON su.team_id = sp.team_id
),
billed AS (
	SELECT
		costed.*,
		(compute_usd + memory_usd + storage_usd) AS current_charges_usd,
		LEAST(compute_usd + memory_usd + storage_usd, available_usd) AS credits_applied_usd,
		GREATEST(available_usd - (compute_usd + memory_usd + storage_usd), 0) AS credits_remaining_usd,
		GREATEST((compute_usd + memory_usd + storage_usd) - available_usd, 0) AS expected_invoice_amount_usd
	FROM costed
),
page_teams AS (
	SELECT
		tp.team_id,
		row_number() OVER (ORDER BY
			CASE WHEN $2 = 'team_name' AND $3 = 'asc' THEN lower(tp.team_name) END ASC,
			CASE WHEN $2 = 'team_name' AND $3 = 'desc' THEN lower(tp.team_name) END DESC,
			CASE WHEN $2 = 'created_at' AND $3 = 'asc' THEN tp.created_at END ASC,
			CASE WHEN $2 = 'created_at' AND $3 = 'desc' THEN tp.created_at END DESC,
			tp.team_id ASC
		) AS row_num
	FROM team_periods tp
),
paged AS (
	SELECT billed.*, page_teams.row_num
	FROM billed
	JOIN page_teams ON page_teams.team_id = billed.team_id
	WHERE page_teams.row_num > $5
	  AND page_teams.row_num <= $5 + $4
),
response_rows AS (
	SELECT
		row_num,
		jsonb_build_object(
			'team_id', team_id,
			'team_name', team_name,
			'summary', CASE WHEN error_code IS NULL THEN jsonb_build_object(
				'current_charges_usd', current_charges_usd,
				'credits_applied_usd', credits_applied_usd,
				'credits_remaining_usd', credits_remaining_usd,
				'expected_invoice_amount_usd', expected_invoice_amount_usd,
				'cost_breakdown_usd', jsonb_build_object(
					'compute', compute_usd,
					'memory', memory_usd,
					'storage', storage_usd
				),
				'billing_period', jsonb_build_object('start', period_start, 'end', period_end),
				'pricing_tier', jsonb_build_object(
					'plan_key', plan_key,
					'plan_name', plan_name,
					'currency', currency
				),
				'calculated_at', calculated_at
			) END,
			'error', CASE WHEN error_code IS NOT NULL THEN jsonb_build_object(
				'code', error_code,
				'message', 'Billing pricing is not available for this team'
			) END
		) AS value
	FROM paged
)
SELECT jsonb_build_object(
	'rows', COALESCE(
		(SELECT jsonb_agg(value ORDER BY row_num) FROM response_rows),
		'[]'::jsonb
	),
	'pagination', jsonb_build_object(
		'limit', $4,
		'offset', $5,
		'total', (SELECT count(*) FROM billed)
	),
	'totals', jsonb_build_object(
		'teams', (SELECT count(*) FROM billed),
		'succeeded', (SELECT count(*) FROM billed WHERE error_code IS NULL),
		'failed', (SELECT count(*) FROM billed WHERE error_code IS NOT NULL),
		'current_charges_usd', COALESCE((SELECT SUM(current_charges_usd) FROM billed WHERE error_code IS NULL), 0),
		'credits_applied_usd', COALESCE((SELECT SUM(credits_applied_usd) FROM billed WHERE error_code IS NULL), 0),
		'credits_remaining_usd', COALESCE((SELECT SUM(credits_remaining_usd) FROM billed WHERE error_code IS NULL), 0),
		'expected_invoice_amount_usd', COALESCE((SELECT SUM(expected_invoice_amount_usd) FROM billed WHERE error_code IS NULL), 0)
	)
)
`
