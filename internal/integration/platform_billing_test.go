//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type platformBillingTestResponse struct {
	Rows []struct {
		TeamID   string         `json:"team_id"`
		TeamName string         `json:"team_name"`
		Summary  map[string]any `json:"summary"`
		Error    *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"rows"`
	Pagination struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
		Total  int `json:"total"`
	} `json:"pagination"`
	Totals struct {
		Teams     int     `json:"teams"`
		Succeeded int     `json:"succeeded"`
		Failed    int     `json:"failed"`
		Charges   float64 `json:"current_charges_usd"`
	} `json:"totals"`
}

func decodePlatformBilling(t *testing.T, body []byte) platformBillingTestResponse {
	t.Helper()
	var response platformBillingTestResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode platform billing response: %v\n%s", err, body)
	}
	return response
}

func TestPlatformBillingPaginationTotalsAndPartialFailures(t *testing.T) {
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	prefix := "platform-billing-" + suffix
	goodTeam, err := testQueries.CreateTeam(ctx, prefix+"-alpha")
	if err != nil {
		t.Fatalf("create team with valid pricing: %v", err)
	}
	badTeam, err := testQueries.CreateTeam(ctx, prefix+"-beta")
	if err != nil {
		t.Fatalf("create team with incomplete pricing: %v", err)
	}

	planKey := "incomplete-" + suffix
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency)
		VALUES ($1, 'Incomplete test plan', 'USD')
	`, planKey); err != nil {
		t.Fatalf("seed incomplete pricing plan: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd)
		VALUES
			($1, 'vcpu', 'second', 0.00001),
			($1, 'memory_gib', 'second', 0.00001)
	`, planKey); err != nil {
		t.Fatalf("seed incomplete pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key)
		VALUES ($2, $1)
	`, planKey, badTeam.ID); err != nil {
		t.Fatalf("assign incomplete pricing plan: %v", err)
	}

	actorID := seedPlatformAdminProfile(t)
	r := newInternalRouter(t)

	first := doInternal(
		r,
		http.MethodGet,
		fmt.Sprintf("/internal/billing?search=%s&sort=team_name&order=asc&limit=1", prefix),
		actorID.String(),
		"",
	)
	if first.Code != http.StatusOK {
		t.Fatalf("first page: %d %s", first.Code, first.Body.String())
	}
	firstBody := decodePlatformBilling(t, first.Body.Bytes())
	if firstBody.Pagination.Total != 2 || firstBody.Totals.Teams != 2 {
		t.Fatalf("page-independent totals = pagination:%d totals:%d, want 2/2", firstBody.Pagination.Total, firstBody.Totals.Teams)
	}
	if firstBody.Totals.Succeeded != 1 || firstBody.Totals.Failed != 1 {
		t.Fatalf("success/failure totals = %d/%d, want 1/1", firstBody.Totals.Succeeded, firstBody.Totals.Failed)
	}
	if len(firstBody.Rows) != 1 || firstBody.Rows[0].TeamID != goodTeam.ID.String() {
		t.Fatalf("first page rows = %+v, want valid-pricing team", firstBody.Rows)
	}
	if firstBody.Rows[0].Summary == nil || firstBody.Rows[0].Error != nil {
		t.Fatalf("valid-pricing row should contain a summary: %+v", firstBody.Rows[0])
	}

	second := doInternal(
		r,
		http.MethodGet,
		fmt.Sprintf("/internal/billing?search=%s&sort=team_name&order=asc&limit=1&offset=1", prefix),
		actorID.String(),
		"",
	)
	if second.Code != http.StatusOK {
		t.Fatalf("second page: %d %s", second.Code, second.Body.String())
	}
	secondBody := decodePlatformBilling(t, second.Body.Bytes())
	if len(secondBody.Rows) != 1 || secondBody.Rows[0].TeamID != badTeam.ID.String() {
		t.Fatalf("second page rows = %+v, want incomplete-pricing team", secondBody.Rows)
	}
	if secondBody.Rows[0].Summary != nil || secondBody.Rows[0].Error == nil || secondBody.Rows[0].Error.Code != "pricing_unavailable" {
		t.Fatalf("incomplete-pricing row should contain a partial failure: %+v", secondBody.Rows[0])
	}

	unprivileged := seedSuperserveEmailProfile(t)
	denied := doInternal(r, http.MethodGet, "/internal/billing?search="+prefix, unprivileged.String(), "")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unprivileged platform billing status = %d, want 403: %s", denied.Code, denied.Body.String())
	}
}

func TestPlatformBillingUsesCurrentPeriodLedgerToReconstructOpeningBalance(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	fixedNow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	r := newInternalRouterWithNow(t, func() time.Time { return fixedNow })

	cw := do(r, "POST", "/sandboxes", ownerKey, `{"name":"platform-billing-ledger"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID, err := uuid.Parse(mustJSON(t, cw)["id"].(string))
	if err != nil {
		t.Fatalf("parse sandbox id: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}

	periodStart, periodEnd := billing.CurrentBillingPeriod(fixedNow)
	if _, err := testQueries.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{
		TeamID:      teamID,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		Status:      "open",
	}); err != nil {
		t.Fatalf("upsert billing period: %v", err)
	}

	start := periodStart.Add(15 * time.Minute)
	end := start.Add(1 * time.Hour)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 2, 2048, $3, $4, 'paused')
	`, sandboxID, teamID, start, end); err != nil {
		t.Fatalf("seed compute billing usage: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (
			sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
		)
		VALUES ($1, $2, 10240, $3, $4, 'deleted')
	`, sandboxID, teamID, start, end); err != nil {
		t.Fatalf("seed storage billing usage: %v", err)
	}

	var grantID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at, updated_at)
		VALUES ($1, 0.100000, 0.060000, 'opening balance test grant', $2, $2)
		RETURNING id
	`, teamID, periodStart.Add(-time.Hour)).Scan(&grantID); err != nil {
		t.Fatalf("seed credit grant: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_ledger (
			team_id, grant_id, billing_period_start, billing_period_end, amount_usd, reason
		)
		VALUES ($1, $2, $3, $4, 0.040000, 'billing period finalization credit application')
	`, teamID, grantID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed current-period credit ledger: %v", err)
	}

	actorID := seedPlatformAdminProfile(t)
	resp := doInternal(
		r,
		http.MethodGet,
		fmt.Sprintf("/internal/billing?search=%s&sort=team_name&order=asc", teamID.String()),
		actorID.String(),
		"",
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("platform billing response: %d %s", resp.Code, resp.Body.String())
	}

	body := decodePlatformBilling(t, resp.Body.Bytes())
	if len(body.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(body.Rows))
	}
	row := body.Rows[0]
	if row.TeamID != teamID.String() {
		t.Fatalf("team_id = %s, want %s", row.TeamID, teamID)
	}
	if row.Error != nil {
		t.Fatalf("unexpected billing error: %+v", row.Error)
	}
	if row.Summary == nil {
		t.Fatal("summary missing")
	}
	currentCharges, ok := row.Summary["current_charges_usd"].(float64)
	if !ok || currentCharges <= 0.1 {
		t.Fatalf("current_charges_usd = %v, want > 0.1", row.Summary["current_charges_usd"])
	}
	if got := row.Summary["credits_applied_usd"].(float64); got < 0.099999 || got > 0.100001 {
		t.Fatalf("credits_applied_usd = %v, want 0.1", got)
	}
	if got := row.Summary["credits_remaining_usd"].(float64); got < -0.000001 || got > 0.000001 {
		t.Fatalf("credits_remaining_usd = %v, want 0", got)
	}
}

func seedPlatformBillingRatesForTest(t *testing.T, ctx context.Context, teamID uuid.UUID, planKey string, effectiveFrom time.Time) {
	t.Helper()

	insertPricingPlanForTest(t, ctx, planKey, true)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.000011, $2),
			($1, 'memory_gib', 'second', 0.0000045, $2),
			($1, 'storage_gib', 'second', 0.00000003, $2)
	`, planKey, effectiveFrom); err != nil {
		t.Fatalf("insert platform billing pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, $3)
	`, teamID, planKey, effectiveFrom); err != nil {
		t.Fatalf("assign platform billing pricing plan: %v", err)
	}
}

func TestPlatformBillingUsesHalfOpenMonthBoundaryForUsage(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	fixedNow := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	r := newInternalRouterWithNow(t, func() time.Time { return fixedNow })

	cw := do(r, "POST", "/sandboxes", ownerKey, `{"name":"platform-billing-month-boundary"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID, err := uuid.Parse(mustJSON(t, cw)["id"].(string))
	if err != nil {
		t.Fatalf("parse sandbox id: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}

	periodStart, periodEnd := billing.CurrentBillingPeriod(fixedNow)
	seedPlatformBillingRatesForTest(t, ctx, teamID, "platform-billing-half-open-"+uuid.NewString(), periodStart.Add(-time.Hour))

	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES
			($1, $2, 2, 2048, $3, $4, 'paused'),
			($1, $2, 2, 2048, $4, $5, 'paused')
	`, sandboxID, teamID, periodStart.Add(-time.Hour), periodStart, periodStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed month-boundary compute intervals: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (
			sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
		)
		VALUES
			($1, $2, 10240, $3, $4, 'deleted'),
			($1, $2, 10240, $4, $5, 'deleted')
	`, sandboxID, teamID, periodStart.Add(-time.Hour), periodStart, periodStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed month-boundary storage intervals: %v", err)
	}

	var grantID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at, updated_at)
		VALUES ($1, 0.060000, 0.020000, 'month boundary opening balance', $2, $2)
		RETURNING id
	`, teamID, periodStart.Add(-time.Hour)).Scan(&grantID); err != nil {
		t.Fatalf("seed credit grant: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_ledger (
			team_id, grant_id, billing_period_start, billing_period_end, amount_usd, reason
		)
		VALUES ($1, $2, $3, $4, 0.040000, 'billing period finalization credit application')
	`, teamID, grantID, periodStart, periodEnd); err != nil {
		t.Fatalf("seed july credit ledger: %v", err)
	}

	actorID := seedPlatformAdminProfile(t)
	resp := doInternal(
		r,
		http.MethodGet,
		fmt.Sprintf("/internal/billing?search=%s&sort=team_name&order=asc", teamID.String()),
		actorID.String(),
		"",
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("platform billing response: %d %s", resp.Code, resp.Body.String())
	}

	body := decodePlatformBilling(t, resp.Body.Bytes())
	if len(body.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(body.Rows))
	}
	row := body.Rows[0]
	if row.TeamID != teamID.String() {
		t.Fatalf("team_id = %s, want %s", row.TeamID, teamID)
	}
	if row.Error != nil {
		t.Fatalf("unexpected billing error: %+v", row.Error)
	}
	if row.Summary == nil {
		t.Fatal("summary missing")
	}

	billingPeriod, ok := row.Summary["billing_period"].(map[string]any)
	if !ok {
		t.Fatalf("billing_period = %T, want map", row.Summary["billing_period"])
	}
	start, err := time.Parse(time.RFC3339Nano, billingPeriod["start"].(string))
	if err != nil {
		t.Fatalf("parse billing_period.start: %v", err)
	}
	if !start.Equal(periodStart) {
		t.Fatalf("billing_period.start = %s, want %s", start, periodStart)
	}
	end, err := time.Parse(time.RFC3339Nano, billingPeriod["end"].(string))
	if err != nil {
		t.Fatalf("parse billing_period.end: %v", err)
	}
	if !end.Equal(periodEnd) {
		t.Fatalf("billing_period.end = %s, want %s", end, periodEnd)
	}

	want := billing.CalculateSummaryCharges(
		2*3600,
		2*3600,
		10*3600,
		0.000011,
		0.0000045,
		0.00000003,
		0.060000,
	)
	assertFloatNear(t, row.Summary["current_charges_usd"].(float64), want.CurrentChargesUSD)
	assertFloatNear(t, row.Summary["credits_applied_usd"].(float64), want.CreditsAppliedUSD)
	assertFloatNear(t, row.Summary["credits_remaining_usd"].(float64), want.CreditsRemainingUSD)
}

func TestPlatformBillingUsesExactMonthBoundaryAtRollover(t *testing.T) {
	ctx := context.Background()
	teamID, ownerKey := seedTeamAndKey(t)
	fixedNow := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	r := newInternalRouterWithNow(t, func() time.Time { return fixedNow })

	cw := do(r, "POST", "/sandboxes", ownerKey, `{"name":"platform-billing-month-rollover"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create sandbox: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	sandboxID, err := uuid.Parse(mustJSON(t, cw)["id"].(string))
	if err != nil {
		t.Fatalf("parse sandbox id: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_compute_billing_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded compute billing interval: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM sandbox_storage_interval WHERE sandbox_id = $1`, sandboxID); err != nil {
		t.Fatalf("clear seeded storage billing interval: %v", err)
	}

	periodStart, periodEnd := billing.CurrentBillingPeriod(fixedNow)
	seedPlatformBillingRatesForTest(t, ctx, teamID, "platform-billing-rollover-"+uuid.NewString(), periodStart.Add(-time.Hour))

	// One interval ends exactly at the boundary, one starts exactly at the
	// boundary, and one ledger row belongs to the previous month.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_compute_billing_interval (
			sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
		)
		VALUES
			($1, $2, 2, 2048, $3, $4, 'paused'),
			($1, $2, 2, 2048, $4, $5, 'paused')
	`, sandboxID, teamID, periodStart.Add(-time.Hour), periodStart, periodStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed rollover compute intervals: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sandbox_storage_interval (
			sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
		)
		VALUES
			($1, $2, 10240, $3, $4, 'deleted'),
			($1, $2, 10240, $4, $5, 'deleted')
	`, sandboxID, teamID, periodStart.Add(-time.Hour), periodStart, periodStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed rollover storage intervals: %v", err)
	}

	var grantID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_at, updated_at)
		VALUES ($1, 0.060000, 0.020000, 'month rollover opening balance', $2, $2)
		RETURNING id
	`, teamID, periodStart.Add(-time.Hour)).Scan(&grantID); err != nil {
		t.Fatalf("seed credit grant: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_ledger (
			team_id, grant_id, billing_period_start, billing_period_end, amount_usd, reason
		)
		VALUES ($1, $2, $3, $4, 0.040000, 'billing period finalization credit application')
	`, teamID, grantID, periodStart.AddDate(0, -1, 0), periodStart); err != nil {
		t.Fatalf("seed july credit ledger: %v", err)
	}

	actorID := seedPlatformAdminProfile(t)
	resp := doInternal(
		r,
		http.MethodGet,
		fmt.Sprintf("/internal/billing?search=%s&sort=team_name&order=asc", teamID.String()),
		actorID.String(),
		"",
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("platform billing response: %d %s", resp.Code, resp.Body.String())
	}

	body := decodePlatformBilling(t, resp.Body.Bytes())
	if len(body.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(body.Rows))
	}
	row := body.Rows[0]
	if row.TeamID != teamID.String() {
		t.Fatalf("team_id = %s, want %s", row.TeamID, teamID)
	}
	if row.Error != nil {
		t.Fatalf("unexpected billing error: %+v", row.Error)
	}
	if row.Summary == nil {
		t.Fatal("summary missing")
	}

	billingPeriod, ok := row.Summary["billing_period"].(map[string]any)
	if !ok {
		t.Fatalf("billing_period = %T, want map", row.Summary["billing_period"])
	}
	start, err := time.Parse(time.RFC3339Nano, billingPeriod["start"].(string))
	if err != nil {
		t.Fatalf("parse billing_period.start: %v", err)
	}
	if !start.Equal(periodStart) {
		t.Fatalf("billing_period.start = %s, want %s", start, periodStart)
	}
	end, err := time.Parse(time.RFC3339Nano, billingPeriod["end"].(string))
	if err != nil {
		t.Fatalf("parse billing_period.end: %v", err)
	}
	if !end.Equal(periodEnd) {
		t.Fatalf("billing_period.end = %s, want %s", end, periodEnd)
	}

	want := billing.CalculateSummaryCharges(
		0,
		0,
		0,
		0.000011,
		0.0000045,
		0.00000003,
		0.020000,
	)
	assertFloatNear(t, row.Summary["current_charges_usd"].(float64), want.CurrentChargesUSD)
	assertFloatNear(t, row.Summary["credits_applied_usd"].(float64), want.CreditsAppliedUSD)
	assertFloatNear(t, row.Summary["credits_remaining_usd"].(float64), want.CreditsRemainingUSD)
}
