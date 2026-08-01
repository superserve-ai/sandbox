//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A mixed range (one hour with a matching rate for every resource, one hour
// missing a resource's rate) must poison the aggregate to NULL rather than
// silently returning the priced hour's subtotal, matching the Grafana
// panel query for analytics.team_hourly_spend and its
// bool_and(spend_usd IS NOT NULL) pattern. SUM() alone ignores NULL rows,
// so a partial gap would still look like a plausible total instead of
// surfacing as incomplete.
func TestAnalyticsTeamHourlySpend_MixedRangePoisonsAggregate(t *testing.T) {
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	team, err := testQueries.CreateTeam(ctx, "analytics-view-"+suffix)
	if err != nil {
		t.Fatalf("create team: %v", err)
	}

	planKey := "analytics-view-plan-" + suffix
	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_plan (key, name, currency)
		VALUES ($1, 'Analytics view test plan', 'USD')
	`, planKey); err != nil {
		t.Fatalf("seed pricing plan: %v", err)
	}

	// Both usage hours are well after the view's pinned pre-launch boundary
	// (2026-06-17) so that boundary never fires here — this test is about
	// the post-launch missing-rate case, not the pre-launch zero-price one.
	// vcpu + memory rates cover the whole window; storage's rate only
	// starts at storageRateStart, strictly between the two usage hours, so
	// hourA is missing a rate and hourB has all three.
	rateStart := time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC)
	hourA := time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC)
	storageRateStart := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	hourB := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

	if _, err := testPool.Exec(ctx, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from)
		VALUES
			($1, 'vcpu', 'second', 0.00001, $2),
			($1, 'memory_gib', 'second', 0.00001, $2),
			($1, 'storage_gib', 'second', 0.00001, $3)
	`, planKey, rateStart, storageRateStart); err != nil {
		t.Fatalf("seed pricing rates: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_pricing_plan (team_id, plan_key, effective_from)
		VALUES ($1, $2, $3)
	`, team.ID, planKey, rateStart); err != nil {
		t.Fatalf("assign pricing plan: %v", err)
	}

	for _, hourStart := range []time.Time{hourA, hourB} {
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_billing_usage_hourly (
				team_id, hour_start, hour_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
			)
			VALUES ($1, $2, $3, 3600, 3600, 3600)
		`, team.ID, hourStart, hourStart.Add(time.Hour)); err != nil {
			t.Fatalf("seed usage hour %s: %v", hourStart, err)
		}
	}

	// Row level: hourA (before storage's rate exists) is unpriceable, hourB
	// (after) is fully priced. This is what the view itself guarantees.
	rows, err := testPool.Query(ctx, `
		SELECT hour_start, spend_usd
		FROM analytics.team_hourly_spend
		WHERE team_name = $1
		ORDER BY hour_start
	`, team.Name)
	if err != nil {
		t.Fatalf("query row-level view: %v", err)
	}
	defer rows.Close()

	var gotHourA, gotHourB bool
	for rows.Next() {
		var hourStart time.Time
		var spendUSD *float64
		if err := rows.Scan(&hourStart, &spendUSD); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		switch {
		case hourStart.Equal(hourA):
			gotHourA = true
			if spendUSD != nil {
				t.Fatalf("hourA (missing storage rate) spend_usd = %v, want NULL", *spendUSD)
			}
		case hourStart.Equal(hourB):
			gotHourB = true
			if spendUSD == nil {
				t.Fatal("hourB (fully priced) spend_usd = NULL, want a value")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate rows: %v", err)
	}
	if !gotHourA || !gotHourB {
		t.Fatalf("expected both seeded hours in the view, gotHourA=%v gotHourB=%v", gotHourA, gotHourB)
	}

	// Aggregate level: the same "poison the total if any row is unpriceable"
	// query the Grafana panel uses. A plain SUM() would return hourB's
	// subtotal alone and look like a complete, if small, total.
	var total *float64
	if err := testPool.QueryRow(ctx, `
		SELECT CASE WHEN bool_and(spend_usd IS NOT NULL) THEN SUM(spend_usd) ELSE NULL END
		FROM analytics.team_hourly_spend
		WHERE team_name = $1
		GROUP BY team_name
	`, team.Name).Scan(&total); err != nil {
		t.Fatalf("query poisoned aggregate: %v", err)
	}
	if total != nil {
		t.Fatalf("mixed-range aggregate = %v, want NULL (poisoned by the unpriceable hour)", *total)
	}
}
