//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	// analytics.team_hourly_spend filters to teams with a team_member row
	// (see 20260801000001) — CreateTeam alone doesn't seed one, so without
	// this the team is invisible to the view regardless of usage seeded
	// below.
	profileID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, $2, 'google', $3)`,
		profileID, "analytics-view-"+suffix+"@example.com", "google-"+suffix,
	); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`,
		team.ID, profileID,
	); err != nil {
		t.Fatalf("seed team_member: %v", err)
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

// Regression test for review feedback on 20260801000001: excluding a team
// solely because it lacks a row in the legacy team_member table would hide
// live billing data, since the current membership-management path
// (upsertMembership, internal/api/rbac_phase2b.go) only writes
// team_memberships.
func TestAnalyticsTeamHourlySpend_IncludesTeamWithOnlyModernMembership(t *testing.T) {
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	team, err := testQueries.CreateTeam(ctx, "analytics-view-modern-"+suffix)
	if err != nil {
		t.Fatalf("create team: %v", err)
	}

	profileID := uuid.New()
	if _, err := testPool.Exec(ctx,
		`INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, $2, 'google', $3)`,
		profileID, "analytics-view-modern-"+suffix+"@example.com", "google-"+suffix,
	); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	// Only team_memberships, deliberately no team_member row.
	if _, err := testPool.Exec(ctx,
		`INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`,
		team.ID, profileID,
	); err != nil {
		t.Fatalf("seed team_memberships: %v", err)
	}

	hourStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage_hourly (
			team_id, hour_start, hour_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 3600, 3600, 3600)
	`, team.ID, hourStart, hourStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed usage hour: %v", err)
	}

	var spendUSD *float64
	if err := testPool.QueryRow(ctx, `
		SELECT spend_usd FROM analytics.team_hourly_spend
		WHERE team_name = $1 AND hour_start = $2
	`, team.Name, hourStart).Scan(&spendUSD); err != nil {
		t.Fatalf("team with only team_memberships is missing from the view: %v", err)
	}
	if spendUSD == nil {
		t.Fatal("spend_usd = NULL, want a priced value (payg has rates for all three resources)")
	}
}

// Regression test: a fully detached team (no rows in any of the three
// membership tables) must stay excluded even though its historical usage
// rows remain as a cold fallback until purge.
func TestAnalyticsTeamHourlySpend_ExcludesFullyDetachedTeam(t *testing.T) {
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	team, err := testQueries.CreateTeam(ctx, "analytics-view-detached-"+suffix)
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	// Deliberately no team_member / team_memberships / user_role_assignments
	// rows — this is what cmd/migrate-team's detach leaves behind.

	hourStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_usage_hourly (
			team_id, hour_start, hour_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds
		)
		VALUES ($1, $2, $3, 3600, 3600, 3600)
	`, team.ID, hourStart, hourStart.Add(time.Hour)); err != nil {
		t.Fatalf("seed usage hour: %v", err)
	}

	var spendUSD *float64
	err = testPool.QueryRow(ctx, `
		SELECT spend_usd FROM analytics.team_hourly_spend
		WHERE team_name = $1 AND hour_start = $2
	`, team.Name, hourStart).Scan(&spendUSD)
	if err == nil {
		t.Fatalf("fully detached team appeared in the view with spend_usd=%v, want excluded entirely", spendUSD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unexpected query error: %v", err)
	}
}
