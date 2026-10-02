//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestTrialRunwayRefreshIndependentOfDelivery(t *testing.T) {
	ctx := context.Background()
	team := seedWarningWorkerTeam(t)
	h := &api.Handlers{DB: testQueries}
	check := func(want string) db.GetTeamTrialRunwayRow {
		t.Helper()
		row, err := testQueries.GetTeamTrialRunway(ctx, team)
		if err != nil || row.State != want || !row.ObservedAt.Valid {
			t.Fatalf("runway=%+v err=%v, want %s", row, err, want)
		}
		return row
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	first := check("under_24h")
	if warningStatus(t, team) != "absent" {
		t.Fatal("advisory wrote email state")
	}
	calls := 0
	h.TrialWarningSender = warningSenderFunc(func(context.Context, uuid.UUID, float64) error { calls++; return nil })
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	if calls != 1 || warningStatus(t, team) != "sent" {
		t.Fatal("warning not completed")
	}
	teams, err := testQueries.ListTrialCreditWarningTeams(ctx, db.ListTrialCreditWarningTeamsParams{BatchLimit: 100000})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range teams {
		if id == team {
			found = true
		}
	}
	if !found {
		t.Fatal("sent team excluded from advisory discovery")
	}
	if _, err := testPool.Exec(ctx, "UPDATE team_credit_grant SET amount_usd=100, remaining_usd=100 WHERE team_id=$1", team); err != nil {
		t.Fatal(err)
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	over := check("over_24h")
	if !over.ObservedAt.Time.After(first.ObservedAt.Time) {
		t.Fatal("observation did not advance")
	}
	if calls != 1 || warningStatus(t, team) != "sent" {
		t.Fatal("refresh changed delivery state")
	}
	// An older worker cannot overwrite a newer observation.
	if err := testQueries.UpsertTeamTrialRunway(ctx, db.UpsertTeamTrialRunwayParams{TeamID: team, LifecycleKey: over.LifecycleKey, State: "under_24h", ObservedAt: first.ObservedAt.Time}); err != nil {
		t.Fatal(err)
	}
	check("over_24h")
	if _, err := testPool.Exec(ctx, "UPDATE sandbox_compute_billing_interval SET ended_at=now()-interval '20 minutes' WHERE team_id=$1", team); err != nil {
		t.Fatal(err)
	}
	api.ProcessTrialCreditWarningForTest(h, ctx, team)
	check("unknown")
	if calls != 1 || warningStatus(t, team) != "sent" {
		t.Fatal("unknown advisory changed delivery state")
	}
	// A replacement grant invalidates the old lifecycle's advisory immediately.
	if _, err := testPool.Exec(ctx, "INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,1,1,'signup trial credit')", team); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.UpsertTeamTrialRunway(ctx, db.UpsertTeamTrialRunwayParams{TeamID: team, LifecycleKey: over.LifecycleKey, State: "under_24h", ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	row, err := testQueries.GetTeamTrialRunway(ctx, team)
	if err != nil || row.State != "unknown" || row.ObservedAt.Valid {
		t.Fatalf("previous lifecycle visible: %+v %v", row, err)
	}
}

func TestTrialRunwayBillingAPI(t *testing.T) {
	ctx := context.Background()
	team := seedWarningWorkerTeam(t)
	key := seedKeyForExistingTeamWithRole(t, team, "viewer")
	router := newBillingRouter(t, nil)
	cached, err := testQueries.GetTeamTrialRunway(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for _, state := range []string{"unknown", "under_24h", "over_24h"} {
		observed = observed.Add(time.Second)
		if err := testQueries.UpsertTeamTrialRunway(ctx, db.UpsertTeamTrialRunwayParams{TeamID: team, LifecycleKey: cached.LifecycleKey, State: state, ObservedAt: observed}); err != nil {
			t.Fatal(err)
		}
		w := do(router, "GET", "/billing/summary", key, "")
		if w.Code != 200 {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		trial := mustJSON(t, w)["trial"].(map[string]any)
		if trial["runway_state"] != state {
			t.Fatalf("trial=%v, want %s", trial, state)
		}
		got, err := time.Parse(time.RFC3339Nano, trial["runway_observed_at"].(string))
		if err != nil || !got.Equal(observed) {
			t.Fatalf("timestamp=%v err=%v", trial["runway_observed_at"], err)
		}
		for field := range trial {
			switch field {
			case "grant_usd", "consumed_usd", "remaining_usd", "state", "eligible", "runway_state", "runway_observed_at":
			default:
				t.Fatalf("unexpected public trial field %s", field)
			}
		}
	}
	if _, err := testPool.Exec(ctx, "UPDATE team_trial_runway SET observed_at=now()-interval '16 minutes' WHERE team_id=$1", team); err != nil {
		t.Fatal(err)
	}
	w := do(router, "GET", "/billing/summary", key, "")
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if trial := mustJSON(t, w)["trial"].(map[string]any); trial["runway_state"] != "unknown" || trial["runway_observed_at"] == nil {
		t.Fatalf("stale trial=%v", trial)
	}
}
