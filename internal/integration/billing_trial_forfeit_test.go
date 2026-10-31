//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type trialForfeitRow struct {
	Grants   string `json:"trial_grants_usd"`
	Consumed string `json:"consumed_usd"`
}

func trialForfeit(t *testing.T, teamID uuid.UUID) []trialForfeitRow {
	t.Helper()
	raw, err := os.ReadFile("../../scripts/billing/trial-forfeit.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := strings.NewReplacer(":'label'", "$1::text", ":'team'", "$2::text").Replace(string(raw))
	var out []byte
	if err := testPool.QueryRow(context.Background(), query, "", teamID.String()).Scan(&out); err != nil {
		t.Fatal(err)
	}
	var rows []trialForfeitRow
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestIntegration_TrialForfeitUsesTheGrantPoolAtTrialEnd(t *testing.T) {
	teamID, _ := seedTeamAndKey(t)
	rolloutExec(t, testPool, `INSERT INTO team_billing_account (team_id, trial_ended_at) VALUES ($1, now() - interval '2 days')`, teamID)
	rolloutExec(t, testPool, `
		INSERT INTO team_credit_grant (team_id, reason, amount_usd, remaining_usd, created_at, expires_at) VALUES
		($1, 'signup trial credit', 0.05, 0, now() - interval '3 days', NULL),
		($1, 'signup trial credit', 100, 0, now() - interval '3 days', now() - interval '1 day'),
		($1, 'signup trial credit', 7, 7, now() - interval '3 days', now() - interval '50 hours'),
		($1, 'signup trial credit', 9, 9, now() - interval '1 hour', NULL)`, teamID)
	rows := trialForfeit(t, teamID)
	if len(rows) != 1 || rows[0].Grants != "100.050000" || rows[0].Consumed != "0.000000" {
		t.Fatalf("forfeit pool at trial end = %+v, want the 0.05 signup grant and the unused 100 top-up that expired after activation", rows)
	}
}

func TestIntegration_TrialForfeitPricesUsageWithThePlanEffectiveAtTrialEnd(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	plan := "trial-forfeit-" + uuid.NewString()[:8]
	rolloutExec(t, testPool, `INSERT INTO pricing_plan (key, name) VALUES ($1, 'Trial forfeit test plan')`, plan)
	rolloutExec(t, testPool, `
		INSERT INTO pricing_rate (plan_key, resource, unit, price_usd, effective_from) VALUES
		($1, 'vcpu', 'second', 0.001, now() - interval '10 days'),
		($1, 'memory_gib', 'second', 0, now() - interval '10 days'),
		($1, 'storage_gib', 'second', 0, now() - interval '10 days')`, plan)
	rolloutExec(t, testPool, `INSERT INTO team_pricing_plan (team_id, plan_key, effective_from) VALUES ($1, $2, now() - interval '5 days')`, teamID, plan)
	rolloutExec(t, testPool, `INSERT INTO team_billing_account (team_id, trial_ended_at) VALUES ($1, now() - interval '2 days')`, teamID)
	rolloutExec(t, testPool, `
		INSERT INTO team_credit_grant (team_id, reason, amount_usd, remaining_usd, created_at)
		VALUES ($1, 'signup trial credit', 100, 0, now() - interval '3 days')`, teamID)
	sandboxID, err := insertSandboxRow(ctx, teamID, "trial-forfeit-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, testPool, `
		INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1, $2, 1, 1024, now() - interval '50 hours', now() - interval '50 hours' + interval '1000 seconds', 'paused')`, sandboxID, teamID)
	rolloutExec(t, testPool, `UPDATE pricing_plan SET active = false WHERE key = $1`, plan)
	rows := trialForfeit(t, teamID)
	if len(rows) != 1 || rows[0].Grants != "100.000000" || rows[0].Consumed != "1.000000" {
		t.Fatalf("forfeit after the trial plan was deactivated = %+v, want 1000 vCPU seconds at that plan's 0.001 rate", rows)
	}
}
