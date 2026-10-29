//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestIntegration_TrialForfeitUsesTheGrantPoolAtTrialEnd(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile("../../scripts/billing/trial-forfeit.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := strings.NewReplacer(":'label'", "$1::text", ":'team'", "$2::text").Replace(string(raw))
	teamID, _ := seedTeamAndKey(t)
	rolloutExec(t, testPool, `INSERT INTO team_billing_account (team_id, trial_ended_at) VALUES ($1, now() - interval '2 days')`, teamID)
	rolloutExec(t, testPool, `
		INSERT INTO team_credit_grant (team_id, reason, amount_usd, remaining_usd, created_at, expires_at) VALUES
		($1, 'signup trial credit', 0.05, 0, now() - interval '3 days', NULL),
		($1, 'signup trial credit', 100, 0, now() - interval '3 days', now() - interval '1 day'),
		($1, 'signup trial credit', 7, 7, now() - interval '3 days', now() - interval '50 hours'),
		($1, 'signup trial credit', 9, 9, now() - interval '1 hour', NULL)`, teamID)
	var out []byte
	if err := testPool.QueryRow(ctx, query, "", teamID.String()).Scan(&out); err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Grants   string `json:"trial_grants_usd"`
		Consumed string `json:"consumed_usd"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Grants != "100.050000" || rows[0].Consumed != "0.000000" {
		t.Fatalf("forfeit pool at trial end = %+v, want the 0.05 signup grant and the unused 100 top-up that expired after activation", rows)
	}
}
