//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"
)

func TestIntegration_ActivationRevocationRedemptionGuardsUpgrade(t *testing.T) {
	ctx := t.Context()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, teamID, "cus_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile("../../supabase/migrations/20260925195248_canonical_stripe_promotion_fences.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(previous), "CREATE FUNCTION stripe_promotion_eligible(")
	end := strings.Index(string(previous), "CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event_state(")
	if start < 0 || end <= start {
		t.Fatal("prior promotion function definitions not found")
	}
	if _, err := tx.Exec(ctx, strings.ReplaceAll(string(previous[start:end]), "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO stripe_activation_credit_revocation(team_id,stripe_customer_id,completed_at) VALUES($1,$2,now())`, teamID, "cus_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	var eligible bool
	if err := tx.QueryRow(ctx, `SELECT stripe_promotion_eligible($1,$2)`, teamID, userID).Scan(&eligible); err != nil || !eligible {
		t.Fatalf("prior schema did not reproduce eligibility gap: eligible=%v err=%v", eligible, err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_before_upgrade')`, teamID, userID).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("prior reserve: %s %v", state, err)
	}
	if _, err := tx.Exec(ctx, `SELECT release_stripe_promotion($1,$2)`, teamID, userID); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../supabase/migrations/20260928220233_stripe_activation_revocation_redemption_guards.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT stripe_promotion_eligible($1,$2)`, teamID, userID).Scan(&eligible); err != nil || eligible {
		t.Fatalf("upgraded eligibility: eligible=%v err=%v", eligible, err)
	}
	for _, eventID := range []string{"evt_reversed", "evt_replacement"} {
		if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`, teamID, userID, eventID).Scan(&state); err != nil || state != "ineligible" {
			t.Fatalf("upgraded reserve: %s %v", state, err)
		}
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT stripe_redemption_reserved_team_id IS NOT NULL FROM user_promotion_entitlement WHERE user_id=$1`, userID).Scan(&pending); err != nil || pending {
		t.Fatalf("upgrade left pending entitlement: %v %v", pending, err)
	}
}
