//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_PromotionDeviceLiveSignupWriterAndSnapshot(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	missing := uuid.New()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, missing, missing.String()+"@example.com")
	var team uuid.UUID
	if err := region.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`,
		"example-no-device-"+uuid.NewString(), missing).Scan(&team); err != nil {
		t.Fatalf("team creation with missing device: %v", err)
	}
	var outcome, reason string
	if err := region.QueryRow(ctx, `SELECT outcome,reason FROM team_signup_promotion_outcome WHERE team_id=$1`, team).
		Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "evidence_missing" {
		t.Fatalf("missing-evidence result = %q/%q: %v", outcome, reason, err)
	}
	var grants, claims int
	if err := region.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM team_credit_grant WHERE team_id=$1),
		(SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$2)`, team, missing).
		Scan(&grants, &claims); err != nil || grants != 0 || claims != 0 {
		t.Fatalf("missing evidence consumed grant or claim: %d/%d: %v", grants, claims, err)
	}
	var ownership, decision, eligibility, snapshotReason string
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, missing).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "evidence_missing" || decision != "evidence_missing" || eligibility != "ineligible" {
		t.Fatalf("missing snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	var state string
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
		team, missing, "evt-"+uuid.NewString()).Scan(&state); err != nil || state != "evidence_missing" {
		t.Fatalf("missing-evidence Stripe reservation = %q: %v", state, err)
	}

	owner, other := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	}
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, other).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "another_owner" || decision != "owner_conflict" || eligibility != "ineligible" {
		t.Fatalf("conflict snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(false,true)`)
	if err := region.QueryRow(ctx, `SELECT * FROM evaluate_signup_promotion_snapshot($1)`, other).
		Scan(&ownership, &decision, &eligibility, &snapshotReason); err != nil ||
		ownership != "another_owner" || decision != "eligible" || eligibility != "unknown" || snapshotReason != "team_checks_pending" {
		t.Fatalf("disabled device check snapshot = %q/%q/%q/%q: %v", ownership, decision, eligibility, snapshotReason, err)
	}
	if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant WHERE user_id=$1`, other).
		Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("snapshot issued a grant: %d: %v", grants, err)
	}
	if err := region.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`,
		"example-device-off-"+uuid.NewString(), other).Scan(&team); err != nil {
		t.Fatalf("team creation while device check is off: %v", err)
	}
	if err := region.QueryRow(ctx, `SELECT outcome,reason FROM team_signup_promotion_outcome WHERE team_id=$1`, team).
		Scan(&outcome, &reason); err != nil || outcome != "granted" {
		t.Fatalf("device-off grant = %q/%q: %v", outcome, reason, err)
	}
	rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	event := "evt-" + uuid.NewString()
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
		team, other, event).Scan(&state); err != nil || state != "acquired" {
		t.Fatalf("Stripe compatibility reservation = %q: %v", state, err)
	}
	rolloutExec(t, region, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, other, "grant-"+uuid.NewString())
	var stripeGrants int
	if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant
		WHERE promotion='stripe' AND team_id=$1 AND user_id=$2 AND fingerprint=$3`,
		team, other, fingerprint).Scan(&stripeGrants); err != nil || stripeGrants != 1 {
		t.Fatalf("Stripe finalization did not record device grant: %d: %v", stripeGrants, err)
	}
}
