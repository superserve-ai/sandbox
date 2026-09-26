//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestIntegration_PromotionDeviceFirstRegionalOwner(t *testing.T) {
	ctx := context.Background()
	first, second := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	eventFirst, eventSecond := "event-"+uuid.NewString(), "event-"+uuid.NewString()
	attemptFirst, attemptSecond := uuid.New(), uuid.New()
	register := func(user, attempt uuid.UUID, event string) string {
		t.Helper()
		var outcome string
		if err := testPool.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, attempt, event, fingerprint).Scan(&outcome); err != nil {
			t.Fatal(err)
		}
		return outcome
	}
	if got := register(first, attemptFirst, eventFirst); got != "owner" {
		t.Fatalf("first registration = %q", got)
	}
	if got := register(second, attemptSecond, eventSecond); got != "owner_conflict" {
		t.Fatalf("second registration = %q", got)
	}
	if got := register(first, attemptFirst, eventFirst); got != "owner" {
		t.Fatalf("replay = %q", got)
	}
	var owner uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT user_id FROM promotion_device_owner WHERE fingerprint=$1`,
		fingerprint).Scan(&owner); err != nil || owner != first {
		t.Fatalf("owner = %v, error = %v", owner, err)
	}
	var retained bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$1 AND fingerprint=$2)`,
		second, fingerprint).Scan(&retained); err != nil || !retained {
		t.Fatalf("loser's evidence was not retained: %v", err)
	}
	if got := register(second, attemptSecond, eventSecond); got != "owner_conflict" {
		t.Fatalf("loser replay = %q", got)
	}
	if _, err := testPool.Exec(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		first, uuid.New(), "event-"+uuid.NewString(), fingerprint); err == nil {
		t.Fatal("first account evidence was replaced")
	}
	if _, err := testPool.Exec(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		uuid.New(), attemptFirst, eventFirst, fingerprint); err == nil {
		t.Fatal("source event was rebound to another account")
	}
}

func TestIntegration_PromotionDeviceConcurrentRegistration(t *testing.T) {
	ctx := context.Background()
	fingerprint := "visitor-" + uuid.NewString()
	users := [2]uuid.UUID{uuid.New(), uuid.New()}
	results := make(chan string, len(users))
	errors := make(chan error, len(users))
	var wg sync.WaitGroup
	for _, user := range users {
		wg.Add(1)
		go func(user uuid.UUID) {
			defer wg.Done()
			var outcome string
			err := testPool.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
				user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&outcome)
			results <- outcome
			errors <- err
		}(user)
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	counts := map[string]int{}
	for result := range results {
		counts[result]++
	}
	if counts["owner"] != 1 || counts["owner_conflict"] != 1 {
		t.Fatalf("concurrent registrations = %v", counts)
	}
}

func TestIntegration_PromotionDeviceRegistrationRollback(t *testing.T) {
	ctx := context.Background()
	user := uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		user, uuid.New(), "event-"+uuid.NewString(), fingerprint); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err = testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_device_owner WHERE fingerprint=$1)`,
		fingerprint).Scan(&exists); err != nil || exists {
		t.Fatalf("rolled-back owner remains: exists=%t err=%v", exists, err)
	}
}

func TestIntegration_PromotionDeviceGateMatrix(t *testing.T) {
	ctx := context.Background()
	owner, loser, missing := uuid.New(), uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, loser} {
		var outcome string
		err := testPool.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&outcome)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx := localIdentityTransaction(t, false)
	for _, gates := range [][2]bool{{false, true}, {true, false}, {true, true}} {
		localIdentityError(t, tx, "22023", `SELECT set_promotion_device_policy($1,$2)`, gates[0], gates[1])
	}
	if _, err := tx.Exec(ctx, `UPDATE promotion_identity_enforcement
		SET enabled=true, enabled_at=now(), readiness_reference='integration test' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		device, evidence bool
		loser, missing   string
	}{
		{false, false, "eligible", "eligible"},
		{false, true, "eligible", "evidence_missing"},
		{true, false, "owner_conflict", "eligible"},
		{true, true, "owner_conflict", "evidence_missing"},
	} {
		if _, err := tx.Exec(ctx, `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence); err != nil {
			t.Fatal(err)
		}
		var gotLoser, gotMissing, gotOwner string
		if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'signup')`, loser).Scan(&gotLoser); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'signup')`, missing).Scan(&gotMissing); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT promotion_device_decision($1,'signup')`, owner).Scan(&gotOwner); err != nil {
			t.Fatal(err)
		}
		if gotLoser != tc.loser || gotMissing != tc.missing || gotOwner != "eligible" {
			t.Fatalf("D=%t E=%t: loser=%s missing=%s owner=%s", tc.device, tc.evidence, gotLoser, gotMissing, gotOwner)
		}
	}
}

func TestIntegration_PromotionDeviceGateFailuresDoNotConsumeCredit(t *testing.T) {
	ctx := context.Background()
	assertUnchanged := func(t *testing.T, tx pgx.Tx, user, team uuid.UUID, allowDenial bool) {
		t.Helper()
		var changes int
		err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM team_credit_grant WHERE team_id=$2)
			+(SELECT count(*) FROM promotion_device_grant WHERE user_id=$1 OR team_id=$2)
			+(SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$1)
			+(SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$1)
			+(SELECT count(*) FROM promotion_identity_binding WHERE user_id=$1)
			+(SELECT count(*) FROM promotion_identity WHERE identity_key='user:'||$1::text OR stripe_reserved_team_id=$2)
			+(SELECT count(*) FROM promotion_identity_history WHERE user_id=$1 OR team_id=$2)
			+(SELECT count(*) FROM team_signup_promotion_outcome WHERE team_id=$2 AND NOT $3)
			+(SELECT count(*) FROM team_signup_trial_denial WHERE team_id=$2 AND NOT $3)
			+(SELECT count(*) FROM team_signup_trial_provenance WHERE team_id=$2 AND completed_at IS NOT NULL AND NOT $3)
			+(SELECT count(*) FROM team_billing_account WHERE team_id=$2 AND stripe_activation_credit_reserved_at IS NOT NULL)`, user, team, allowDenial).Scan(&changes)
		if err != nil || changes != 0 {
			t.Fatalf("failed gate changed grant, consumption, or reservation state: changes=%d err=%v", changes, err)
		}
	}
	for _, tc := range []struct {
		name              string
		canonical, device bool
		evidence          bool
		failure, sqlState string
	}{
		{"off/evidence only", false, false, true, "configuration", "55000"},
		{"off/device only", false, true, false, "configuration", "55000"},
		{"off/both", false, true, true, "configuration", "55000"},
		{"on/neither/policy unavailable", true, false, false, "policy", "P0002"},
		{"on/evidence only/policy unavailable", true, false, true, "policy", "P0002"},
		{"on/device only/policy unavailable", true, true, false, "policy", "P0002"},
		{"on/both/policy unavailable", true, true, true, "policy", "P0002"},
		{"on/neither/canonical unavailable", true, false, false, "canonical", "P0002"},
		{"on/evidence only/canonical unavailable", true, false, true, "canonical", "P0002"},
		{"on/device only/canonical unavailable", true, true, false, "canonical", "P0002"},
		{"on/both/canonical unavailable", true, true, true, "canonical", "P0002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := localIdentityTransaction(t, tc.canonical)
			user, team := uuid.New(), uuid.New()
			rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
			rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "gate-"+team.String())
			rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			assertUnchanged(t, tx, user, team, false)
			switch tc.failure {
			case "configuration":
				localIdentityError(t, tx, "22023", `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
				assertUnchanged(t, tx, user, team, false)
				// Simulate a malformed persisted configuration so both claim paths must fail closed.
				rolloutExec(t, tx, `UPDATE promotion_device_policy SET device_enforced=$1,evidence_required=$2 WHERE singleton`, tc.device, tc.evidence)
			case "policy":
				rolloutExec(t, tx, `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
				rolloutExec(t, tx, `DELETE FROM promotion_device_policy WHERE singleton`)
			case "canonical":
				rolloutExec(t, tx, `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
				rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible`)
				rolloutExec(t, tx, `DELETE FROM promotion_identity_enforcement WHERE singleton`)
				rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible`)
			}
			localIdentityError(t, tx, tc.sqlState, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user)
			assertUnchanged(t, tx, user, team, false)
			localIdentityError(t, tx, tc.sqlState, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
				team, user, "evt-"+uuid.NewString())
			assertUnchanged(t, tx, user, team, false)
		})
	}
	for _, tc := range []struct {
		name, reason      string
		device, evidence  bool
		registerDuplicate bool
	}{
		{"evidence only/missing", "evidence_missing", false, true, false},
		{"both/missing", "evidence_missing", true, true, false},
		{"device only/duplicate", "owner_conflict", true, false, true},
		{"both/duplicate", "owner_conflict", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := localIdentityTransaction(t, true)
			user, team := uuid.New(), uuid.New()
			rolloutExec(t, tx, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
			rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "gate-"+team.String())
			rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			if tc.registerDuplicate {
				fingerprint := "visitor-" + uuid.NewString()
				rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
					uuid.New(), uuid.New(), "event-"+uuid.NewString(), fingerprint)
				rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
					user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
			}
			rolloutExec(t, tx, `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
			assertUnchanged(t, tx, user, team, false)
			var outcome, reason string
			if err := tx.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user).Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != tc.reason {
				t.Fatalf("signup denial: outcome=%q reason=%q err=%v", outcome, reason, err)
			}
			assertUnchanged(t, tx, user, team, true)
			var reservation string
			if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
				team, user, "evt-"+uuid.NewString()).Scan(&reservation); err != nil || reservation != tc.reason {
				t.Fatalf("Stripe denial: reason=%q err=%v", reservation, err)
			}
			assertUnchanged(t, tx, user, team, true)
		})
	}
}
