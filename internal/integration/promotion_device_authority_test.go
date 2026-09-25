//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
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
	rolloutExec(t, tx, `SAVEPOINT expected_device_gate_error`)
	if _, err := tx.Exec(ctx, `SELECT set_promotion_device_policy(true,false)`); err == nil {
		t.Fatal("device enforcement enabled before canonical authority")
	}
	rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT expected_device_gate_error`)
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
