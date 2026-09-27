//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
)

const rolloutOwnerInsert = `INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id)
	SELECT $1, id, 'team', $2 FROM roles WHERE name = 'team_owner'`

func rolloutExec(t *testing.T, q db.DBTX, statement string, args ...any) {
	t.Helper()
	if _, err := q.Exec(context.Background(), statement, args...); err != nil {
		t.Fatal(err)
	}
}

func rolloutProfile(t *testing.T) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	rolloutExec(t, testPool, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, userID.String()+"@example.com")
	return userID
}

// Each write commits separately, as it does in the deployed Console.
func rolloutLegacyTeam(t *testing.T, userID uuid.UUID, complete bool) uuid.UUID {
	t.Helper()
	teamID := uuid.New()
	rolloutExec(t, testPool, `INSERT INTO team (id, name) VALUES ($1, $2)`, teamID, "signup-rollout-"+teamID.String())
	rolloutExec(t, testPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, teamID, userID)
	rolloutExec(t, testPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, teamID, userID)
	if complete {
		rolloutExec(t, testPool, rolloutOwnerInsert, userID, teamID)
	}
	return teamID
}

func rolloutExplicitTeam(t *testing.T, userID uuid.UUID) uuid.UUID {
	t.Helper()
	var teamID uuid.UUID
	if err := testPool.QueryRow(context.Background(), `SELECT id FROM create_team_with_signup_trial($1, $2, 'use')`,
		"signup-explicit-"+uuid.NewString(), userID).Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	return teamID
}

func rolloutAssertClaim(t *testing.T, q db.DBTX, userID, wantTeam uuid.UUID) {
	t.Helper()
	var claimed, entitled bool
	if err := q.QueryRow(context.Background(), `SELECT
		EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id = $1),
		EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = $1 AND signup_trial_claimed_at IS NOT NULL)`,
		userID).Scan(&claimed, &entitled); err != nil {
		t.Fatal(err)
	}
	want := wantTeam != uuid.Nil
	if claimed != want || entitled != want {
		t.Fatalf("signup claim=%t entitlement=%t, want both %t", claimed, entitled, want)
	}
	if want {
		var claimTeam, entitlementTeam uuid.UUID
		if err := q.QueryRow(context.Background(), `SELECT c.team_id, e.signup_trial_team_id
			FROM user_signup_trial_claim c JOIN user_promotion_entitlement e USING (user_id)
			WHERE c.user_id = $1`, userID).Scan(&claimTeam, &entitlementTeam); err != nil {
			t.Fatal(err)
		}
		if claimTeam != wantTeam || entitlementTeam != wantTeam {
			t.Fatalf("claimed teams=%s/%s, want %s", claimTeam, entitlementTeam, wantTeam)
		}
	}
}

func rolloutAssertTeam(t *testing.T, q db.DBTX, teamID uuid.UUID, granted bool) {
	t.Helper()
	var grants int
	var amount, remaining float64
	var eligible, denied bool
	if err := q.QueryRow(context.Background(), `SELECT count(*), COALESCE(sum(amount_usd), 0), COALESCE(sum(remaining_usd), 0)
		FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'`,
		teamID).Scan(&grants, &amount, &remaining); err != nil {
		t.Fatal(err)
	}
	if err := q.QueryRow(context.Background(), `SELECT team_sandbox_billing_eligible($1),
		EXISTS (SELECT 1 FROM team_signup_trial_denial WHERE team_id = $1)`, teamID).Scan(&eligible, &denied); err != nil {
		t.Fatal(err)
	}
	wantGrants, wantAmount := 0, float64(0)
	if granted {
		wantGrants, wantAmount = 1, 5
	}
	if grants != wantGrants || amount != wantAmount || remaining != wantAmount || eligible != granted || denied == granted {
		t.Fatalf("team %s: grants=%d amount=%v remaining=%v eligible=%t denied=%t, want grants=%d amount=%v eligible=%t denied=%t",
			teamID, grants, amount, remaining, eligible, denied, wantGrants, wantAmount, granted, !granted)
	}
}

func rolloutAssertPending(t *testing.T, q db.DBTX, teamID, userID uuid.UUID) {
	t.Helper()
	rolloutAssertClaim(t, q, userID, uuid.Nil)
	var grants int
	var eligible bool
	if err := q.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'),
		team_sandbox_billing_eligible($1)`, teamID).Scan(&grants, &eligible); err != nil {
		t.Fatal(err)
	}
	if grants != 0 || eligible {
		t.Fatalf("unfinished team: grants=%d eligible=%t, want 0/false", grants, eligible)
	}
}

func TestIntegration_SignupTrialLegacyAndExplicitShareClaim(t *testing.T) {
	for _, legacyFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy_first_%t", legacyFirst), func(t *testing.T) {
			userID := rolloutProfile(t)
			var first, second uuid.UUID
			if legacyFirst {
				first = rolloutLegacyTeam(t, userID, true)
				second = rolloutExplicitTeam(t, userID)
			} else {
				first = rolloutExplicitTeam(t, userID)
				second = rolloutLegacyTeam(t, userID, true)
			}
			rolloutAssertClaim(t, testPool, userID, first)
			rolloutAssertTeam(t, testPool, first, true)
			rolloutAssertTeam(t, testPool, second, false)
			third := rolloutLegacyTeam(t, userID, true)
			rolloutAssertTeam(t, testPool, third, false)
			rolloutAssertClaim(t, testPool, userID, first)
		})
	}
}

func TestIntegration_SignupTrialLegacyInvitationPreservesClaim(t *testing.T) {
	for _, membershipStatus := range []string{"invited", "active"} {
		t.Run(membershipStatus, func(t *testing.T) {
			existingOwner := rolloutProfile(t)
			existingTeam := rolloutLegacyTeam(t, existingOwner, true)
			userID := rolloutProfile(t)
			rolloutExec(t, testPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'member')`, existingTeam, userID)
			rolloutExec(t, testPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, $3)`, existingTeam, userID, membershipStatus)
			rolloutAssertClaim(t, testPool, userID, uuid.Nil)
			teamID := rolloutLegacyTeam(t, userID, true)
			rolloutAssertTeam(t, testPool, teamID, true)
			rolloutAssertClaim(t, testPool, userID, teamID)
			rolloutAssertTeam(t, testPool, existingTeam, true)
		})
	}
}

func TestIntegration_SignupTrialLaterOwnersDoNotConsumeClaims(t *testing.T) {
	for _, originallyGranted := range []bool{true, false} {
		t.Run(fmt.Sprintf("granted_%t", originallyGranted), func(t *testing.T) {
			creator := rolloutProfile(t)
			if !originallyGranted {
				rolloutExplicitTeam(t, creator)
			}
			teamID := rolloutLegacyTeam(t, creator, true)
			newOwner := rolloutProfile(t)
			rolloutExec(t, testPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, teamID, newOwner)
			rolloutExec(t, testPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, teamID, newOwner)
			rolloutExec(t, testPool, rolloutOwnerInsert, newOwner, teamID)
			rolloutAssertClaim(t, testPool, newOwner, uuid.Nil)
			rolloutExec(t, testPool, `UPDATE team_member SET role = 'member' WHERE team_id = $1 AND profile_id = $2`, teamID, creator)
			rolloutExec(t, testPool, `UPDATE user_role_assignments SET revoked_at = now() WHERE team_id = $1 AND user_id = $2`, teamID, creator)
			rolloutExec(t, testPool, `UPDATE team_memberships SET status = 'inactive' WHERE team_id = $1 AND user_id = $2`, teamID, creator)
			rolloutAssertClaim(t, testPool, newOwner, uuid.Nil)
			rolloutAssertTeam(t, testPool, teamID, originallyGranted)
			personalTeam := rolloutLegacyTeam(t, newOwner, true)
			rolloutAssertTeam(t, testPool, personalTeam, true)
			rolloutAssertClaim(t, testPool, newOwner, personalTeam)
		})
	}
}

func TestIntegration_SignupTrialLegacyFailureBeforeCompletion(t *testing.T) {
	for _, failedStep := range []string{"team", "legacy_owner", "membership", "owner_assignment"} {
		t.Run(failedStep, func(t *testing.T) {
			userID, teamID := rolloutProfile(t), uuid.New()
			name := "signup-failed-" + teamID.String()
			steps := []struct {
				name, sql, failureSQL string
			}{
				{"team", `INSERT INTO team (id, name) VALUES ($1, $2)`, `INSERT INTO team (id, name) VALUES ($1, NULL)`},
				{"legacy_owner", `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, NULL, 'owner')`},
				{"membership", `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'invalid')`},
				{"owner_assignment", ``, `INSERT INTO user_role_assignments (team_id, user_id, role_id, scope_type) VALUES ($1, $2, gen_random_uuid(), 'team')`},
			}
			for _, step := range steps {
				args := []any{teamID, userID}
				if step.name == "team" {
					args[1] = name
				}
				if step.name == failedStep {
					if step.name == "team" || step.name == "legacy_owner" {
						args = args[:1]
					}
					if _, err := testPool.Exec(context.Background(), step.failureSQL, args...); err == nil {
						t.Fatalf("expected %s failure", failedStep)
					}
					break
				}
				rolloutExec(t, testPool, step.sql, args...)
				rolloutAssertPending(t, testPool, teamID, userID)
			}
			rolloutAssertClaim(t, testPool, userID, uuid.Nil)
			for _, sql := range []string{
				`DELETE FROM user_role_assignments WHERE team_id = $1`,
				`DELETE FROM team_memberships WHERE team_id = $1`,
				`DELETE FROM team_member WHERE team_id = $1`,
				`DELETE FROM team WHERE id = $1`,
			} {
				rolloutExec(t, testPool, sql, teamID)
			}
			var remains bool
			if err := testPool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM team WHERE id = $1)`, teamID).Scan(&remains); err != nil || remains {
				t.Fatalf("failed team remains=%t error=%v", remains, err)
			}
			retryTeam := rolloutLegacyTeam(t, userID, true)
			rolloutAssertTeam(t, testPool, retryTeam, true)
			rolloutAssertClaim(t, testPool, userID, retryTeam)
		})
	}
}

func TestIntegration_SignupTrialOwnerAndGrantRollbackTogether(t *testing.T) {
	ctx := context.Background()
	userID := rolloutProfile(t)
	teamID := rolloutLegacyTeam(t, userID, false)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// Reject the grant itself, after the owner completion trigger has begun.
	rolloutExec(t, tx, fmt.Sprintf(`ALTER TABLE team_credit_grant ADD CONSTRAINT rollout_injected_grant_failure CHECK (team_id <> '%s'::uuid) NOT VALID`, teamID))
	rolloutExec(t, tx, `SAVEPOINT owner_insert`)
	_, err = tx.Exec(ctx, rolloutOwnerInsert, userID, teamID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "rollout_injected_grant_failure" {
		t.Fatalf("owner completion error=%v, want injected grant check violation", err)
	}
	rolloutExec(t, tx, `ROLLBACK TO SAVEPOINT owner_insert`)
	rolloutAssertPending(t, tx, teamID, userID)
	var assignments int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE team_id = $1`, teamID).Scan(&assignments); err != nil || assignments != 0 {
		t.Fatalf("owner assignments after rollback=%d error=%v", assignments, err)
	}
	rolloutExec(t, tx, `ALTER TABLE team_credit_grant DROP CONSTRAINT rollout_injected_grant_failure`)
	rolloutExec(t, tx, rolloutOwnerInsert, userID, teamID)
	rolloutAssertClaim(t, tx, userID, teamID)
	rolloutAssertTeam(t, tx, teamID, true)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rolloutAssertClaim(t, testPool, userID, teamID)
}

func TestIntegration_SignupTrialMixedConcurrentCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	userID := rolloutProfile(t)
	legacyTeams := []uuid.UUID{rolloutLegacyTeam(t, userID, false), rolloutLegacyTeam(t, userID, false)}
	type result struct {
		teamID uuid.UUID
		err    error
	}
	const attempts = 4
	ready, start := make(chan struct{}, attempts), make(chan struct{})
	results := make(chan result, attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			ready <- struct{}{}
			<-start
			var r result
			if i < len(legacyTeams) {
				r.teamID = legacyTeams[i]
				_, r.err = testPool.Exec(ctx, rolloutOwnerInsert, userID, r.teamID)
			} else {
				r.err = testPool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1, $2, 'use')`, "signup-race-"+uuid.NewString(), userID).Scan(&r.teamID)
			}
			results <- r
		}(i)
	}
	for i := 0; i < attempts; i++ {
		<-ready
	}
	close(start)
	teams := make([]uuid.UUID, 0, attempts)
	for i := 0; i < attempts; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("concurrent creation: %v", r.err)
		}
		teams = append(teams, r.teamID)
	}
	if t.Failed() {
		return
	}
	var claimTeam uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT team_id FROM user_signup_trial_claim WHERE user_id = $1`, userID).Scan(&claimTeam); err != nil {
		t.Fatal(err)
	}
	var grants int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id = ANY($1::uuid[]) AND reason = 'signup trial credit'`, teams).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("concurrent signup grants=%d error=%v, want 1", grants, err)
	}
	rolloutAssertClaim(t, testPool, userID, claimTeam)
	for _, teamID := range teams {
		rolloutAssertTeam(t, testPool, teamID, teamID == claimTeam)
	}
}

func TestIntegration_SignupTrialCommittedOwnerSurvivesLostResponseCleanup(t *testing.T) {
	ctx := context.Background()
	userID := rolloutProfile(t)
	teamID := rolloutLegacyTeam(t, userID, true)
	// The client received no confirmation of the final write and runs every
	// compensating DELETE independently, even if an earlier DELETE failed.
	for _, sql := range []string{
		`DELETE FROM user_role_assignments WHERE team_id = $1`,
		`DELETE FROM team_memberships WHERE team_id = $1`,
		`DELETE FROM team_member WHERE team_id = $1`,
		`DELETE FROM team WHERE id = $1`,
	} {
		if _, err := testPool.Exec(ctx, sql, teamID); err == nil {
			t.Errorf("committed signup cleanup unexpectedly succeeded: %s", sql)
		}
	}
	var usableOwner bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM team_member legacy
		JOIN team_memberships m ON m.team_id = legacy.team_id AND m.user_id = legacy.profile_id
		JOIN user_role_assignments a ON a.team_id = m.team_id AND a.user_id = m.user_id
		JOIN roles r ON r.id = a.role_id
		WHERE legacy.team_id = $1 AND legacy.profile_id = $2 AND legacy.role = 'owner'
		  AND m.status = 'active' AND a.revoked_at IS NULL AND a.scope_type = 'team' AND r.name = 'team_owner'
	)`, teamID, userID).Scan(&usableOwner); err != nil || !usableOwner {
		t.Fatalf("usable owner after compensating cleanup=%t error=%v", usableOwner, err)
	}
	rolloutAssertClaim(t, testPool, userID, teamID)
	rolloutAssertTeam(t, testPool, teamID, true)
	retryTeam := rolloutLegacyTeam(t, userID, true)
	rolloutAssertTeam(t, testPool, retryTeam, false)
	rolloutAssertClaim(t, testPool, userID, teamID)
}

func TestIntegration_SignupTrialPrivilegedDeletionRetainsClaim(t *testing.T) {
	ctx := context.Background()
	userID := rolloutProfile(t)
	teamID := rolloutLegacyTeam(t, userID, true)
	// Explicit ledger removal distinguishes privileged deletion from the old
	// Console's compensation, which never deletes a granted signup credit.
	for _, sql := range []string{
		`DELETE FROM team_credit_grant WHERE team_id = $1`,
		`DELETE FROM user_role_assignments WHERE team_id = $1`,
		`DELETE FROM team_memberships WHERE team_id = $1`,
		`DELETE FROM team_member WHERE team_id = $1`,
		`DELETE FROM team WHERE id = $1`,
	} {
		rolloutExec(t, testPool, sql, teamID)
	}
	var retained bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM user_signup_trial_claim c JOIN user_promotion_entitlement e USING (user_id)
		WHERE c.user_id = $1 AND c.team_id IS NULL AND e.signup_trial_team_id IS NULL AND e.signup_trial_claimed_at IS NOT NULL
	) AND NOT EXISTS (SELECT 1 FROM team WHERE id = $2)`, userID, teamID).Scan(&retained); err != nil || !retained {
		t.Fatalf("consumed signup claim after team deletion=%t error=%v", retained, err)
	}
	rolloutAssertTeam(t, testPool, rolloutLegacyTeam(t, userID, true), false)
	rolloutAssertTeam(t, testPool, rolloutExplicitTeam(t, userID), false)
}

func TestIntegration_SignupTrialMutationPrivileges(t *testing.T) {
	ctx := context.Background()
	functions := []string{
		"public.claim_team_signup_trial(uuid,uuid)",
		"public.create_team_with_signup_trial(text,uuid)",
		"public.create_team_with_signup_trial(text,uuid,text)",
		"public.grant_signup_trial_credit()",
		"public.bind_legacy_signup_trial_creator()",
		"public.complete_legacy_signup_trial()",
		"public.guard_legacy_signup_trial_owner()",
	}
	for _, function := range functions {
		var publicExecute bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_proc p,
			LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) privilege
			WHERE p.oid = $1::regprocedure AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
		)`, function).Scan(&publicExecute); err != nil {
			t.Fatal(err)
		}
		if publicExecute {
			t.Errorf("PUBLIC can invoke signup mutation %s", function)
		}
	}
	for _, role := range []string{"anon", "authenticated"} {
		t.Run(role, func(t *testing.T) {
			var exists bool
			if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Skip("Supabase browser role is absent from the local integration harness")
			}
			for _, function := range functions {
				var executable bool
				if err := testPool.QueryRow(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, role, function).Scan(&executable); err != nil {
					t.Fatal(err)
				}
				if executable {
					t.Errorf("%s can invoke signup mutation %s", role, function)
				}
			}
		})
	}
}

func TestIntegration_SignupTrialAdoptsInflightLegacyGrant(t *testing.T) {
	migrationBytes, err := os.ReadFile("../../supabase/migrations/20260925195213_promotion_redemption_limits.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(migrationBytes)
	adoptionStart := strings.Index(migration, "-- Adopt unfinished legacy signup chains.")
	adoptionEnd := strings.Index(migration, "-- Install legacy signup claims only after the final owner assignment commits.")
	backfillStart := strings.Index(migration, "INSERT INTO user_signup_trial_claim(user_id, claimed_at, team_id)")
	backfillEnd := strings.Index(migration, "-- Legacy Stripe grant rows retain")
	if adoptionStart < 0 || adoptionEnd <= adoptionStart || backfillStart < adoptionEnd || backfillEnd <= backfillStart {
		t.Fatal("legacy signup adoption or historical backfill fragment not found")
	}
	for _, stage := range []string{"team_only", "legacy_owner", "active_membership", "completed"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			teamID, userID, grantID := uuid.New(), uuid.New(), uuid.New()
			rolloutExec(t, tx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, userID.String()+"@example.com")
			rolloutExec(t, tx, `INSERT INTO team (id, name) VALUES ($1, $2)`, teamID, "signup-historical-"+teamID.String())
			// Model a team inserted by the pre-expansion trigger. Its anonymous
			// grant committed with the team, before any owner writes.
			rolloutExec(t, tx, `DELETE FROM team_signup_trial_provenance WHERE team_id = $1`, teamID)
			rolloutExec(t, tx, `INSERT INTO team_credit_grant (id, team_id, amount_usd, remaining_usd, reason, created_at)
				SELECT $2, id, 5, 2.75, 'signup trial credit', created_at FROM team WHERE id = $1`, teamID, grantID)
			if stage != "team_only" {
				rolloutExec(t, tx, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, teamID, userID)
			}
			if stage == "active_membership" || stage == "completed" {
				rolloutExec(t, tx, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, teamID, userID)
			}
			if stage == "completed" {
				rolloutExec(t, tx, rolloutOwnerInsert, userID, teamID)
			}
			for attempt := 0; attempt < 2; attempt++ {
				rolloutExec(t, tx, migration[adoptionStart:adoptionEnd])
				rolloutExec(t, tx, migration[backfillStart:backfillEnd])
			}
			var pending, eligible bool
			if err := tx.QueryRow(ctx, `SELECT
				EXISTS (SELECT 1 FROM team_signup_trial_provenance WHERE team_id = $1 AND completed_at IS NULL),
				team_sandbox_billing_eligible($1)`, teamID).Scan(&pending, &eligible); err != nil {
				t.Fatal(err)
			}
			if stage == "completed" {
				if pending || !eligible {
					t.Fatalf("historically completed team: pending=%t eligible=%t, want false/true", pending, eligible)
				}
				rolloutAssertClaim(t, tx, userID, teamID)
				return
			}
			if !pending || eligible {
				t.Fatalf("adopted in-flight team: pending=%t eligible=%t, want true/false", pending, eligible)
			}
			rolloutAssertClaim(t, tx, userID, uuid.Nil)
			if stage == "team_only" {
				rolloutExec(t, tx, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, teamID, userID)
			}
			if stage != "active_membership" {
				rolloutExec(t, tx, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, teamID, userID)
			}
			rolloutAssertClaim(t, tx, userID, uuid.Nil)
			rolloutExec(t, tx, rolloutOwnerInsert, userID, teamID)
			rolloutExec(t, tx, `UPDATE user_role_assignments SET updated_at = now() WHERE team_id = $1`, teamID)
			rolloutAssertClaim(t, tx, userID, teamID)
			var grants int
			var unchanged bool
			if err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(bool_and(id = $2 AND amount_usd = 5 AND remaining_usd = 2.75 AND created_by = $3), false)
				FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'`, teamID, grantID, userID).Scan(&grants, &unchanged); err != nil {
				t.Fatal(err)
			}
			if grants != 1 || !unchanged {
				t.Fatalf("adopted grant: count=%d original amount/balance/actor preserved=%t", grants, unchanged)
			}
		})
	}
}
