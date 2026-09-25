//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func canonicalSignupOutcome(t *testing.T, teamID uuid.UUID) string {
	t.Helper()
	var outcome string
	if err := testPool.QueryRow(context.Background(), `SELECT outcome FROM team_signup_promotion_outcome WHERE team_id=$1`, teamID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	return outcome
}

func TestIntegration_CanonicalSignupAliasesShareAuthority(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed_legacy_%t", mixed), func(t *testing.T) {
			ctx := context.Background()
			mailbox := "signup" + strings.ReplaceAll(uuid.NewString(), "-", "")
			emails := []string{mailbox + "+one@gmail.com", strings.ToUpper(mailbox[:6]+"."+mailbox[6:]) + "+two@GOOGLEMAIL.COM"}
			users := []uuid.UUID{canonicalStripeActor(t, emails[0], true), canonicalStripeActor(t, emails[1], true)}
			teams, errs := make([]uuid.UUID, 2), make([]error, 2)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range users {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					if mixed && i == 0 {
						teams[i] = uuid.New()
						statements := []string{
							`INSERT INTO team(id,name) VALUES($1::uuid,'legacy-' || $1::text)`,
							`INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'owner')`,
							`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`,
							`INSERT INTO user_role_assignments(team_id,user_id,scope_type,role_id) SELECT $1,$2,'team',id FROM roles WHERE name='team_owner'`,
						}
						for j, statement := range statements {
							args := []any{teams[i], users[i]}
							if j == 0 {
								args = args[:1]
							}
							if _, errs[i] = testPool.Exec(ctx, statement, args...); errs[i] != nil {
								return
							}
						}
					} else {
						errs[i] = testPool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`, "api-"+uuid.NewString(), users[i]).Scan(&teams[i])
					}
				}(i)
			}
			close(start)
			wg.Wait()
			granted := 0
			for i, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
				switch got := canonicalSignupOutcome(t, teams[i]); got {
				case "granted":
					granted++
				case "already_claimed":
				default:
					t.Fatalf("unexpected outcome %q", got)
				}
				var email string
				if err := testPool.QueryRow(ctx, `SELECT email FROM profile WHERE id=$1`, users[i]).Scan(&email); err != nil || email != emails[i] {
					t.Fatalf("stored email changed: %q, %v", email, err)
				}
			}
			var count int
			if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=ANY($1::uuid[]) AND reason='signup trial credit'`, teams).Scan(&count); err != nil || count != 1 || granted != 1 {
				t.Fatalf("aliases minted duplicate credit: grants=%d outcomes=%d err=%v", count, granted, err)
			}
		})
	}
}

func TestIntegration_CanonicalSignupRollbackJoinAndDeletion(t *testing.T) {
	ctx := context.Background()
	mailbox := "lifecycle" + strings.ReplaceAll(uuid.NewString(), "-", "")
	user := canonicalStripeActor(t, mailbox+"@gmail.com", true)
	joined := rolloutLegacyTeam(t, rolloutProfile(t), true)
	rolloutExec(t, testPool, `INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'member')`, joined, user)
	rolloutAssertClaim(t, testPool, user, uuid.Nil)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var failedTeam uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`, "rollback-"+uuid.NewString(), user).Scan(&failedTeam); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity WHERE identity_key=promotion_identity_key($1,$2,true) AND signup_claimed_at IS NOT NULL)`, user, mailbox+"@gmail.com").Scan(&consumed); err != nil || consumed {
		t.Fatalf("rollback consumed canonical claim: %t %v", consumed, err)
	}
	team := rolloutExplicitTeam(t, user)
	if got := canonicalSignupOutcome(t, team); got != "granted" {
		t.Fatal(got)
	}
	rolloutExec(t, testPool, `DELETE FROM team_credit_grant WHERE team_id=$1`, team)
	rolloutExec(t, testPool, `DELETE FROM team WHERE id=$1`, team)
	rolloutExec(t, testPool, `DELETE FROM team_member WHERE profile_id=$1`, user)
	rolloutExec(t, testPool, `DELETE FROM profile WHERE id=$1`, user)
	alias := canonicalStripeActor(t, mailbox+"+again@googlemail.com", true)
	if got := canonicalSignupOutcome(t, rolloutExplicitTeam(t, alias)); got != "already_claimed" {
		t.Fatalf("deletion reopened identity: %s", got)
	}
}

func TestIntegration_CanonicalSignupEvidenceOutcomes(t *testing.T) {
	ctx := context.Background()
	for _, evidence := range []string{"unverified", "missing", "malformed", "malformed_domain"} {
		t.Run(evidence, func(t *testing.T) {
			user := canonicalStripeActor(t, "untrusted"+uuid.NewString()[:8]+"@gmail.com", false)
			if evidence == "missing" {
				rolloutExec(t, testPool, `UPDATE promotion_auth.identity_source SET email=NULL WHERE id=$1`, user)
			}
			if evidence == "malformed" {
				rolloutExec(t, testPool, `UPDATE promotion_auth.identity_source SET email='not-an-email',email_confirmed_at=now() WHERE id=$1`, user)
			}
			if evidence == "malformed_domain" {
				rolloutExec(t, testPool, `UPDATE promotion_auth.identity_source SET email='alias@gmail.com.',email_confirmed_at=now() WHERE id=$1`, user)
			}
			team := rolloutExplicitTeam(t, user)
			if got := canonicalSignupOutcome(t, team); got != "promotion_ineligible" {
				t.Fatal(got)
			}
			rolloutAssertClaim(t, testPool, user, uuid.Nil)
			var grants int
			if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1`, team).Scan(&grants); err != nil || grants != 0 {
				t.Fatalf("ineligible grant: %d %v", grants, err)
			}
		})
	}
	t.Run("unavailable", func(t *testing.T) {
		user := rolloutProfile(t)
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		rolloutExec(t, tx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, user)
		_, err = tx.Exec(ctx, `SELECT create_team_with_signup_trial($1,$2,'use')`, "unavailable-"+uuid.NewString(), user)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
			t.Fatalf("want unavailable authority, got %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		rolloutAssertClaim(t, testPool, user, uuid.Nil)
	})
	t.Run("non-Gmail uses authenticated user", func(t *testing.T) {
		for range 2 {
			user := canonicalStripeActor(t, "same.address+alias@example.com", true)
			if got := canonicalSignupOutcome(t, rolloutExplicitTeam(t, user)); got != "granted" {
				t.Fatal(got)
			}
		}
	})
}

func TestIntegration_CanonicalHistoryIsExplicitAndGrantPreserving(t *testing.T) {
	ctx := context.Background()
	mailbox := "history" + strings.ReplaceAll(uuid.NewString(), "-", "")
	user := canonicalStripeActor(t, mailbox+"@gmail.com", true)
	historyKey := "test-signup:" + user.String()
	rolloutExec(t, testPool, `INSERT INTO promotion_identity_history(history_key,promotion,user_id,claimed_at) VALUES($1,'signup',$2,now()-interval '1 day')`, historyKey, user)
	t.Cleanup(func() {
		rolloutExec(t, testPool, `DELETE FROM promotion_identity_history WHERE history_key=$1`, historyKey)
	})
	team := rolloutExplicitTeam(t, user)
	if got := canonicalSignupOutcome(t, team); got != "promotion_ineligible" {
		t.Fatalf("unknown historical identity failed open: %s", got)
	}
	rolloutAssertClaim(t, testPool, user, uuid.Nil)
	var key string
	if err := testPool.QueryRow(ctx, `SELECT promotion_identity_key($1,$2,true)`, user, mailbox+"@gmail.com").Scan(&key); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, testPool, `SELECT reconcile_promotion_identity_history($1,ARRAY[$2]::text[],'verified historical fixture')`, historyKey, key)
	alias := canonicalStripeActor(t, mailbox+"+again@googlemail.com", true)
	if got := canonicalSignupOutcome(t, rolloutExplicitTeam(t, alias)); got != "already_claimed" {
		t.Fatalf("historical canonical claim lost: %s", got)
	}
	var grants int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE created_by=ANY($1::uuid[])`, []uuid.UUID{user, alias}).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("reconciliation issued replacement: %d %v", grants, err)
	}
}

func TestIntegration_CanonicalHistoricalMigrationPreservesDuplicates(t *testing.T) {
	ctx := context.Background()
	mailbox := "old" + strings.ReplaceAll(uuid.NewString(), "-", "")
	users := []uuid.UUID{canonicalStripeActor(t, mailbox+"@gmail.com", true), canonicalStripeActor(t, mailbox+"+old@googlemail.com", true)}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	teams := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, team := range teams {
		rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "historical-"+team.String())
		rolloutExec(t, tx, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,2,'signup trial credit')`, team)
		if i < len(users) {
			rolloutExec(t, tx, `INSERT INTO user_signup_trial_claim(user_id,team_id) VALUES($1,$2)`, users[i], team)
		}
	}
	var before string
	if err := tx.QueryRow(ctx, `SELECT jsonb_agg(g ORDER BY id)::text FROM team_credit_grant g WHERE team_id=ANY($1)`, teams).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual snapshot SQL, not a hand-built substitute. Current
	// Auth and regional email are deliberately not used to resolve old aliases.
	migration, err := os.ReadFile("../../supabase/migrations/20260924191820_canonical_promotion_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "-- Current Auth state")
	end := strings.Index(string(migration), "CREATE FUNCTION reconcile_promotion_identity_history")
	if start < 0 || end <= start {
		t.Fatal("historical snapshot segment missing")
	}
	rolloutExec(t, tx, `DELETE FROM promotion_identity_history`)
	rolloutExec(t, tx, string(migration[start:end]))
	var pending int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM promotion_identity_history WHERE team_id=ANY($1) AND status='pending' AND cardinality(identity_keys)=0`, teams).Scan(&pending); err != nil || pending != 3 {
		t.Fatalf("historical evidence was inferred: pending=%d err=%v", pending, err)
	}
	for _, user := range users {
		rolloutExec(t, tx, `SELECT reconcile_promotion_identity_history('signup-user:'||$1::text,
			ARRAY[promotion_identity_key($1::uuid,$2,true)],'verified historical mailbox evidence')`, user, mailbox+"@gmail.com")
	}
	var consumed bool
	if err := tx.QueryRow(ctx, `SELECT signup_claimed_at IS NOT NULL FROM promotion_identity WHERE identity_key=promotion_identity_key($1,$2,true)`, users[0], mailbox+"@gmail.com").Scan(&consumed); err != nil || !consumed {
		t.Fatalf("historical aliases not consumed: %t %v", consumed, err)
	}
	var after string
	if err := tx.QueryRow(ctx, `SELECT jsonb_agg(g ORDER BY id)::text FROM team_credit_grant g WHERE team_id=ANY($1)`, teams).Scan(&after); err != nil || after != before {
		t.Fatalf("reconciliation changed historical grants: %v", err)
	}
}

func TestIntegration_CanonicalPromotionPrivileges(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rolloutExec(t, tx, `DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
		IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN',r); END IF; END LOOP; END $$;
		GRANT ALL ON promotion_identity,promotion_identity_binding,promotion_identity_history,team_signup_promotion_outcome TO anon,authenticated,service_role;
		GRANT ALL ON FUNCTION reconcile_promotion_identity_history(text,text[],text,text),claim_team_signup_trial(uuid,uuid) TO anon,authenticated,service_role`)
	migration, err := os.ReadFile("../../supabase/migrations/20260924191820_canonical_promotion_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "REVOKE ALL ON FUNCTION promotion_identity_key")
	if start < 0 {
		t.Fatal("promotion privilege segment missing")
	}
	rolloutExec(t, tx, string(migration[start:]))
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		var claim, reconcile, writeHistory bool
		if err := tx.QueryRow(ctx, `SELECT has_function_privilege($1,'claim_team_signup_trial(uuid,uuid)','EXECUTE'),
			has_function_privilege($1,'reconcile_promotion_identity_history(text,text[],text,text)','EXECUTE'),
			has_table_privilege($1,'promotion_identity_history','INSERT,UPDATE,DELETE,TRUNCATE')`, role).Scan(&claim, &reconcile, &writeHistory); err != nil {
			t.Fatal(err)
		}
		if claim != (role == "service_role") || reconcile || writeHistory {
			t.Fatalf("unexpected %s privileges: claim=%t reconcile=%t history=%t", role, claim, reconcile, writeHistory)
		}
	}
}
