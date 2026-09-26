//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/promotiontest"
)

func promotionIsolatedDatabase(t *testing.T, regional bool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	name := "promotion_test_" + uuid.NewString()[:8]
	if _, err := testPool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config := testPool.Config().Copy()
	config.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := testPool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated promotion database: %v", err)
		}
	})
	if regional {
		if err := applyMigrations(ctx, pool); err != nil {
			t.Fatalf("regional migrations: %v", err)
		}
		if err := promotiontest.Install(ctx, pool); err != nil {
			t.Fatalf("regional identity fixture: %v", err)
		}
	} else {
		rolloutExec(t, pool, `CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY, created_at timestamptz NOT NULL)`)
		rolloutExec(t, pool, `DO $$ DECLARE r text; BEGIN
			FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
				IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
					EXECUTE format('CREATE ROLE %I NOLOGIN',r);
				END IF;
			END LOOP;
		END $$`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon,authenticated,service_role`)
		migration, err := os.ReadFile("../../supabase/shared-auth-migrations/20260925000000_signup_device_evidence.sql")
		if err != nil {
			t.Fatal(err)
		}
		rolloutExec(t, pool, string(migration))
		for _, role := range []string{"anon", "authenticated", "service_role"} {
			var tableAccess bool
			if err := pool.QueryRow(ctx, `SELECT
				has_table_privilege($1, 'public.signup_device_attempt', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
				OR has_table_privilege($1, 'public.signup_device_account_evidence', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role).
				Scan(&tableAccess); err != nil || tableAccess {
				t.Fatalf("initial shared Auth table privileges for %s: %t, %v", role, tableAccess, err)
			}
		}
		// Mirror Supabase's direct API-role table grants before applying the fix.
		rolloutExec(t, pool, `GRANT ALL ON public.signup_device_attempt, public.signup_device_account_evidence TO anon,authenticated,service_role`)
		migration, err = os.ReadFile("../../supabase/shared-auth-migrations/20260925183413_protect_shared_signup_device_evidence.sql")
		if err != nil {
			t.Fatal(err)
		}
		rolloutExec(t, pool, string(migration))
		migration, err = os.ReadFile("../../supabase/shared-auth-migrations/20260925190000_promotion_evidence_proxy_role.sql")
		if err != nil {
			t.Fatal(err)
		}
		var roleExists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='promotion_evidence_proxy')`).Scan(&roleExists); err != nil {
			t.Fatal(err)
		}
		proxyMigration := string(migration)
		if roleExists {
			// Roles are cluster-wide; each isolated Auth database still needs its own grants.
			proxyMigration = strings.Replace(proxyMigration,
				"CREATE ROLE promotion_evidence_proxy LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;", "", 1)
		}
		rolloutExec(t, pool, proxyMigration)
	}
	return pool
}

type originalSignupEvidence struct {
	attempt            uuid.UUID
	event, fingerprint string
}

func promotionAuthRole(t *testing.T, auth *pgxpool.Pool, role string, fn func(pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := auth.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	fn(tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func promotionVerifiedSignup(t *testing.T, auth *pgxpool.Pool, user uuid.UUID, fingerprint string) originalSignupEvidence {
	t.Helper()
	ctx := context.Background()
	var attempt, challenge uuid.UUID
	event := "event-" + uuid.NewString()
	var outcome string
	promotionAuthRole(t, auth, "promotion_evidence_proxy", func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&attempt, &challenge); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`, attempt, challenge, event, fingerprint).Scan(&outcome); err != nil || outcome != "verified" {
			t.Fatalf("verify signup: %q, %v", outcome, err)
		}
	})
	var eventAt time.Time
	if err := auth.QueryRow(ctx, `SELECT event_at FROM public.signup_device_attempt WHERE attempt_id=$1`, attempt).Scan(&eventAt); err != nil {
		t.Fatal(err)
	}
	var unbound int
	if err := auth.QueryRow(ctx, `SELECT count(*) FROM public.get_signup_device_account_evidence($1)`, user).Scan(&unbound); err != nil || unbound != 0 {
		t.Fatalf("verified attempt published before account binding: %d, %v", unbound, err)
	}
	promotionAuthRole(t, auth, "promotion_evidence_proxy", func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,$5)`, attempt, challenge, event, fingerprint, eventAt).Scan(&outcome); err != nil || outcome != "replayed" {
			t.Fatalf("verify replay: %q, %v", outcome, err)
		}
	})
	rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp())`, user)
	promotionAuthRole(t, auth, "promotion_evidence_proxy", func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user).Scan(&outcome); err != nil || outcome != "bound" {
			t.Fatalf("bind signup: %q, %v", outcome, err)
		}
		if err := tx.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user).Scan(&outcome); err != nil || outcome != "replayed" {
			t.Fatalf("bind replay: %q, %v", outcome, err)
		}
	})
	return originalSignupEvidence{attempt, event, fingerprint}
}

func promotionPublishOriginal(t *testing.T, auth, region *pgxpool.Pool, user uuid.UUID, want originalSignupEvidence) string {
	t.Helper()
	ctx := context.Background()
	var attempt uuid.UUID
	var event, fingerprint string
	var eventAt, boundAt time.Time
	promotionAuthRole(t, auth, "promotion_evidence_proxy", func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT * FROM public.get_signup_device_account_evidence($1)`, user).
			Scan(&attempt, &event, &fingerprint, &eventAt, &boundAt); err != nil {
			t.Fatal(err)
		}
	})
	if attempt != want.attempt || event != want.event || fingerprint != want.fingerprint || boundAt.IsZero() {
		t.Fatal("retrieval changed original signup evidence")
	}
	var outcome string
	if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`, user, attempt, event, fingerprint).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	return outcome
}

func promotionClaimSignup(t *testing.T, region *pgxpool.Pool, user uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2) ON CONFLICT (id) DO NOTHING`, user, user.String()+"@example.com")
	team := uuid.New()
	rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
	var outcome, reason string
	if err := region.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user).Scan(&outcome, &reason); err != nil {
		t.Fatal(err)
	}
	return team, outcome
}

func TestIntegration_PromotionSignupGrantWithLateDeviceEvidence(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, recipient := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		owner, uuid.New(), "event-"+uuid.NewString(), fingerprint)

	team, outcome := promotionClaimSignup(t, region, recipient)
	if outcome != "granted" {
		t.Fatalf("signup grant without evidence: %s", outcome)
	}
	var grantWithoutEvidence bool
	if err := region.QueryRow(ctx, `SELECT fingerprint IS NULL FROM promotion_device_grant
		WHERE promotion='signup' AND user_id=$1 AND team_id=$2`, recipient, team).Scan(&grantWithoutEvidence); err != nil || !grantWithoutEvidence {
		t.Fatalf("signup grant did not retain missing evidence: %t, %v", grantWithoutEvidence, err)
	}
	var registration string
	if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		recipient, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&registration); err != nil || registration != "owner_conflict" {
		t.Fatalf("late evidence registration: %q, %v", registration, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	var decision string
	if err := region.QueryRow(ctx, `SELECT promotion_device_decision($1,'signup')`, owner).Scan(&decision); err != nil || decision != "device_already_redeemed" {
		t.Fatalf("owner decision after late evidence: %q, %v", decision, err)
	}
	if _, outcome := promotionClaimSignup(t, region, owner); outcome != "promotion_ineligible" {
		t.Fatalf("owner signup claim after late evidence: %s", outcome)
	}
}

func TestIntegration_SignupClaimWaitsForRegionalEvidenceRegistration(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, other := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	}
	rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		owner, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,false)`)

	team := uuid.New()
	rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
	registration, err := region.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer registration.Rollback(ctx)
	var registrationPID int
	if err := registration.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&registrationPID); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, registration, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-user:' || $1::text)::bigint)`, other)

	claimConn, err := region.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer claimConn.Release()
	claimCtx, cancelClaim := context.WithCancel(ctx)
	defer cancelClaim()
	var claimPID int
	if err := claimConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&claimPID); err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		outcome, reason string
		err             error
	}
	claimDone := make(chan claimResult, 1)
	go func() {
		var result claimResult
		result.err = claimConn.QueryRow(claimCtx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, other).
			Scan(&result.outcome, &result.reason)
		claimDone <- result
	}()
	deadline := time.Now().Add(4 * time.Second)
	for {
		var blocked bool
		if err := region.QueryRow(ctx, `SELECT $1 = ANY(pg_blocking_pids($2))`, registrationPID, claimPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case result := <-claimDone:
			t.Fatalf("claim passed registration lock: %q %q %v", result.outcome, result.reason, result.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("claim did not reach registration lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, outcome := promotionClaimSignup(t, region, owner); outcome != "granted" {
		t.Fatalf("regional owner signup claim: %s", outcome)
	}
	var registered string
	if err := registration.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
		other, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&registered); err != nil || registered != "owner_conflict" {
		t.Fatalf("concurrent regional registration: %q, %v", registered, err)
	}
	if err := registration.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-claimDone
	if result.err != nil || result.outcome != "promotion_ineligible" || result.reason != "owner_conflict" {
		t.Fatalf("claim after registration: %q %q %v", result.outcome, result.reason, result.err)
	}
	var grants int
	if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND fingerprint=$1`, fingerprint).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("same regional Fingerprint grants: %d, %v", grants, err)
	}
}

func TestIntegration_DeniedSignupDeviceClaimFencesLegacyCompletion(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, denied := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, denied} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		rolloutExec(t, region, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	team := uuid.New()
	rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "denied-"+team.String())
	var outcome, reason string
	if err := region.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, denied).Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "owner_conflict" {
		t.Fatalf("device denial: %q %q, %v", outcome, reason, err)
	}
	rolloutExec(t, region, `INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'owner')`, team, denied)
	rolloutExec(t, region, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, denied)
	rolloutExec(t, region, `INSERT INTO user_role_assignments(team_id,user_id,scope_type,role_id)
		SELECT $1,$2,'team',id FROM roles WHERE name='team_owner'`, team, denied)
	if err := region.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, denied).Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "owner_conflict" {
		t.Fatalf("denial replay after legacy provisioning: %q %q, %v", outcome, reason, err)
	}
	var completed, deniedMarker, consumed, entitled bool
	var grants, deviceGrants int
	if err := region.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM team_signup_trial_provenance WHERE team_id=$1 AND creator_user_id=$2 AND completed_at IS NOT NULL),
		EXISTS(SELECT 1 FROM team_signup_trial_denial WHERE team_id=$1),
		EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id=$2),
		EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND signup_trial_claimed_at IS NOT NULL),
		(SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'),
		(SELECT count(*) FROM promotion_device_grant WHERE team_id=$1 AND promotion='signup')`, team, denied).
		Scan(&completed, &deniedMarker, &consumed, &entitled, &grants, &deviceGrants); err != nil || !completed || !deniedMarker || consumed || entitled || grants != 0 || deviceGrants != 0 {
		t.Fatalf("denial facts: completed=%t marker=%t consumed=%t entitled=%t grants=%d device_grants=%d err=%v", completed, deniedMarker, consumed, entitled, grants, deviceGrants, err)
	}
}

func TestIntegration_PromotionSharedAuthIndependentRegions(t *testing.T) {
	ctx := context.Background()
	auth := promotionIsolatedDatabase(t, false)
	east := promotionIsolatedDatabase(t, true)
	west := promotionIsolatedDatabase(t, true)
	a, b := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	aEvidence := promotionVerifiedSignup(t, auth, a, fingerprint)
	bEvidence := promotionVerifiedSignup(t, auth, b, fingerprint)
	if _, err := auth.Exec(ctx, `SELECT public.bind_signup_device_account($1,$2)`, aEvidence.attempt, b); err == nil {
		t.Fatal("accepted signup event rebound to another Auth account")
	}
	for _, role := range []string{"anon", "authenticated", "service_role", "promotion_evidence_proxy"} {
		var tableAccess bool
		if err := auth.QueryRow(ctx, `SELECT
			has_table_privilege($1, 'public.signup_device_attempt', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
			OR has_table_privilege($1, 'public.signup_device_account_evidence', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, role).
			Scan(&tableAccess); err != nil || tableAccess {
			t.Fatalf("shared Auth table privileges for %s: %t, %v", role, tableAccess, err)
		}
		for _, signature := range []string{
			"public.create_signup_device_attempt()",
			"public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz)",
			"public.bind_signup_device_account(uuid,uuid)",
			"public.get_signup_device_account_evidence(uuid)",
		} {
			var rpcAccess bool
			if err := auth.QueryRow(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, role, signature).
				Scan(&rpcAccess); err != nil || rpcAccess != (role == "service_role" || role == "promotion_evidence_proxy") {
				t.Fatalf("shared Auth RPC privilege for %s on %s: %t, %v", role, signature, rpcAccess, err)
			}
		}
	}
	for _, role := range []string{"anon", "authenticated"} {
		for _, check := range []struct {
			query string
			args  []any
		}{
			{`SELECT * FROM public.create_signup_device_attempt()`, nil},
			{`SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`, []any{uuid.New(), uuid.New(), "event", "visitor"}},
			{`SELECT public.bind_signup_device_account($1,$2)`, []any{uuid.New(), a}},
			{`SELECT * FROM public.get_signup_device_account_evidence($1)`, []any{a}},
			{`SELECT attempt_id FROM public.signup_device_attempt LIMIT 1`, nil},
		} {
			tx, err := auth.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, check.query, check.args...)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("%s shared Auth access with %s: expected permission denied, got %v", role, check.query, err)
			}
		}
	}
	for _, role := range []string{"service_role", "promotion_evidence_proxy"} {
		for _, table := range []string{"signup_device_attempt", "signup_device_account_evidence"} {
			tx, err := auth.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, "SELECT * FROM public."+pgx.Identifier{table}.Sanitize()+" LIMIT 1")
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("%s read shared Auth %s table: expected permission denied, got %v", role, table, err)
			}
		}
	}
	var duplicateAttempt, duplicateChallenge uuid.UUID
	if err := auth.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&duplicateAttempt, &duplicateChallenge); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Exec(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`,
		duplicateAttempt, uuid.New(), aEvidence.event, fingerprint); err == nil {
		t.Fatal("signup attempt accepted the wrong challenge")
	}
	if _, err := auth.Exec(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`,
		duplicateAttempt, duplicateChallenge, aEvidence.event, fingerprint); err == nil {
		t.Fatal("provider event was accepted for a second signup attempt")
	}
	var laterAttempt, laterChallenge uuid.UUID
	promotionAuthRole(t, auth, "promotion_evidence_proxy", func(tx pgx.Tx) {
		if err := tx.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&laterAttempt, &laterChallenge); err != nil {
			t.Fatal(err)
		}
		var outcome string
		if err := tx.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`,
			laterAttempt, laterChallenge, "event-"+uuid.NewString(), "other-"+uuid.NewString()).Scan(&outcome); err != nil || outcome != "verified" {
			t.Fatalf("later verification: %q, %v", outcome, err)
		}
		if err := tx.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, laterAttempt, a).Scan(&outcome); err != nil || outcome != "first_evidence_retained" {
			t.Fatalf("later binding: %q, %v", outcome, err)
		}
	})
	if _, err := auth.Exec(ctx, `UPDATE public.signup_device_attempt SET fingerprint='replaced' WHERE attempt_id=$1`, aEvidence.attempt); err == nil {
		t.Fatal("accepted signup Fingerprint was replaced directly")
	}
	if _, err := auth.Exec(ctx, `DELETE FROM public.signup_device_attempt WHERE attempt_id=$1`, aEvidence.attempt); err == nil {
		t.Fatal("accepted signup attempt was deleted directly")
	}
	if _, err := auth.Exec(ctx, `UPDATE public.signup_device_account_evidence SET attempt_id=$1 WHERE user_id=$2`, bEvidence.attempt, a); err == nil {
		t.Fatal("first account evidence was replaced directly")
	}
	if _, err := auth.Exec(ctx, `TRUNCATE public.signup_device_account_evidence CASCADE`); err == nil {
		t.Fatal("accepted account evidence was truncated")
	}
	var staleAttempt, staleChallenge uuid.UUID
	if err := auth.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&staleAttempt, &staleChallenge); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, auth, `UPDATE public.signup_device_attempt SET created_at=now()-interval '31 minutes' WHERE attempt_id=$1`, staleAttempt)
	if _, err := auth.Exec(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`,
		staleAttempt, staleChallenge, "event-"+uuid.NewString(), fingerprint); err == nil {
		t.Fatal("stale unverified signup attempt accepted")
	}
	if _, err := auth.Exec(ctx, `UPDATE public.signup_device_attempt SET created_at=now()-interval '31 minutes' WHERE attempt_id=$1`, aEvidence.attempt); err == nil {
		t.Fatal("accepted signup creation time was changed")
	}
	for _, region := range []*pgxpool.Pool{east, west} {
		rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
		var remoteLinks int
		if err := region.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_foreign_server) +
			(SELECT count(*) FROM pg_extension WHERE extname IN ('dblink','postgres_fdw'))`).Scan(&remoteLinks); err != nil || remoteLinks != 0 {
			t.Fatalf("regional database has remote database access: %d, %v", remoteLinks, err)
		}
	}
	for _, tc := range []struct {
		name       string
		region     *pgxpool.Pool
		first      uuid.UUID
		proof      originalSignupEvidence
		other      uuid.UUID
		otherProof originalSignupEvidence
	}{
		{"east", east, a, aEvidence, b, bEvidence},
		{"west", west, b, bEvidence, a, aEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "west" {
				var eastOwner uuid.UUID
				var eastSignupGrants, eastStripeGrants, westOwners, westGrants int
				if err := east.QueryRow(ctx, `SELECT user_id,
					(SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND fingerprint=$1),
					(SELECT count(*) FROM promotion_device_grant WHERE promotion='stripe' AND fingerprint=$1)
					FROM promotion_device_owner WHERE fingerprint=$1`, fingerprint).
					Scan(&eastOwner, &eastSignupGrants, &eastStripeGrants); err != nil ||
					eastOwner != a || eastSignupGrants != 1 || eastStripeGrants != 1 {
					t.Fatalf("East before West entry: owner=%s signup=%d stripe=%d err=%v",
						eastOwner, eastSignupGrants, eastStripeGrants, err)
				}
				if err := west.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM promotion_device_owner WHERE fingerprint=$1),
					(SELECT count(*) FROM promotion_device_grant WHERE fingerprint=$1)`, fingerprint).
					Scan(&westOwners, &westGrants); err != nil || westOwners != 0 || westGrants != 0 {
					t.Fatalf("West before original evidence publication: owners=%d grants=%d err=%v",
						westOwners, westGrants, err)
				}
			}
			if got := promotionPublishOriginal(t, auth, tc.region, tc.first, tc.proof); got != "owner" {
				t.Fatalf("first owner: %s", got)
			}
			if got := promotionPublishOriginal(t, auth, tc.region, tc.other, tc.otherProof); got != "owner_conflict" {
				t.Fatalf("later owner: %s", got)
			}
			if got := promotionPublishOriginal(t, auth, tc.region, tc.first, tc.proof); got != "owner" {
				t.Fatalf("publication replay: %s", got)
			}
			rollback, err := tc.region.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			trialTeam := uuid.New()
			rolloutExec(t, rollback, `INSERT INTO profile(id,email) VALUES($1,$2)`, tc.first, tc.first.String()+"@example.com")
			rolloutExec(t, rollback, `INSERT INTO team(id,name) VALUES($1,$2)`, trialTeam, "rollback-"+trialTeam.String())
			var trialOutcome string
			if err := rollback.QueryRow(ctx, `SELECT outcome FROM claim_team_signup_trial_with_device($1,$2)`, trialTeam, tc.first).Scan(&trialOutcome); err != nil || trialOutcome != "granted" {
				t.Fatalf("uncommitted signup grant: %q, %v", trialOutcome, err)
			}
			if err := rollback.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var retainedOwner uuid.UUID
			var leakedGrants, leakedClaims, leakedEntitlements int
			if err := tc.region.QueryRow(ctx, `SELECT user_id,
				(SELECT count(*) FROM promotion_device_grant WHERE team_id=$2),
				(SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$3),
				(SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$3 AND signup_trial_claimed_at IS NOT NULL)
				FROM promotion_device_owner WHERE fingerprint=$1`, fingerprint, trialTeam, tc.first).
				Scan(&retainedOwner, &leakedGrants, &leakedClaims, &leakedEntitlements); err != nil ||
				retainedOwner != tc.first || leakedGrants != 0 || leakedClaims != 0 || leakedEntitlements != 0 {
				t.Fatalf("grant rollback: owner=%s grants=%d claims=%d entitlements=%d err=%v",
					retainedOwner, leakedGrants, leakedClaims, leakedEntitlements, err)
			}
			team, outcome := promotionClaimSignup(t, tc.region, tc.first)
			if outcome != "granted" {
				t.Fatalf("owner signup claim: %s", outcome)
			}
			var replay string
			if err := tc.region.QueryRow(ctx, `SELECT outcome FROM claim_team_signup_trial_with_device($1,$2)`, team, tc.first).Scan(&replay); err != nil || replay != "granted" {
				t.Fatalf("signup replay: %q, %v", replay, err)
			}
			_, outcome = promotionClaimSignup(t, tc.region, tc.first)
			if outcome == "granted" {
				t.Fatal("second local signup grant")
			}
			otherTeam, outcome := promotionClaimSignup(t, tc.region, tc.other)
			if outcome == "granted" {
				t.Fatal("later account received local signup grant")
			}
			var count int
			if err := tc.region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND fingerprint=$1`, fingerprint).Scan(&count); err != nil || count != 1 {
				t.Fatalf("local signup grant count = %d, %v", count, err)
			}
			rolloutExec(t, tc.region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			rolloutExec(t, tc.region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, otherTeam)
			var deniedReservation string
			if err := tc.region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
				otherTeam, tc.other, "evt-"+uuid.NewString()).Scan(&deniedReservation); err != nil || deniedReservation != "owner_conflict" {
				t.Fatalf("later account Stripe reservation: %q, %v", deniedReservation, err)
			}
			var deniedFence, deniedEntitlement bool
			if err := tc.region.QueryRow(ctx, `SELECT
				EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND stripe_activation_credit_reserved_at IS NOT NULL),
				EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND stripe_redemption_reserved_team_id IS NOT NULL)`,
				otherTeam, tc.other).Scan(&deniedFence, &deniedEntitlement); err != nil || deniedFence || deniedEntitlement {
				t.Fatalf("denied Stripe reservation wrote a fence: team=%t user=%t err=%v", deniedFence, deniedEntitlement, err)
			}
			event := "evt-" + uuid.NewString()
			var reserved string
			if err := tc.region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`, team, tc.first, event).Scan(&reserved); err != nil || reserved != "acquired" {
				t.Fatalf("Stripe reservation: %q, %v", reserved, err)
			}
			if err := tc.region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`, team, tc.first, event).Scan(&reserved); err != nil || reserved != "existing" {
				t.Fatalf("Stripe reservation replay: %q, %v", reserved, err)
			}
			var pending, settled bool
			if err := tc.region.QueryRow(ctx, `SELECT stripe_redemption_reserved_team_id=$2, stripe_redemption_at IS NOT NULL
				FROM user_promotion_entitlement WHERE user_id=$1`, tc.first, team).Scan(&pending, &settled); err != nil || !pending || settled {
				t.Fatalf("reservation fence: pending=%t settled=%t err=%v", pending, settled, err)
			}
			rolloutExec(t, tc.region, `SELECT finalize_stripe_promotion($1,$2,$3)`, team, tc.first, "grant-"+uuid.NewString())
			rolloutExec(t, tc.region, `SELECT record_stripe_promotion_device_grant($1,$2)`, team, tc.first)
			rolloutExec(t, tc.region, `SELECT record_stripe_promotion_device_grant($1,$2)`, team, tc.first)
			if err := tc.region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant
				WHERE promotion='stripe' AND user_id=$1 AND team_id=$2 AND fingerprint=$3`, tc.first, team, fingerprint).Scan(&count); err != nil || count != 1 {
				t.Fatalf("settled Stripe device grant count = %d, %v", count, err)
			}
		})
	}
	for _, region := range []*pgxpool.Pool{east, west} {
		var grants int
		if err := region.QueryRow(ctx, `SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND fingerprint=$1`, fingerprint).Scan(&grants); err != nil || grants != 1 {
			t.Fatalf("regional grant count = %d, %v", grants, err)
		}
	}
	rolloutExec(t, auth, `DELETE FROM auth.users WHERE id=$1`, a)
	if got := promotionPublishOriginal(t, auth, west, a, aEvidence); got != "owner_conflict" {
		t.Fatalf("original evidence after Auth account deletion: %s", got)
	}
}

func TestIntegration_SharedSignupEvidenceRejectsUnverifiedAndReboundAttempts(t *testing.T) {
	ctx := context.Background()
	auth := promotionIsolatedDatabase(t, false)
	var attempt, challenge uuid.UUID
	if err := auth.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&attempt, &challenge); err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp())`, user)
	if _, err := auth.Exec(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user); err == nil {
		t.Fatal("unverified attempt bound to an Auth account")
	}
	var count int
	if err := auth.QueryRow(ctx, `SELECT count(*) FROM public.get_signup_device_account_evidence($1)`, user).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unverified attempt became retrievable: %d, %v", count, err)
	}
	event := "event-" + uuid.NewString()
	fingerprint := "visitor-" + uuid.NewString()
	if _, err := auth.Exec(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp()-interval '6 minutes')`,
		attempt, challenge, event, fingerprint); err == nil {
		t.Fatal("stale provider event verified for a fresh attempt")
	}
	var eventAt time.Time
	if err := auth.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&eventAt); err != nil {
		t.Fatal(err)
	}
	var outcome string
	if err := auth.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,$5)`,
		attempt, challenge, event, fingerprint, eventAt).Scan(&outcome); err != nil || outcome != "verified" {
		t.Fatalf("initial verification: %q, %v", outcome, err)
	}
	if _, err := auth.Exec(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,$5)`,
		attempt, challenge, event, "changed-"+fingerprint, eventAt); err == nil {
		t.Fatal("changed Fingerprint accepted as verification replay")
	}
	oldUser := uuid.New()
	rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp()-interval '1 hour')`, oldUser)
	if _, err := auth.Exec(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, oldUser); err == nil {
		t.Fatal("old Auth account accepted fresh signup evidence")
	}
	if err := auth.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user).Scan(&outcome); err != nil || outcome != "bound" {
		t.Fatalf("valid binding after rejected provenance: %q, %v", outcome, err)
	}
	var retrievedAttempt uuid.UUID
	var retrievedEvent, retrievedFingerprint string
	var retrievedEventAt, boundAt time.Time
	if err := auth.QueryRow(ctx, `SELECT * FROM public.get_signup_device_account_evidence($1)`, user).
		Scan(&retrievedAttempt, &retrievedEvent, &retrievedFingerprint, &retrievedEventAt, &boundAt); err != nil ||
		retrievedAttempt != attempt || retrievedEvent != event || retrievedFingerprint != fingerprint ||
		!retrievedEventAt.Equal(eventAt) || boundAt.IsZero() {
		t.Fatalf("original accepted evidence was not retained: attempt=%s event=%q fingerprint=%q err=%v",
			retrievedAttempt, retrievedEvent, retrievedFingerprint, err)
	}
	if err := auth.QueryRow(ctx, `SELECT count(*) FROM public.get_signup_device_account_evidence($1)`, oldUser).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old Auth account gained evidence: %d, %v", count, err)
	}
}

func TestIntegration_SharedSignupFirstBindingWinsRace(t *testing.T) {
	ctx := context.Background()
	auth := promotionIsolatedDatabase(t, false)
	user := uuid.New()
	rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp())`, user)
	type candidate struct {
		attempt     uuid.UUID
		fingerprint string
	}
	var attempts [2]candidate
	for i := range attempts {
		var challenge uuid.UUID
		if err := auth.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&attempts[i].attempt, &challenge); err != nil {
			t.Fatal(err)
		}
		attempts[i].fingerprint = "visitor-" + uuid.NewString()
		var outcome string
		if err := auth.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,clock_timestamp())`,
			attempts[i].attempt, challenge, "event-"+uuid.NewString(), attempts[i].fingerprint).Scan(&outcome); err != nil || outcome != "verified" {
			t.Fatalf("verify candidate %d: %q, %v", i, outcome, err)
		}
	}
	type result struct {
		outcome string
		err     error
	}
	results := make(chan result, len(attempts))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, attempt := range attempts {
		wg.Add(1)
		go func(attempt uuid.UUID) {
			defer wg.Done()
			<-start
			var outcome string
			err := auth.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user).Scan(&outcome)
			results <- result{outcome, err}
		}(attempt.attempt)
	}
	close(start)
	wg.Wait()
	close(results)
	counts := map[string]int{}
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		counts[result.outcome]++
	}
	if counts["bound"] != 1 || counts["first_evidence_retained"] != 1 {
		t.Fatalf("concurrent account bindings = %v", counts)
	}
	var retainedAttempt uuid.UUID
	var retainedFingerprint string
	if err := auth.QueryRow(ctx, `SELECT attempt_id, fingerprint FROM public.get_signup_device_account_evidence($1)`, user).
		Scan(&retainedAttempt, &retainedFingerprint); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range attempts {
		if attempt.attempt == retainedAttempt && attempt.fingerprint != retainedFingerprint {
			t.Fatalf("retrieved Fingerprint changed for winning attempt %s", retainedAttempt)
		}
	}
	if retainedAttempt != attempts[0].attempt && retainedAttempt != attempts[1].attempt {
		t.Fatalf("retrieved attempt %s was not verified by either contender", retainedAttempt)
	}
}

func TestIntegration_SharedSignupEvidenceSurvivesFreshnessAndAccountDeletion(t *testing.T) {
	ctx := context.Background()
	auth := promotionIsolatedDatabase(t, false)
	user := uuid.New()
	var attempt, challenge uuid.UUID
	event, fingerprint := "event-"+uuid.NewString(), "visitor-"+uuid.NewString()
	if err := auth.QueryRow(ctx, `SELECT * FROM public.create_signup_device_attempt()`).Scan(&attempt, &challenge); err != nil {
		t.Fatal(err)
	}
	rolloutExec(t, auth, `UPDATE public.signup_device_attempt SET created_at=clock_timestamp()-interval '4 minutes 58 seconds' WHERE attempt_id=$1`, attempt)
	rolloutExec(t, auth, `INSERT INTO auth.users(id,created_at) VALUES($1,clock_timestamp())`, user)
	var outcome string
	if err := auth.QueryRow(ctx, `SELECT public.verify_signup_device_attempt($1,$2,$3,$4,
		(SELECT created_at FROM public.signup_device_attempt WHERE attempt_id=$1))`,
		attempt, challenge, event, fingerprint).Scan(&outcome); err != nil || outcome != "verified" {
		t.Fatalf("verify near freshness limit: %q, %v", outcome, err)
	}
	if err := auth.QueryRow(ctx, `SELECT public.bind_signup_device_account($1,$2)`, attempt, user).Scan(&outcome); err != nil || outcome != "bound" {
		t.Fatalf("bind original evidence: %q, %v", outcome, err)
	}
	// The accepted event is no longer fresh for a new verification after this wait.
	if _, err := auth.Exec(ctx, `SELECT pg_sleep(3)`); err != nil {
		t.Fatal(err)
	}
	var eventExpired bool
	if err := auth.QueryRow(ctx, `SELECT event_at < clock_timestamp()-interval '5 minutes'
		FROM public.signup_device_attempt WHERE attempt_id=$1`, attempt).Scan(&eventExpired); err != nil || !eventExpired {
		t.Fatalf("event did not pass freshness limit: expired=%t, %v", eventExpired, err)
	}
	if got := promotionPublishOriginal(t, auth, testPool, user,
		originalSignupEvidence{attempt, event, fingerprint}); got != "owner" {
		t.Fatalf("regional publication after freshness limit: %s", got)
	}
	rolloutExec(t, auth, `DELETE FROM auth.users WHERE id=$1`, user)
	var gotAttempt uuid.UUID
	var gotEvent, gotFingerprint string
	if err := auth.QueryRow(ctx, `SELECT attempt_id,event_id,fingerprint FROM public.get_signup_device_account_evidence($1)`, user).
		Scan(&gotAttempt, &gotEvent, &gotFingerprint); err != nil || gotAttempt != attempt || gotEvent != event || gotFingerprint != fingerprint {
		t.Fatalf("durable evidence after freshness limit and Auth deletion: %s %q %q, %v", gotAttempt, gotEvent, gotFingerprint, err)
	}
}

func TestIntegration_LateDeviceEvidencePinsPendingStripeReservation(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, other, ownerTeam, otherTeam := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
	}
	for _, team := range []uuid.UUID{ownerTeam, otherTeam} {
		rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
		rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
	}
	var result string
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
		otherTeam, other, "evt-"+uuid.NewString()).Scan(&result); err != nil || result != "acquired" {
		t.Fatalf("reservation before evidence: %s, %v", result, err)
	}
	var pinned *string
	if err := region.QueryRow(ctx, `SELECT stripe_device_fingerprint FROM user_promotion_entitlement WHERE user_id=$1`, other).
		Scan(&pinned); err != nil || pinned != nil {
		t.Fatalf("reservation unexpectedly pinned before evidence: %v, %v", pinned, err)
	}
	for _, user := range []uuid.UUID{owner, other} {
		if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&result); err != nil {
			t.Fatal(err)
		}
		if user == owner && result != "owner" || user == other && result != "owner_conflict" {
			t.Fatalf("registration for %s: %s", user, result)
		}
	}
	if err := region.QueryRow(ctx, `SELECT stripe_device_fingerprint FROM user_promotion_entitlement WHERE user_id=$1`, other).
		Scan(&pinned); err != nil || pinned == nil || *pinned != fingerprint {
		t.Fatalf("late evidence did not pin pending reservation: %v, %v", pinned, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
		ownerTeam, owner, "evt-"+uuid.NewString()).Scan(&result); err != nil || result != "device_reservation_pending" {
		t.Fatalf("owner escaped pending reservation: %s, %v", result, err)
	}
}

func TestIntegration_PendingStripeDeviceReservationSurvivesPolicyChange(t *testing.T) {
	ctx := context.Background()
	region := promotionIsolatedDatabase(t, true)
	owner, other := uuid.New(), uuid.New()
	fingerprint := "visitor-" + uuid.NewString()
	for _, user := range []uuid.UUID{owner, other} {
		rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
		var registration string
		if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
			user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&registration); err != nil {
			t.Fatal(err)
		}
		if user == owner && registration != "owner" || user == other && registration != "owner_conflict" {
			t.Fatalf("registration for %s: %s", user, registration)
		}
	}
	makeTeam := func() uuid.UUID {
		t.Helper()
		team := uuid.New()
		rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
		rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
		return team
	}
	ownerTeam, otherTeam := makeTeam(), makeTeam()
	reserve := func(team, user uuid.UUID, event string) string {
		t.Helper()
		var result string
		if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
			team, user, event).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	event := "evt-" + uuid.NewString()
	if got := reserve(otherTeam, other, event); got != "acquired" {
		t.Fatalf("reservation while device policy is off: %s", got)
	}
	var reservedFingerprint string
	if err := region.QueryRow(ctx, `SELECT stripe_device_fingerprint FROM user_promotion_entitlement WHERE user_id=$1`, other).
		Scan(&reservedFingerprint); err != nil || reservedFingerprint != fingerprint {
		t.Fatalf("reservation did not pin signup device: %q, %v", reservedFingerprint, err)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	if got := reserve(ownerTeam, owner, "evt-"+uuid.NewString()); got != "device_reservation_pending" {
		t.Fatalf("owner reservation during other account's pending grant: %s", got)
	}
	if got := reserve(otherTeam, other, event); got != "existing" {
		t.Fatalf("pending reservation replay after policy change: %s", got)
	}
	if got := reserve(otherTeam, other, "evt-"+uuid.NewString()); got != "owner_conflict" {
		t.Fatalf("different event bypassed device policy: %s", got)
	}
	release, err := region.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release.Rollback(context.Background())
	rolloutExec(t, release, `SELECT release_stripe_promotion($1,$2)`, otherTeam, other)
	conn, err := region.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := conn.Conn().PgConn().PID()
	type reservationResult struct {
		state string
		err   error
	}
	done := make(chan reservationResult, 1)
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	go func() {
		defer conn.Release()
		var result reservationResult
		result.err = conn.QueryRow(waitCtx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
			otherTeam, other, event).Scan(&result.state)
		done <- result
	}()
	for {
		var waiting bool
		if err := region.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_locks
			WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("reservation did not wait for release: %s, %v", result.state, result.err)
		case <-waitCtx.Done():
			t.Fatal(waitCtx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := release.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if result := <-done; result.err != nil || result.state != "owner_conflict" {
		t.Fatalf("released reservation bypassed device policy: %s, %v", result.state, result.err)
	}
	if got := reserve(ownerTeam, owner, "evt-"+uuid.NewString()); got != "acquired" {
		t.Fatalf("owner reservation after release: %s", got)
	}
	rolloutExec(t, region, `SELECT release_stripe_promotion($1,$2)`, ownerTeam, owner)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(false,false)`)
	if got := reserve(otherTeam, other, "evt-"+uuid.NewString()); got != "acquired" {
		t.Fatalf("second reservation while device policy is off: %s", got)
	}
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	var definition string
	if err := region.QueryRow(ctx, `SELECT pg_get_functiondef('promotion_device_decision(uuid,text)'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(definition, "SELECT CASE")
	end := strings.Index(definition, "END INTO v_stripe_decision")
	if start < 0 || end < start ||
		!strings.Contains(definition[start:end], "stripe_redemption_at IS NOT NULL") ||
		!strings.Contains(definition[start:end], "stripe_redemption_reserved_team_id IS NOT NULL") {
		t.Fatal("settled and pending device facts must be read in one SQL statement")
	}
	finalize, err := region.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer finalize.Rollback(context.Background())
	rolloutExec(t, finalize, `SELECT finalize_stripe_promotion($1,$2,$3)`, otherTeam, other, "grant-"+uuid.NewString())
	if got := reserve(ownerTeam, owner, "evt-"+uuid.NewString()); got != "device_reservation_pending" {
		t.Fatalf("owner reservation while finalization is uncommitted: %s", got)
	}
	if err := finalize.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := reserve(ownerTeam, owner, "evt-"+uuid.NewString()); got != "device_already_redeemed" {
		t.Fatalf("owner reservation after other account settled, before device grant recording: %s", got)
	}
	rolloutExec(t, region, `SELECT record_stripe_promotion_device_grant($1,$2)`, otherTeam, other)
}
