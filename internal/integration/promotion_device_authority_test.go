//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegration_DeviceReservationRetainsAmbiguousStripePins(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "recoverable"
		if expired {
			name = "expired replay window"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			team, _, user := seedTeamAndKeyWithRole(t, "team_owner")
			fingerprint := "visitor-" + uuid.NewString()
			rolloutExec(t, testPool, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
				user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
			rolloutExec(t, testPool, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
				VALUES($1,$2,$3,'incomplete')`, team, "cus_"+team.String(), "sub_"+team.String())
			event := "evt-" + uuid.NewString()
			reserve := func(team, user uuid.UUID, event, want string) {
				t.Helper()
				var result string
				if err := testPool.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
					team, user, event).Scan(&result); err != nil || result != want {
					t.Fatalf("device reservation = %q, want %q: %v", result, want, err)
				}
			}
			reserve(team, user, event, "acquired")
			var identity string
			var evidence uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT stripe_activation_identity_key,stripe_activation_identity_evidence_version
				FROM team_billing_account WHERE team_id=$1`, team).Scan(&identity, &evidence); err != nil {
				t.Fatal(err)
			}
			stripe := &ambiguousPromotionClient{fakeStripeClient: &fakeStripeClient{}, t: t, userID: user, teamID: team, accepted: make(map[string]string)}
			router := newBillingRouter(t, stripe)
			now := time.Now().UTC().Truncate(time.Second)
			if w := sendStripeActivationWebhook(t, router, event, team, user, now); w.Code != http.StatusInternalServerError {
				t.Fatalf("ambiguous grant: %d %s", w.Code, w.Body.String())
			}
			if len(stripe.creditGrantCalls) != 1 || len(stripe.accepted) != 1 {
				t.Fatalf("ambiguous provider result: calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
			}
			var attemptedAt time.Time
			if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_attempted_at FROM user_promotion_entitlement WHERE user_id=$1`, user).
				Scan(&attemptedAt); err != nil {
				t.Fatal(err)
			}
			assertPending := func() {
				t.Helper()
				var retained bool
				if err := testPool.QueryRow(ctx, `SELECT
					u.stripe_device_fingerprint=$4 AND u.stripe_redemption_reserved_team_id=$1
					AND u.stripe_redemption_attempted_at=$5 AND u.stripe_redemption_at IS NULL
					AND a.stripe_activation_user_id=$2 AND a.stripe_activation_credit_reserved_at IS NOT NULL
					AND a.stripe_activation_credit_reservation_event_id=$3
					AND a.stripe_activation_identity_key=$6 AND a.stripe_activation_identity_evidence_version=$7
					AND a.stripe_activation_credit_granted_at IS NULL AND a.stripe_activation_credit_grant_id IS NULL
					AND i.stripe_reserved_team_id=$1 AND i.stripe_reserved_user_id=$2 AND i.stripe_redemption_at IS NULL
					AND e.processed_at IS NULL
					AND NOT EXISTS(SELECT 1 FROM promotion_device_grant WHERE promotion='stripe' AND user_id=$2)
					FROM user_promotion_entitlement u JOIN team_billing_account a ON a.team_id=$1
					JOIN promotion_identity i ON i.identity_key=$6
					JOIN stripe_webhook_event e ON e.event_id=$3 WHERE u.user_id=$2`,
					team, user, event, fingerprint, attemptedAt, identity, evidence).Scan(&retained); err != nil || !retained {
					t.Fatalf("ambiguous grant lost original device, actor, evidence or event fence: %t, %v", retained, err)
				}
			}
			assertPending()
			if expired {
				attemptedAt = now.Add(-25 * time.Hour)
				rolloutExec(t, testPool, `UPDATE user_promotion_entitlement SET stripe_redemption_attempted_at=$2 WHERE user_id=$1`, user, attemptedAt)
				// A new provider call after its idempotency cache expires would grant twice.
				clear(stripe.accepted)
			}
			reserve(team, user, "evt-"+uuid.NewString(), "blocked")
			reserve(canonicalStripeTeam(t), user, "evt-"+uuid.NewString(), "blocked")
			other := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
			rolloutExec(t, testPool, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
				other, uuid.New(), "event-"+uuid.NewString(), "visitor-"+uuid.NewString())
			reserve(team, other, event, "blocked")
			assertPending()
			for retry := 0; retry < 2; retry++ {
				reserve(team, user, event, "existing")
				assertPending()
			}
			wantStatus := http.StatusOK
			if expired {
				wantStatus = http.StatusInternalServerError
			}
			for retry := 0; retry < 2; retry++ {
				if w := sendStripeActivationWebhook(t, router, event, team, user, now); w.Code != wantStatus {
					t.Fatalf("ambiguous recovery: %d %s", w.Code, w.Body.String())
				}
				if expired {
					reserve(team, user, event, "existing")
					assertPending()
				}
			}
			if expired {
				if len(stripe.creditGrantCalls) != 1 || len(stripe.accepted) != 0 {
					t.Fatalf("expired retry called provider: calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
				}
				return
			}
			if len(stripe.creditGrantCalls) != 2 || len(stripe.accepted) != 1 ||
				stripe.creditGrantCalls[0].IdempotencyKey != stripe.creditGrantCalls[1].IdempotencyKey {
				t.Fatalf("recovery did not replay one provider grant: calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
			}
			for retry := 0; retry < 2; retry++ {
				rolloutExec(t, testPool, `SELECT record_stripe_promotion_device_grant($1,$2)`, team, user)
			}
			var settled bool
			if err := testPool.QueryRow(ctx, `SELECT
				u.stripe_device_fingerprint=$3 AND u.stripe_redemption_team_id=$1 AND u.stripe_redemption_at IS NOT NULL
				AND u.stripe_redemption_reserved_team_id IS NULL
				AND a.stripe_activation_user_id=$2 AND a.stripe_activation_identity_key=$4
				AND a.stripe_activation_identity_evidence_version=$5 AND a.stripe_activation_credit_reserved_at IS NULL
				AND a.stripe_activation_credit_grant_id=$6 AND a.stripe_activation_credit_granted_at IS NOT NULL
				AND i.stripe_redemption_at IS NOT NULL AND i.stripe_reserved_team_id IS NULL
				AND (SELECT count(*) FROM promotion_device_grant WHERE promotion='stripe' AND user_id=$2 AND team_id=$1 AND fingerprint=$3)=1
				FROM user_promotion_entitlement u JOIN team_billing_account a ON a.team_id=$1
				JOIN promotion_identity i ON i.identity_key=$4 WHERE u.user_id=$2`,
				team, user, fingerprint, identity, evidence, stripe.accepted[stripe.creditGrantCalls[0].IdempotencyKey]).Scan(&settled); err != nil || !settled {
				t.Fatalf("recovered grant lost original pins or consumption: %t, %v", settled, err)
			}
			reserve(team, user, event, "ineligible")
		})
	}
}

func TestIntegration_PromotionDeviceAliasesAfterRegionalAccountDeletion(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	promotionExampleProviderDomains(t, region)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	for _, state := range []string{"unclaimed", "redeemed"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			mailbox := "device" + strings.ReplaceAll(uuid.NewString(), "-", "")
			fingerprint := "visitor-" + uuid.NewString()
			newActor := func(email, device, wantRegistration string) uuid.UUID {
				t.Helper()
				user := uuid.New()
				rolloutExec(t, region, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, user, email)
				var registration string
				if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
					user, uuid.New(), "event-"+uuid.NewString(), device).Scan(&registration); err != nil || registration != wantRegistration {
					t.Fatalf("registration = %q, want %q: %v", registration, wantRegistration, err)
				}
				return user
			}
			owner := newActor(mailbox+"@mail.example.com", fingerprint, "owner")
			var ownerTeam uuid.UUID
			if state == "redeemed" {
				var outcome string
				ownerTeam, outcome = promotionClaimSignup(t, region, owner)
				if outcome != "granted" {
					t.Fatalf("owner signup = %q", outcome)
				}
				rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, ownerTeam)
				var reservation string
				if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
					ownerTeam, owner, "evt-"+uuid.NewString()).Scan(&reservation); err != nil || reservation != "acquired" {
					t.Fatalf("owner Stripe reservation = %q: %v", reservation, err)
				}
				rolloutExec(t, region, `SELECT finalize_stripe_promotion($1,$2,$3)`, ownerTeam, owner, "grant-"+uuid.NewString())
				rolloutExec(t, region, `SELECT record_stripe_promotion_device_grant($1,$2)`, ownerTeam, owner)
			}
			assertAliasDenied := func(device, registration, wantOutcome, wantReason, wantReservation string) {
				t.Helper()
				email := strings.ToUpper(mailbox[:6]+"."+mailbox[6:]) + "+" + uuid.NewString() + "@ALIAS.EXAMPLE.COM"
				alias := newActor(email, device, registration)
				var sameIdentity bool
				if err := region.QueryRow(ctx, `SELECT promotion_identity_key($1,$2,true)=promotion_identity_key($3,$4,true)`,
					owner, mailbox+"@mail.example.com", alias, email).Scan(&sameIdentity); err != nil || !sameIdentity {
					t.Fatalf("fixture must share canonical identity: %t, %v", sameIdentity, err)
				}
				team := uuid.New()
				rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
				rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
				for retry := 0; retry < 2; retry++ {
					var outcome, reason, reservation string
					if err := region.QueryRow(ctx, `SELECT outcome,reason FROM claim_team_signup_trial_with_device($1,$2)`,
						team, alias).Scan(&outcome, &reason); err != nil || outcome != wantOutcome || reason != wantReason {
						t.Fatalf("alias signup = %q %q, want %q %q: %v", outcome, reason, wantOutcome, wantReason, err)
					}
					if err := region.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
						team, alias, "evt-"+team.String()).Scan(&reservation); err != nil || reservation != wantReservation {
						t.Fatalf("alias Stripe reservation = %q, want %q: %v", reservation, wantReservation, err)
					}
				}
				var consumed bool
				if err := region.QueryRow(ctx, `SELECT
					EXISTS(SELECT 1 FROM team_credit_grant WHERE team_id=$1)
					OR EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$2)
					OR EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id=$2)
					OR EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND
						(signup_trial_claimed_at IS NOT NULL OR stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
					OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND
						(stripe_activation_credit_reserved_at IS NOT NULL OR stripe_activation_credit_grant_id IS NOT NULL))`,
					team, alias).Scan(&consumed); err != nil || consumed {
					t.Fatalf("denied alias acquired credit or a reservation: %t, %v", consumed, err)
				}
			}
			assertAliasDenied(fingerprint, "owner_conflict", "promotion_ineligible", "owner_conflict", "owner_conflict")
			if state == "redeemed" {
				// Remove the ledger's actor reference through the existing team cleanup
				// path before deleting the regional profile and its cascading entitlements.
				rolloutExec(t, region, `DELETE FROM team_credit_grant WHERE team_id=$1`, ownerTeam)
				rolloutExec(t, region, `DELETE FROM team WHERE id=$1`, ownerTeam)
			}
			rolloutExec(t, region, `DELETE FROM profile WHERE id=$1`, owner)
			var remains bool
			if err := region.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profile WHERE id=$1)
				OR EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id=$1)
				OR EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1)`, owner).Scan(&remains); err != nil || remains {
				t.Fatalf("regional account deletion did not cascade: %t, %v", remains, err)
			}
			assertAliasDenied(fingerprint, "owner_conflict", "promotion_ineligible", "owner_conflict", "owner_conflict")
			if state == "redeemed" {
				assertAliasDenied("visitor-"+uuid.NewString(), "owner", "already_claimed", "identity_already_claimed", "ineligible")
			}
			var retainedOwner uuid.UUID
			var evidence, signupGrants, stripeGrants int
			if err := region.QueryRow(ctx, `SELECT user_id,
				(SELECT count(*) FROM promotion_signup_device_evidence WHERE user_id=$2 AND fingerprint=$1),
				(SELECT count(*) FROM promotion_device_grant WHERE fingerprint=$1 AND promotion='signup' AND user_id=$2),
				(SELECT count(*) FROM promotion_device_grant WHERE fingerprint=$1 AND promotion='stripe' AND user_id=$2)
				FROM promotion_device_owner WHERE fingerprint=$1`, fingerprint, owner).
				Scan(&retainedOwner, &evidence, &signupGrants, &stripeGrants); err != nil {
				t.Fatal(err)
			}
			wantGrants := 0
			if state == "redeemed" {
				wantGrants = 1
			}
			if retainedOwner != owner || evidence != 1 || signupGrants != wantGrants || stripeGrants != wantGrants {
				t.Fatalf("retained facts: owner=%s evidence=%d signup=%d stripe=%d", retainedOwner, evidence, signupGrants, stripeGrants)
			}
		})
	}
}

func TestIntegration_PromotionDeviceConcurrentClaims(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	rolloutExec(t, region, `SELECT set_promotion_device_policy(true,true)`)
	for _, promotion := range []string{"signup", "stripe"} {
		for _, scenario := range []string{"same user across teams", "same device across users", "same request replay"} {
			t.Run(promotion+"/"+scenario, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				users := [2]uuid.UUID{uuid.New(), uuid.New()}
				fingerprint := "visitor-" + uuid.NewString()
				for i, user := range users {
					rolloutExec(t, region, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
					var registration string
					if err := region.QueryRow(ctx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
						user, uuid.New(), "event-"+uuid.NewString(), fingerprint).Scan(&registration); err != nil {
						t.Fatal(err)
					}
					want := "owner"
					if i == 1 {
						want = "owner_conflict"
					}
					if registration != want {
						t.Fatalf("registration = %q, want %q", registration, want)
					}
				}
				teams := [2]uuid.UUID{uuid.New(), uuid.New()}
				for _, team := range teams {
					rolloutExec(t, region, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "promotion-"+team.String())
					if promotion == "stripe" {
						rolloutExec(t, region, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
					}
				}
				events := [2]string{"evt-" + uuid.NewString(), "evt-" + uuid.NewString()}
				if scenario != "same device across users" {
					users[1] = users[0]
				}
				if scenario == "same request replay" {
					teams[1], events[1] = teams[0], events[0]
				}
				query := `SELECT outcome, reason FROM claim_team_signup_trial_with_device($1,$2)`
				args := [2][]any{{teams[0], users[0]}, {teams[1], users[1]}}
				if promotion == "stripe" {
					query = `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false), ''::text`
					for i := range args {
						args[i] = append(args[i], events[i])
					}
				}
				first, err := region.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Rollback(context.Background())
				var outcome, reason string
				if err := first.QueryRow(ctx, query, args[0]...).Scan(&outcome, &reason); err != nil {
					t.Fatal(err)
				}
				want := "granted"
				if promotion == "stripe" {
					want = "acquired"
				}
				if outcome != want {
					t.Fatalf("first claim = %q, want %q", outcome, want)
				}
				// Keep the first write uncommitted until the competing connection has
				// reached its fence, so scheduling cannot turn this into serial calls.
				waits := scenario == "same user across teams" || promotion == "stripe" && scenario == "same request replay"
				result := promotionOverlappingClaim(t, ctx, region, first, waits, query, args[1])
				if promotion == "signup" && scenario == "same request replay" {
					var pgErr *pgconn.PgError
					if !errors.As(result.err, &pgErr) || pgErr.Code != "55P03" {
						t.Fatalf("overlapping signup replay must retry the team lock: %+v", result)
					}
					result.err = region.QueryRow(ctx, query, args[1]...).Scan(&result.outcome, &result.reason)
				}
				wantOutcome, wantReason := "already_claimed", "identity_already_claimed"
				if promotion == "stripe" {
					wantOutcome, wantReason = "blocked", ""
				}
				if scenario == "same device across users" {
					wantOutcome, wantReason = "promotion_ineligible", "owner_conflict"
					if promotion == "stripe" {
						wantOutcome, wantReason = "owner_conflict", ""
					}
				} else if scenario == "same request replay" {
					wantOutcome, wantReason = outcome, reason
					if promotion == "stripe" {
						wantOutcome = "existing"
					}
				}
				if result.err != nil || result.outcome != wantOutcome || result.reason != wantReason {
					t.Fatalf("competing claim = %+v, want %q %q", result, wantOutcome, wantReason)
				}
				// Replay the winner after the competing request and check durable facts.
				var replayOutcome, replayReason string
				if err := region.QueryRow(ctx, query, args[0]...).Scan(&replayOutcome, &replayReason); err != nil {
					t.Fatal(err)
				}
				if promotion == "stripe" {
					outcome = "existing"
				}
				if replayOutcome != outcome || replayReason != reason {
					t.Fatalf("winner replay = %q %q, want %q %q", replayOutcome, replayReason, outcome, reason)
				}
				if promotion == "signup" {
					var grants, devices, claims, entitlements, identities, outcomes int
					var amount, remaining float64
					err := region.QueryRow(ctx, `SELECT
						(SELECT count(*) FROM team_credit_grant WHERE team_id IN ($1,$2) AND reason='signup trial credit'),
						(SELECT COALESCE(sum(amount_usd),0) FROM team_credit_grant WHERE team_id IN ($1,$2) AND reason='signup trial credit'),
						(SELECT COALESCE(sum(remaining_usd),0) FROM team_credit_grant WHERE team_id IN ($1,$2) AND reason='signup trial credit'),
						(SELECT count(*) FROM promotion_device_grant WHERE promotion='signup' AND fingerprint=$3),
						(SELECT count(*) FROM user_signup_trial_claim WHERE team_id IN ($1,$2)),
						(SELECT count(*) FROM user_promotion_entitlement WHERE signup_trial_team_id IN ($1,$2)),
						(SELECT count(*) FROM promotion_identity i WHERE i.signup_claimed_at IS NOT NULL AND EXISTS (
							SELECT 1 FROM promotion_identity_binding b JOIN promotion_signup_device_evidence e ON e.user_id=b.user_id
							WHERE b.identity_key=i.identity_key AND e.fingerprint=$3)),
						(SELECT count(*) FROM team_signup_promotion_outcome WHERE team_id IN ($1,$2) AND outcome='granted')`,
						teams[0], teams[1], fingerprint).Scan(&grants, &amount, &remaining, &devices, &claims, &entitlements, &identities, &outcomes)
					if err != nil || grants != 1 || amount != 5 || remaining != 5 || devices != 1 || claims != 1 || entitlements != 1 || identities != 1 || outcomes != 1 {
						t.Fatalf("signup facts: grants=%d amount=%v remaining=%v devices=%d claims=%d entitlements=%d identities=%d outcomes=%d err=%v",
							grants, amount, remaining, devices, claims, entitlements, identities, outcomes, err)
					}
				} else {
					var accounts, entitlements, identities, grants int
					var pinned bool
					err := region.QueryRow(ctx, `SELECT
						(SELECT count(*) FROM team_billing_account WHERE team_id IN ($1,$2) AND stripe_activation_credit_reserved_at IS NOT NULL),
						(SELECT count(*) FROM user_promotion_entitlement WHERE stripe_device_fingerprint=$3 AND stripe_redemption_reserved_team_id IS NOT NULL),
						(SELECT count(*) FROM promotion_identity WHERE stripe_reserved_team_id IN ($1,$2)),
						(SELECT count(*) FROM promotion_device_grant WHERE promotion='stripe' AND fingerprint=$3),
						EXISTS(SELECT 1 FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=a.stripe_activation_user_id
							WHERE a.team_id=$1 AND a.stripe_activation_user_id=$4 AND a.stripe_activation_credit_reservation_event_id=$5
							AND u.stripe_redemption_reserved_team_id=$1 AND u.stripe_device_fingerprint=$3 AND u.stripe_redemption_at IS NULL)`,
						teams[0], teams[1], fingerprint, users[0], events[0]).Scan(&accounts, &entitlements, &identities, &grants, &pinned)
					if err != nil || accounts != 1 || entitlements != 1 || identities != 1 || grants != 0 || !pinned {
						t.Fatalf("Stripe facts: accounts=%d entitlements=%d identities=%d grants=%d pinned=%t err=%v", accounts, entitlements, identities, grants, pinned, err)
					}
				}
			})
		}
	}
}

type promotionConcurrentClaimResult struct {
	outcome, reason string
	err             error
}

func promotionOverlappingClaim(t *testing.T, ctx context.Context, region *pgxpool.Pool, first pgx.Tx, waits bool, query string, args []any) promotionConcurrentClaimResult {
	t.Helper()
	conn, err := region.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := conn.Conn().PgConn().PID()
	claimCtx, cancel := context.WithCancel(ctx)
	done := make(chan promotionConcurrentClaimResult, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		cancel()
		wg.Wait()
	}()
	go func() {
		defer wg.Done()
		defer conn.Release()
		var result promotionConcurrentClaimResult
		result.err = conn.QueryRow(claimCtx, query, args...).Scan(&result.outcome, &result.reason)
		done <- result
	}()
	var result promotionConcurrentClaimResult
	if waits {
		deadline := time.Now().Add(4 * time.Second)
		for {
			var blocked bool
			if err := region.QueryRow(ctx, `SELECT $1::int = ANY(pg_blocking_pids($2::int))`, first.Conn().PgConn().PID(), pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case result := <-done:
				t.Fatalf("competing claim escaped the uncommitted claim: %+v", result)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("competing claim did not reach the first transaction's fence")
			}
			time.Sleep(5 * time.Millisecond)
		}
	} else {
		result = <-done
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if waits {
		result = <-done
	}
	return result
}

func TestIntegration_PromotionGrantFunctionPrivileges(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rolloutExec(t, tx, `DO $$ DECLARE r text; BEGIN
		FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
				EXECUTE format('CREATE ROLE %I NOLOGIN', r);
			END IF;
		END LOOP;
	END $$;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated`)
	migration, err := os.ReadFile("../../supabase/migrations/20260927231112_enforce_promotion_device_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		function, previous, start, end, revoke string
	}{
		{
			"public.claim_team_signup_trial_with_device(uuid,uuid)",
			"claim_team_signup_trial_with_device_acl_test_previous",
			"CREATE OR REPLACE FUNCTION claim_team_signup_trial_with_device(p_team_id",
			"CREATE OR REPLACE FUNCTION claim_team_signup_trial(p_team_id",
			"REVOKE ALL ON FUNCTION claim_team_signup_trial_with_device(uuid,uuid) FROM PUBLIC;",
		},
		{
			"public.claim_team_signup_trial(uuid,uuid)",
			"claim_team_signup_trial_acl_test_previous",
			"CREATE OR REPLACE FUNCTION claim_team_signup_trial(p_team_id",
			"CREATE OR REPLACE FUNCTION create_team_with_signup_trial(",
			"REVOKE ALL ON FUNCTION claim_team_signup_trial(uuid,uuid) FROM PUBLIC;",
		},
		{
			"public.reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean)",
			"reserve_stripe_promotion_with_device_acl_test_previous",
			"CREATE OR REPLACE FUNCTION reserve_stripe_promotion_with_device(p_team_id",
			"CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_subscription_event_state(\n",
			"REVOKE ALL ON FUNCTION reserve_stripe_promotion_with_device(uuid,uuid,text,text,timestamptz,boolean) FROM PUBLIC;",
		},
		{
			"public.reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean)",
			"reserve_stripe_promotion_for_subscription_event_state_acl_test_previous",
			"CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_subscription_event_state(\n",
			"CREATE OR REPLACE FUNCTION finalize_stripe_promotion(",
			"REVOKE ALL ON FUNCTION reserve_stripe_promotion_for_subscription_event_state(uuid,uuid,text,text,timestamptz,boolean) FROM PUBLIC;",
		},
	} {
		start := strings.Index(string(migration), tc.start)
		end := strings.Index(string(migration), tc.end)
		if start < 0 || end <= start {
			t.Fatalf("function migration segment missing: %s", tc.function)
		}
		segment := string(migration[start:end])
		revoke := strings.Index(segment, tc.revoke)
		if revoke < 0 {
			t.Fatalf("function revocation missing: %s", tc.function)
		}
		rolloutExec(t, tx, "ALTER FUNCTION "+tc.function+" RENAME TO "+tc.previous)
		rolloutExec(t, tx, segment[:revoke])
		for _, role := range []string{"anon", "authenticated"} {
			var directlyGranted bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_proc p,
				LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) privilege
				WHERE p.oid = $1::regprocedure AND privilege.grantee = $2::regrole
					AND privilege.privilege_type = 'EXECUTE'
			)`, tc.function, role).Scan(&directlyGranted); err != nil {
				t.Fatal(err)
			}
			if !directlyGranted {
				t.Fatalf("default privileges did not grant %s execute on %s", role, tc.function)
			}
		}
		rolloutExec(t, tx, segment[revoke:])
		var publicExecute bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_proc p,
			LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) privilege
			WHERE p.oid = $1::regprocedure AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
		)`, tc.function).Scan(&publicExecute); err != nil {
			t.Fatal(err)
		}
		if publicExecute {
			t.Errorf("PUBLIC can invoke promotion grant function %s", tc.function)
		}
		for _, role := range []string{"anon", "authenticated", "service_role"} {
			var executable bool
			if err := tx.QueryRow(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, role, tc.function).Scan(&executable); err != nil {
				t.Fatal(err)
			}
			if executable != (role == "service_role") {
				t.Errorf("%s execute on %s = %t", role, tc.function, executable)
			}
		}
	}
}

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
	for _, tc := range []struct {
		name                        string
		canonical, device, evidence bool
		duplicate, missing          string
	}{
		{"off/off/off", false, false, false, "eligible", "eligible"},
		{"off/off/on", false, false, true, "configuration", "configuration"},
		{"off/on/off", false, true, false, "configuration", "configuration"},
		{"off/on/on", false, true, true, "configuration", "configuration"},
		{"on/off/off", true, false, false, "eligible", "eligible"},
		{"on/off/on", true, false, true, "eligible", "evidence_missing"},
		{"on/on/off", true, true, false, "owner_conflict", "eligible"},
		{"on/on/on", true, true, true, "owner_conflict", "evidence_missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, actor := range []struct {
				name, decision string
			}{
				{"owner", "eligible"},
				{"duplicate", tc.duplicate},
				{"missing", tc.missing},
			} {
				t.Run(actor.name, func(t *testing.T) {
					tx := localIdentityTransaction(t, tc.canonical)
					invalid := !tc.canonical && (tc.device || tc.evidence)
					if invalid {
						localIdentityError(t, tx, "22023", `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
						// Malformed persisted gates must also fail closed at both entry points.
						rolloutExec(t, tx, `UPDATE promotion_device_policy SET device_enforced=$1,evidence_required=$2 WHERE singleton`, tc.device, tc.evidence)
					} else {
						rolloutExec(t, tx, `SELECT set_promotion_device_policy($1,$2)`, tc.device, tc.evidence)
					}
					user, team := uuid.New(), uuid.New()
					email := user.String() + "@example.com"
					version := localIdentityWrite(t, tx, user, email, true, time.Now(), time.Now())
					rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "gate-"+team.String())
					rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
					owner := user
					var fingerprint any
					if actor.name != "missing" {
						fingerprint = "visitor-" + uuid.NewString()
						if actor.name == "duplicate" {
							owner = uuid.New()
							rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
								owner, uuid.New(), "event-"+uuid.NewString(), fingerprint)
						}
						rolloutExec(t, tx, `SELECT register_promotion_signup_device($1,$2,$3,$4)`,
							user, uuid.New(), "event-"+uuid.NewString(), fingerprint)
					}
					event := "evt-" + uuid.NewString()
					eligible := !invalid && actor.decision == "eligible"
					wantCount := 0
					if eligible {
						wantCount = 1
					}
					for retry := 0; retry < 2; retry++ {
						if invalid {
							localIdentityError(t, tx, "55000", `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user)
							localIdentityError(t, tx, "55000", `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`, team, user, event)
						} else {
							wantOutcome, wantReason, wantReservation := "promotion_ineligible", actor.decision, actor.decision
							if eligible {
								wantOutcome, wantReason, wantReservation = "granted", "first_user_claim", "acquired"
								if tc.canonical {
									wantReason = "first_identity_claim"
								}
								if retry > 0 {
									wantReservation = "existing"
								}
							}
							var outcome, reason, reservation string
							if err := tx.QueryRow(ctx, `SELECT outcome,reason FROM claim_team_signup_trial_with_device($1,$2)`,
								team, user).Scan(&outcome, &reason); err != nil || outcome != wantOutcome || reason != wantReason {
								t.Fatalf("signup = %q %q, want %q %q: %v", outcome, reason, wantOutcome, wantReason, err)
							}
							if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
								team, user, event).Scan(&reservation); err != nil || reservation != wantReservation {
								t.Fatalf("Stripe reservation = %q, want %q: %v", reservation, wantReservation, err)
							}
						}
						var signupState, stripeState, ownership bool
						if err := tx.QueryRow(ctx, `SELECT
							(SELECT count(*) FROM team_credit_grant WHERE team_id=$1)=$3
							AND (SELECT COALESCE(sum(amount_usd),0) FROM team_credit_grant WHERE team_id=$1)=5*$3
							AND (SELECT COALESCE(sum(remaining_usd),0) FROM team_credit_grant WHERE team_id=$1)=5*$3
							AND (SELECT count(*) FROM user_signup_trial_claim WHERE user_id=$2 AND team_id=$1)=$3
							AND (SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$2
								AND signup_trial_team_id=$1 AND signup_trial_claimed_at IS NOT NULL)=$3
							AND (SELECT count(*) FROM promotion_device_grant WHERE user_id=$2 AND promotion='signup')=$3
							AND (SELECT count(*) FROM promotion_device_grant WHERE user_id=$2 AND promotion='signup'
								AND team_id=$1 AND fingerprint IS NOT DISTINCT FROM $4::text)=$3
							AND (SELECT count(*) FROM promotion_identity WHERE identity_key=promotion_identity_key($2,$5,true)
								AND signup_claimed_at IS NOT NULL)=$3`, team, user, wantCount, fingerprint, email).
							Scan(&signupState); err != nil || !signupState {
							t.Fatalf("signup grant amount, consumption or device attribution mismatch (retry %d): %t, %v", retry, signupState, err)
						}
						if err := tx.QueryRow(ctx, `SELECT
							(SELECT count(*) FROM team_billing_account WHERE team_id=$1 AND stripe_activation_credit_reserved_at IS NOT NULL)=$3
							AND (SELECT count(*) FROM user_promotion_entitlement WHERE user_id=$2 AND stripe_redemption_reserved_team_id=$1)=$3
							AND (SELECT count(*) FROM promotion_identity WHERE stripe_reserved_team_id=$1 AND stripe_reserved_user_id=$2)=$3
							AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND stripe_redemption_at IS NOT NULL)
							AND NOT EXISTS(SELECT 1 FROM promotion_device_grant WHERE user_id=$2 AND promotion='stripe')
							AND NOT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1
								AND (stripe_activation_credit_granted_at IS NOT NULL OR stripe_activation_credit_grant_id IS NOT NULL))`,
							team, user, wantCount).Scan(&stripeState); err != nil || !stripeState {
							t.Fatalf("Stripe reservation fence or premature consumption mismatch (retry %d): %t, %v", retry, stripeState, err)
						}
						if eligible {
							var pinned bool
							if err := tx.QueryRow(ctx, `SELECT a.stripe_activation_user_id=$2
								AND a.stripe_activation_credit_reservation_event_id=$3
								AND a.stripe_activation_identity_evidence_version=$4
								AND a.stripe_activation_identity_key=CASE WHEN $5 THEN promotion_identity_key($2,$6,true) ELSE 'legacy:'||$2::text END
								AND u.stripe_device_fingerprint IS NOT DISTINCT FROM $7::text
								FROM team_billing_account a JOIN user_promotion_entitlement u ON u.user_id=$2
								WHERE a.team_id=$1`, team, user, event, version, tc.canonical, email, fingerprint).
								Scan(&pinned); err != nil || !pinned {
								t.Fatalf("Stripe actor, evidence, event or device pin mismatch: %t, %v", pinned, err)
							}
						}
						if err := tx.QueryRow(ctx, `SELECT CASE WHEN $1::text IS NULL THEN
							NOT EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$2)
							AND NOT EXISTS(SELECT 1 FROM promotion_device_owner WHERE user_id=$2)
							ELSE EXISTS(SELECT 1 FROM promotion_signup_device_evidence WHERE user_id=$2 AND fingerprint=$1)
							AND EXISTS(SELECT 1 FROM promotion_device_owner WHERE fingerprint=$1 AND user_id=$3) END`,
							fingerprint, user, owner).Scan(&ownership); err != nil || !ownership {
							t.Fatalf("gate changed first ownership or fabricated missing evidence: %t, %v", ownership, err)
						}
					}
				})
			}
		})
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
			rolloutExec(t, tx, `INSERT INTO team_signup_trial_provenance(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team)
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
			localIdentityError(t, tx, tc.sqlState, `SELECT reserve_stripe_promotion_with_device($1,$2,$3,NULL,NULL,false)`,
				team, user, "evt-"+uuid.NewString())
			assertUnchanged(t, tx, user, team, false)
			var outcome, reason string
			if err := tx.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial_with_device($1,$2)`, team, user).
				Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "authority_unavailable" {
				t.Fatalf("authority failure result = %q/%q: %v", outcome, reason, err)
			}
			assertUnchanged(t, tx, user, team, true)
			if err := tx.QueryRow(ctx, `SELECT * FROM claim_team_signup_trial($1,$2)`, team, user).
				Scan(&outcome, &reason); err != nil || outcome != "promotion_ineligible" || reason != "authority_unavailable" {
				t.Fatalf("authority failure replay = %q/%q: %v", outcome, reason, err)
			}
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
