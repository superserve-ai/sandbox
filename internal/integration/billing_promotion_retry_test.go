//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_StalePromotionCleanupRetries(t *testing.T) {
	for _, failure := range []string{"release", "bookkeeping", "different_event"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
			now := time.Now().UTC().Truncate(time.Second)
			eventID := "evt_stale_" + teamID.String()
			ownerEvent := eventID
			if failure == "different_event" {
				ownerEvent = "evt_newer_" + teamID.String()
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
				VALUES($1,$2,$3,'canceled',$4)`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String(), now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if state, err := testQueries.ReserveStripePromotionForEventState(ctx, db.ReserveStripePromotionForEventStateParams{TeamID: teamID, UserID: userID, EventID: ownerEvent}); err != nil || state != "acquired" {
				t.Fatalf("reserve: %s %v", state, err)
			}
			stripe := &fakeStripeClient{}
			router := newBillingRouter(t, stripe)
			if failure != "different_event" {
				statement := `CREATE FUNCTION fail_stale_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.stripe_redemption_reserved_team_id IS NULL THEN RAISE EXCEPTION 'injected release failure'; END IF; RETURN NEW; END; $$;
					CREATE TRIGGER fail_stale_cleanup BEFORE UPDATE ON user_promotion_entitlement FOR EACH ROW EXECUTE FUNCTION fail_stale_cleanup();`
				table := "user_promotion_entitlement"
				if failure == "bookkeeping" {
					table = "stripe_webhook_event"
					statement = `CREATE FUNCTION fail_stale_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN IF NEW.processed_at IS NOT NULL THEN RAISE EXCEPTION 'injected bookkeeping failure'; END IF; RETURN NEW; END; $$;
						CREATE TRIGGER fail_stale_cleanup BEFORE UPDATE ON stripe_webhook_event FOR EACH ROW EXECUTE FUNCTION fail_stale_cleanup();`
				}
				if _, err := testPool.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
				removeFailure := func() {
					if _, err := testPool.Exec(ctx, "DROP TRIGGER IF EXISTS fail_stale_cleanup ON "+table+"; DROP FUNCTION IF EXISTS fail_stale_cleanup();"); err != nil {
						t.Error(err)
					}
				}
				t.Cleanup(removeFailure)
				if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
					t.Fatalf("injected failure: %d %s", w.Code, w.Body.String())
				}
				var pending bool
				if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_reserved_team_id=$2 FROM user_promotion_entitlement WHERE user_id=$1`, userID, teamID).Scan(&pending); err != nil || !pending {
					t.Fatalf("failed cleanup lost fence: %v %v", pending, err)
				}
				removeFailure()
			}
			if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusOK {
				t.Fatalf("retry: %d %s", w.Code, w.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			wantPending := failure == "different_event"
			if account.StripeActivationCreditReservedAt.Valid != wantPending || len(stripe.creditGrantCalls) != 0 || derefString(account.StripeSubscriptionStatus) != "canceled" {
				t.Fatalf("stale cleanup: pending=%v want=%v calls=%d status=%s", account.StripeActivationCreditReservedAt.Valid, wantPending, len(stripe.creditGrantCalls), derefString(account.StripeSubscriptionStatus))
			}
			var pending, redeemed bool
			if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_reserved_team_id IS NOT NULL, stripe_redemption_at IS NOT NULL FROM user_promotion_entitlement WHERE user_id=$1`, userID).Scan(&pending, &redeemed); err != nil || pending != wantPending || redeemed {
				t.Fatalf("entitlement: pending=%v redeemed=%v err=%v", pending, redeemed, err)
			}
		})
	}
}

type ambiguousPromotionClient struct {
	*fakeStripeClient
	t              *testing.T
	userID, teamID uuid.UUID
	accepted       map[string]string
	revocationErr  error
	revokedGrantID string
}

func (s *ambiguousPromotionClient) RevokeActivationCredit(_ context.Context, teamID uuid.UUID, customerID, grantID string) (string, error) {
	if s.revocationErr != nil {
		return "", s.revocationErr
	}
	accepted := s.accepted["stripe-activation-credit-"+teamID.String()]
	if teamID != s.teamID || customerID != "cus_"+s.teamID.String() || accepted == "" || grantID != "" && grantID != accepted {
		return "", errors.New("Stripe activation grant identity is missing")
	}
	s.revokedGrantID = accepted
	return accepted, nil
}

func (s *ambiguousPromotionClient) CreateBillingCreditGrant(ctx context.Context, p api.StripeCreateBillingCreditGrantParams) (api.StripeBillingCreditGrant, error) {
	s.t.Helper()
	var attempted bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_attempted_at IS NOT NULL FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_reserved_team_id=$2`, s.userID, s.teamID).Scan(&attempted); err != nil || !attempted {
		s.t.Fatalf("Stripe called without committed attempt marker: %v %v", attempted, err)
	}
	s.creditGrantCalls = append(s.creditGrantCalls, p)
	if s.accepted[p.IdempotencyKey] == "" {
		s.accepted[p.IdempotencyKey] = "credit_" + s.teamID.String()
		return api.StripeBillingCreditGrant{}, errors.New("ambiguous transport timeout")
	}
	return api.StripeBillingCreditGrant{ID: s.accepted[p.IdempotencyKey]}, nil
}

func TestIntegration_StaleAmbiguousPromotionReconcilesWithoutReactivating(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_by)
		VALUES($1,5,5,'signup trial credit',$2)`, teamID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
		VALUES($1,$2,$3,'incomplete')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	config := testPool.Config().Copy()
	config.MaxConns = 1
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	stripe := &ambiguousPromotionClient{fakeStripeClient: &fakeStripeClient{}, t: t, userID: userID, teamID: teamID, accepted: make(map[string]string)}
	router := newBillingRouterWithPool(t, stripe, pool)
	now := time.Now().UTC().Truncate(time.Second)
	eventID := "evt_ambiguous_" + teamID.String()
	if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
		t.Fatalf("ambiguous delivery: %d %s", w.Code, w.Body.String())
	}
	// A process that dies while holding the durable request lease must not
	// permanently prevent retry of its already-attempted grant.
	if _, err := testQueries.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: "cus_" + teamID.String(), Token: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE stripe_webhook_processing_lease SET expires_at=now()-interval '1 second' WHERE customer_id=$1`, "cus_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	if w := sendStripeActivationWebhook(t, newBillingRouterWithPool(t, nil, pool), eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
		t.Fatalf("unavailable Stripe client: %d %s", w.Code, w.Body.String())
	}
	var pending bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_reserved_team_id=$2 AND stripe_redemption_attempted_at IS NOT NULL FROM user_promotion_entitlement WHERE user_id=$1`, userID, teamID).Scan(&pending); err != nil || !pending {
		t.Fatalf("pre-call failure lost ambiguous fence: %v %v", pending, err)
	}
	newer := now.Add(time.Second)
	payload := stripeSubscriptionWebhookPayload(t, "evt_cancel_"+teamID.String(), "customer.subscription.deleted", "sub_"+teamID.String(), "cus_"+teamID.String(), "canceled", newer, now, now.AddDate(0, 1, 0))
	req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
	if w := doRequest(router, req); w.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < 2; i++ {
		if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusOK {
			t.Fatalf("reconcile retry: %d %s", w.Code, w.Body.String())
		}
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	if derefString(account.StripeSubscriptionStatus) != "canceled" || !account.StripeSubscriptionEventAt.Time.Equal(newer) || !account.StripeActivationCreditGrantedAt.Valid || account.StripeActivationCreditReservedAt.Valid || !account.TrialEndedAt.Valid {
		t.Fatalf("reconciliation overwrote lifecycle or lost grant: %+v", account)
	}
	if eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, teamID); err != nil || eligible {
		t.Fatalf("canceled team retained signup credit eligibility: %v %v", eligible, err)
	}
	if len(stripe.creditGrantCalls) != 1 || len(stripe.accepted) != 1 || stripe.revokedGrantID != "credit_"+teamID.String() || derefString(account.StripeActivationCreditGrantID) != stripe.revokedGrantID {
		t.Fatalf("Stripe calls=%d accepted grants=%d revoked=%s", len(stripe.creditGrantCalls), len(stripe.accepted), stripe.revokedGrantID)
	}
	otherTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, otherTeam); err != nil {
		t.Fatal(err)
	}
	if state, err := testQueries.ReserveStripePromotionForEventState(ctx, db.ReserveStripePromotionForEventStateParams{TeamID: otherTeam, UserID: userID, EventID: "evt_other_team"}); err != nil || state != "user_already_redeemed" {
		t.Fatalf("reconciled user can redeem elsewhere: %s %v", state, err)
	}
}

func TestIntegration_StripeProcessingLeaseFencesSupersededWorkers(t *testing.T) {
	ctx := context.Background()
	customerID := "cus_" + uuid.NewString()
	first, second := uuid.New(), uuid.New()
	if _, err := testQueries.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: first}); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: second}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("overlapping request acquired live lease: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE stripe_webhook_processing_lease SET expires_at=now()-interval '1 second' WHERE customer_id=$1`, customerID); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: second}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.ReleaseStripeWebhookProcessingLease(ctx, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: first}); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: first}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("superseded worker retained mutation authority: %v", err)
	}
	if token, err := testQueries.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: second}); err != nil || token != second {
		t.Fatalf("old cleanup erased new lease: %s %v", token, err)
	}
	if err := testQueries.ReleaseStripeWebhookProcessingLease(ctx, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: customerID, Token: second}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_StripeReservationDistinguishesUserRedemption(t *testing.T) {
	region := promotionIsolatedDatabase(t, true)
	for _, tc := range []struct {
		name, want                                 string
		redeemed, canonicalOff, unverified, fenced bool
	}{
		{name: "redeemed user", redeemed: true, want: "user_already_redeemed"},
		{name: "redeemed user with canonical disabled", redeemed: true, canonicalOff: true, want: "user_already_redeemed"},
		{name: "missing canonical evidence", unverified: true, want: "ineligible"},
		{name: "migration fence", fenced: true, want: "ineligible"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := region.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			user, team := uuid.New(), uuid.New()
			rolloutExec(t, tx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,$3,clock_timestamp(),clock_timestamp())`,
				user, user.String()+"@example.com", !tc.unverified)
			rolloutExec(t, tx, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "example-team-"+team.String())
			rolloutExec(t, tx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			if tc.canonicalOff {
				// Model the pre-activation state; production deliberately forbids reversing this gate.
				rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement DISABLE TRIGGER promotion_identity_enforcement_irreversible`)
				rolloutExec(t, tx, `UPDATE promotion_identity_enforcement SET enabled=false,enabled_at=NULL,readiness_reference=NULL WHERE singleton`)
				rolloutExec(t, tx, `ALTER TABLE promotion_identity_enforcement ENABLE TRIGGER promotion_identity_enforcement_irreversible`)
			}
			if tc.redeemed {
				rolloutExec(t, tx, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at) VALUES($1,now())`, user)
			}
			if tc.fenced {
				rolloutExec(t, tx, `INSERT INTO stripe_promotion_migration_fence(team_id) VALUES($1)`, team)
			}
			for _, query := range []string{
				`SELECT reserve_stripe_promotion_for_event_state($1,$2,$3)`,
				`SELECT reserve_stripe_promotion_for_subscription_event_state($1,$2,$3,NULL,NULL,false)`,
			} {
				var state string
				if err := tx.QueryRow(t.Context(), query, team, user, "evt-"+uuid.NewString()).Scan(&state); err != nil || state != tc.want {
					t.Fatalf("reservation reason = %q, want %q: %v", state, tc.want, err)
				}
			}
			var reserved bool
			if err := tx.QueryRow(t.Context(), `SELECT stripe_activation_credit_reserved_at IS NOT NULL FROM team_billing_account WHERE team_id=$1`, team).
				Scan(&reserved); err != nil || reserved {
				t.Fatalf("denial reserved credit: %t %v", reserved, err)
			}
		})
	}
}
