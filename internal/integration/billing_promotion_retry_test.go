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
	if len(stripe.creditGrantCalls) != 2 || len(stripe.accepted) != 1 {
		t.Fatalf("Stripe calls=%d accepted grants=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
	}
	otherTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1)`, otherTeam); err != nil {
		t.Fatal(err)
	}
	if state, err := testQueries.ReserveStripePromotionForEventState(ctx, db.ReserveStripePromotionForEventStateParams{TeamID: otherTeam, UserID: userID, EventID: "evt_other_team"}); err != nil || state != "ineligible" {
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
