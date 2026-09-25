//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

const checkoutRegressionBody = `{"success_url":"https://app.superserve.test/billing/success","cancel_url":"https://app.superserve.test/billing/cancel"}`

type checkoutAssociationCommitTracer struct {
	mu              sync.Mutex
	associationConn *pgx.Conn
	afterCommit     func()
}

func (tr *checkoutAssociationCommitTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "-- name: AssociateTeamBillingCheckoutSubscription ") {
		tr.mu.Lock()
		tr.associationConn = conn
		tr.mu.Unlock()
	}
	return ctx
}

func (tr *checkoutAssociationCommitTracer) TraceQueryEnd(_ context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	tr.mu.Lock()
	var callback func()
	if data.Err == nil && data.CommandTag.String() == "COMMIT" && conn == tr.associationConn {
		tr.associationConn = nil
		callback = tr.afterCommit
		tr.afterCommit = nil
	}
	tr.mu.Unlock()
	if callback != nil {
		callback()
	}
}

type reservedPromotionStripeClient struct {
	*fakeStripeClient
	t               *testing.T
	teamID, actorID uuid.UUID
	eventID         string
	externalGrants  map[string]string
}

func (s *reservedPromotionStripeClient) CreateBillingCreditGrant(ctx context.Context, params api.StripeCreateBillingCreditGrantParams) (api.StripeBillingCreditGrant, error) {
	s.t.Helper()
	var durable bool
	err := testPool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM user_promotion_entitlement u JOIN team_billing_account a
		ON a.team_id=u.stripe_redemption_reserved_team_id
		WHERE u.user_id=$1 AND a.team_id=$2
		AND a.stripe_activation_credit_reservation_event_id=$3
	)`, s.actorID, s.teamID, s.eventID).Scan(&durable)
	if err != nil || !durable {
		s.t.Fatalf("Stripe called without committed event reservation: durable=%v err=%v", durable, err)
	}
	s.creditGrantCalls = append(s.creditGrantCalls, params)
	if s.externalGrants == nil {
		s.externalGrants = make(map[string]string)
	}
	if s.externalGrants[params.IdempotencyKey] == "" {
		s.externalGrants[params.IdempotencyKey] = "credit_" + s.teamID.String()
	}
	return api.StripeBillingCreditGrant{ID: s.externalGrants[params.IdempotencyKey]}, nil
}

func TestIntegration_CheckoutSubscriptionReconciliation(t *testing.T) {
	for _, order := range []string{"subscription_first", "checkout_first", "replacement_checkout_first", "old_event_during_replacement", "old_event_after_completion", "rollback_after_grant", "newest_terminal_first"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
			eventID := "evt_activation_" + teamID.String()
			stripe := &reservedPromotionStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_" + teamID.String()}, t: t, teamID: teamID, actorID: actorID, eventID: eventID}
			tracer := &checkoutAssociationCommitTracer{}
			poolConfig := testPool.Config().Copy()
			poolConfig.ConnConfig.Tracer = tracer
			pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			router := newBillingRouterWithPool(t, stripe, pool)
			if order == "replacement_checkout_first" || order == "old_event_during_replacement" || order == "old_event_after_completion" {
				if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
				VALUES($1,$2,'sub_previous','canceled',now()-interval '1 day')`, teamID, stripe.nextCustomerID); err != nil {
					t.Fatal(err)
				}
			}
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
			}
			now := time.Now().UTC().Truncate(time.Second)
			subID := "sub_" + teamID.String()
			send := func(payload []byte) *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				return doRequest(router, req)
			}
			activation := stripeSubscriptionWebhookPayload(t, eventID, "customer.subscription.created", subID, stripe.nextCustomerID, "active", now, now, now.AddDate(0, 1, 0))
			completeID := "evt_complete_" + teamID.String()
			completion := []byte(strings.ReplaceAll(string(stripeCheckoutWebhookPayload(t, completeID, teamID.String(), stripe.nextCustomerID, subID, now)), "cs_"+completeID, "cs_test_123"))
			if order == "old_event_during_replacement" {
				oldEvent := stripeSubscriptionWebhookPayload(t, "evt_old_"+teamID.String(), "customer.subscription.deleted", "sub_previous", stripe.nextCustomerID, "canceled", now, now, now.AddDate(0, 1, 0))
				if w := send(oldEvent); w.Code != http.StatusOK {
					t.Fatalf("old terminal event: %d %s", w.Code, w.Body.String())
				}
				account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil || !account.CheckoutInitializingAt.Valid || account.CheckoutSessionID == nil {
					t.Fatalf("old subscription cleared new checkout lease/session: %+v %v", account, err)
				}
				otherKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
				if w := do(router, "POST", "/stripe/checkout-session", otherKey, checkoutRegressionBody); w.Code != http.StatusConflict {
					t.Fatalf("old subscription event allowed new checkout: %d", w.Code)
				}
			}
			if order == "checkout_first" || order == "replacement_checkout_first" || order == "old_event_during_replacement" || order == "old_event_after_completion" {
				if w := send(completion); w.Code != http.StatusOK {
					t.Fatalf("completion: %d %s", w.Code, w.Body.String())
				}
				if order == "old_event_after_completion" {
					for _, status := range []string{"active", "canceled"} {
						oldEvent := stripeSubscriptionWebhookPayload(t, "evt_old_"+status+teamID.String(), "customer.subscription.updated", "sub_previous", stripe.nextCustomerID, status, now.Add(-time.Minute), now.Add(-time.Hour), now.AddDate(0, 1, 0))
						if w := send(oldEvent); w.Code != http.StatusOK {
							t.Fatalf("late previous event: %d %s", w.Code, w.Body.String())
						}
					}
					account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
					if err != nil || derefString(account.StripeSubscriptionID) != subID || !account.CheckoutInitializingAt.Valid || len(stripe.externalGrants) != 0 {
						t.Fatalf("old subscription replaced checkout association or reserved promotion: %+v %v", account, err)
					}
				}
				if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
					t.Fatalf("unresolved subscription allowed checkout: %d", w.Code)
				}
				if w := send(activation); w.Code != http.StatusOK {
					t.Fatalf("activation: %d %s", w.Code, w.Body.String())
				}
			} else {
				if w := send(activation); w.Code != http.StatusInternalServerError {
					t.Fatalf("expected deferred activation: %d %s", w.Code, w.Body.String())
				}
				if order == "newest_terminal_first" {
					terminalID := "evt_terminal_" + teamID.String()
					terminal := stripeSubscriptionWebhookPayload(t, terminalID, "customer.subscription.deleted", subID, stripe.nextCustomerID, "canceled", now.Add(time.Second), now, now.AddDate(0, 1, 0))
					if _, err := testQueries.CreateStripeWebhookEvent(ctx, db.CreateStripeWebhookEventParams{EventID: terminalID, EventType: "customer.subscription.deleted", Payload: terminal}); err != nil {
						t.Fatal(err)
					}
					tracer.afterCommit = func() {
						// A provider retry is allowed to run immediately when the
						// association lock is released, before reconciliation resumes.
						if w := send(activation); w.Code != http.StatusOK {
							t.Fatalf("concurrent stale retry: %d %s", w.Code, w.Body.String())
						}
						if len(stripe.externalGrants) != 0 {
							t.Fatal("stale activation granted before retained terminal state")
						}
					}
				}
				if order == "rollback_after_grant" {
					_, err := testPool.Exec(ctx, `CREATE FUNCTION fail_reconciled_activation() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.event_type='customer.subscription.created' AND NEW.processed_at IS NOT NULL THEN
					RAISE EXCEPTION 'injected bookkeeping failure'; END IF; RETURN NEW; END; $$;
					CREATE TRIGGER fail_reconciled_activation BEFORE UPDATE ON stripe_webhook_event
					FOR EACH ROW EXECUTE FUNCTION fail_reconciled_activation();`)
					if err != nil {
						t.Fatal(err)
					}
					removeFailure := func() {
						if _, err := testPool.Exec(ctx, `DROP TRIGGER IF EXISTS fail_reconciled_activation ON stripe_webhook_event; DROP FUNCTION IF EXISTS fail_reconciled_activation();`); err != nil {
							t.Error(err)
						}
					}
					t.Cleanup(removeFailure)
					if w := send(completion); w.Code != http.StatusInternalServerError {
						t.Fatalf("expected bookkeeping failure: %d", w.Code)
					}
					account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
					if err != nil {
						t.Fatal(err)
					}
					if !account.CheckoutInitializingAt.Valid || derefString(account.StripeActivationCreditReservationEventID) != eventID || derefString(account.StripeSubscriptionID) != subID {
						t.Fatalf("rollback lost checkout association/lease or promotion reservation: %+v", account)
					}
					if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
						t.Fatalf("rollback allowed another checkout: %d", w.Code)
					}
					removeFailure()
				}
				if w := send(completion); w.Code != http.StatusOK {
					t.Fatalf("reconcile completion: %d %s", w.Code, w.Body.String())
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus, wantGrants := "active", 1
			if order == "newest_terminal_first" {
				wantStatus, wantGrants = "canceled", 0
			}
			if derefString(account.StripeSubscriptionID) != subID || derefString(account.StripeSubscriptionStatus) != wantStatus || account.CheckoutInitializingAt.Valid {
				t.Fatalf("wrong reconciled account: %+v", account)
			}
			if len(stripe.externalGrants) != wantGrants {
				t.Fatalf("external grants=%d want %d", len(stripe.externalGrants), wantGrants)
			}
			for _, id := range []string{eventID, completeID} {
				event, err := testQueries.GetStripeWebhookEvent(ctx, id)
				if err != nil || !event.ProcessedAt.Valid {
					t.Fatalf("event %s not processed: %v", id, err)
				}
			}
			if wantStatus == "active" {
				if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
					t.Fatalf("activation allowed another checkout: %d", w.Code)
				}
			}
		})
	}
}

func TestIntegration_FailedCheckoutReleasesLeaseAndActorAtomically(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		name := "successful_cleanup"
		if failCleanup {
			name = "failed_cleanup"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			teamID, firstKey, firstActor := seedTeamAndKeyWithRole(t, "team_owner")
			secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
			stripe := &fakeStripeClient{nextCustomerID: "cus_" + teamID.String(), checkoutErr: errors.New("Stripe returned 400")}
			router := newBillingRouter(t, stripe)
			if failCleanup {
				_, err := testPool.Exec(ctx, `CREATE FUNCTION fail_checkout_actor_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF OLD.stripe_checkout_actor_id IS NOT NULL AND NEW.stripe_checkout_actor_id IS NULL THEN
				RAISE EXCEPTION 'injected actor cleanup failure'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER fail_checkout_actor_cleanup BEFORE UPDATE ON team_billing_account
				FOR EACH ROW EXECUTE FUNCTION fail_checkout_actor_cleanup();`)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = testPool.Exec(ctx, `DROP TRIGGER IF EXISTS fail_checkout_actor_cleanup ON team_billing_account; DROP FUNCTION IF EXISTS fail_checkout_actor_cleanup();`)
				})
			}
			if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusBadGateway {
				t.Fatalf("failed checkout: %d %s", w.Code, w.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if account.CheckoutInitializingAt.Valid != failCleanup || account.StripeCheckoutActorID.Valid != failCleanup {
				t.Fatalf("partial cleanup: lease=%v actor=%v", account.CheckoutInitializingAt.Valid, account.StripeCheckoutActorID.Valid)
			}
			oldLease := account.CheckoutInitializingAt
			stripe.checkoutErr = nil
			if failCleanup {
				if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusConflict {
					t.Fatalf("failed cleanup allowed another checkout: %d", w.Code)
				}
				if _, err := testPool.Exec(ctx, `DROP TRIGGER fail_checkout_actor_cleanup ON team_billing_account; DROP FUNCTION fail_checkout_actor_cleanup();`); err != nil {
					t.Fatal(err)
				}
				if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: teamID, LeaseStartedAt: oldLease}); err != nil {
					t.Fatal(err)
				}
			}
			if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("second checkout: %d %s", w.Code, w.Body.String())
			}
			if got := stripe.checkoutCalls[1].Metadata["activation_user_id"]; got == firstActor.String() {
				t.Fatal("successful checkout inherited failed actor")
			}
			if failCleanup {
				if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: teamID, LeaseStartedAt: oldLease}); err != nil {
					t.Fatal(err)
				}
				account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil {
					t.Fatal(err)
				}
				if !account.CheckoutInitializingAt.Valid || !account.StripeCheckoutActorID.Valid {
					t.Fatal("late cleanup cleared newer checkout generation")
				}
			}
		})
	}
}

func TestIntegration_StripeTimestampOnlyRedemptionContinuesBilling(t *testing.T) {
	ctx := context.Background()
	teamID, _, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	grantedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_activation_credit_granted_at)
		VALUES($1,$2,$3)`, teamID, "cus_"+teamID.String(), grantedAt); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	if w := sendStripeActivationWebhook(t, router, "evt_timestamp_marker_"+teamID.String(), teamID, actorID, time.Now().UTC()); w.Code != http.StatusOK {
		t.Fatalf("historical redemption blocked billing: %d %s", w.Code, w.Body.String())
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	if derefString(account.StripeSubscriptionStatus) != "active" || !account.TrialEndedAt.Valid {
		t.Fatalf("billing activation incomplete: %+v", account)
	}
	if len(stripe.creditGrantCalls) != 0 || !account.StripeActivationCreditGrantedAt.Time.Equal(grantedAt) {
		t.Fatal("historical redemption granted another credit or changed its marker")
	}
}
