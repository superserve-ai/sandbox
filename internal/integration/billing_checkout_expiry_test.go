//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

type expiringCheckoutStripeClient struct {
	*fakeStripeClient
}

func (s *expiringCheckoutStripeClient) CreateCheckoutSession(ctx context.Context, params api.StripeCreateCheckoutSessionParams) (api.StripeCheckoutSession, error) {
	session, err := s.fakeStripeClient.CreateCheckoutSession(ctx, params)
	if err != nil {
		return session, err
	}
	s.mu.Lock()
	session.ID = "cs_expiry_" + strconv.Itoa(len(s.checkoutCalls))
	s.mu.Unlock()
	return session, nil
}

func checkoutExpiryWebhookPayload(t *testing.T, eventID, eventType, sessionID, teamID, customerID, subscriptionID string, created time.Time) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": eventType, "created": created.Unix(),
		"data": map[string]any{"object": map[string]any{
			"id": sessionID, "client_reference_id": teamID,
			"customer": customerID, "subscription": subscriptionID,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestIntegration_CheckoutExpirationReleasesOnlyMatchingLease(t *testing.T) {
	ctx := context.Background()
	teamID, firstKey, firstActor := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &expiringCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_expiry_" + teamID.String()}}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("first checkout: %d %s", w.Code, w.Body.String())
	}
	first, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	send := func(eventID, sessionID, customerID string) {
		t.Helper()
		payload := checkoutExpiryWebhookPayload(t, eventID+teamID.String(), "checkout.session.expired", sessionID, teamID.String(), customerID, "", now)
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
		if w := doRequest(router, req); w.Code != http.StatusOK {
			t.Fatalf("expiration: %d %s", w.Code, w.Body.String())
		}
	}
	for _, event := range []struct{ name, session, customer string }{
		{"missing_session", "", stripe.nextCustomerID},
		{"wrong_session", "cs_other", stripe.nextCustomerID},
		{"missing_customer", "cs_expiry_1", ""},
		{"wrong_customer", "cs_expiry_1", "cus_other"},
	} {
		send("evt_"+event.name, event.session, event.customer)
		account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
		if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutInitializingAt.Time.Equal(first.CheckoutInitializingAt.Time) || account.StripeCheckoutActorID != first.StripeCheckoutActorID {
			t.Fatalf("%s expiration changed checkout lease/actor: %+v %v", event.name, account, err)
		}
	}
	send("evt_matching", "cs_expiry_1", stripe.nextCustomerID)
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	if account.CheckoutInitializingAt.Valid || account.CheckoutSessionID != nil || account.CheckoutSubscriptionID != nil || account.StripeCheckoutActorID.Valid || account.StripeCheckoutActorClaimedAt.Valid {
		t.Fatalf("matching expiration retained checkout state: %+v", account)
	}
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("replacement checkout: %d %s", w.Code, w.Body.String())
	}
	second, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stripe.checkoutCalls[1].Metadata["activation_user_id"]; got == "" || got == firstActor.String() {
		t.Fatalf("replacement checkout retained expired actor: %q", got)
	}
	if stripe.checkoutCalls[0].IdempotencyKey == stripe.checkoutCalls[1].IdempotencyKey {
		t.Fatal("replacement checkout reused expired session idempotency generation")
	}
	send("evt_stale", "cs_expiry_1", stripe.nextCustomerID)
	account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutInitializingAt.Time.Equal(second.CheckoutInitializingAt.Time) || account.StripeCheckoutActorID != second.StripeCheckoutActorID || derefString(account.CheckoutSessionID) != "cs_expiry_2" {
		t.Fatalf("stale expiration changed replacement checkout: %+v %v", account, err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("stale expiration permitted duplicate checkout: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegration_CheckoutExpirationPreservesCompletedCheckout(t *testing.T) {
	for _, subscriptionID := range []string{"", "sub_completed"} {
		name := "without_subscription"
		if subscriptionID != "" {
			name = "with_subscription"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
			stripe := &expiringCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_completed_" + teamID.String()}}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
			}
			now := time.Now().UTC().Truncate(time.Second)
			for _, eventType := range []string{"checkout.session.completed", "checkout.session.expired"} {
				payload := checkoutExpiryWebhookPayload(t, "evt_"+eventType+teamID.String(), eventType, "cs_expiry_1", teamID.String(), stripe.nextCustomerID, subscriptionID, now)
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", eventType, w.Code, w.Body.String())
				}
				if eventType == "checkout.session.completed" {
					if _, err := testPool.Exec(ctx, `UPDATE team_billing_account
						SET checkout_initializing_at=now()-interval '2 days', checkout_completed_at=checkout_completed_at-interval '2 days'
						WHERE team_id=$1`, teamID); err != nil {
						t.Fatal(err)
					}
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutCompletedAt.Valid || derefString(account.CheckoutSessionID) != "cs_expiry_1" || !account.StripeCheckoutActorID.Valid || derefString(account.CheckoutSubscriptionID) != subscriptionID {
				t.Fatalf("expiration cleared completed checkout: %+v %v", account, err)
			}
			if err := testQueries.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: teamID, LeaseStartedAt: account.CheckoutInitializingAt}); err != nil {
				t.Fatal(err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusConflict {
				t.Fatalf("completed checkout permitted duplicate session: %d %s", w.Code, w.Body.String())
			}
			anchor := now.Add(-time.Hour)
			if _, err := testQueries.ClaimTeamCommercialBillingAnchor(ctx, db.ClaimTeamCommercialBillingAnchorParams{TeamID: teamID, Anchor: anchor}); err == nil || !strings.Contains(err.Error(), "checkout is initializing") {
				t.Fatalf("completed checkout allowed anchor cutover: %v", err)
			}
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET commercial_billing_anchor=$1 WHERE team_id<>$2 AND commercial_billing_anchor IS NULL`, anchor, teamID); err != nil {
				t.Fatal(err)
			}
			if _, err := testQueries.WithTx(tx).EstablishBillingCutover(ctx, db.EstablishBillingCutoverParams{Cutover: anchor}); err == nil || !strings.Contains(err.Error(), "checkout is initializing") {
				t.Fatalf("completed checkout allowed bulk cutover: %v", err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if subscriptionID != "" {
				payload := stripeSubscriptionWebhookPayload(t, "evt_delayed_activation_"+teamID.String(), "customer.subscription.created", subscriptionID, stripe.nextCustomerID, "active", now, now, now.AddDate(0, 1, 0))
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("delayed subscription activation: %d %s", w.Code, w.Body.String())
				}
				account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil || account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid {
					t.Fatalf("processed subscription retained checkout completion fence: %+v %v", account, err)
				}
			}
		})
	}
}

func TestIntegration_DelayedCheckoutCompletionKeepsUnresolvedLease(t *testing.T) {
	ctx := context.Background()
	teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	stripe := &expiringCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_delayed_" + teamID.String()}}
	router := newBillingRouter(t, stripe)
	if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
		t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account
		SET checkout_initializing_at=now()-interval '2 days', stripe_checkout_actor_claimed_at=now()-interval '2 days'
		WHERE team_id=$1`, teamID); err != nil {
		t.Fatal(err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != http.StatusConflict {
		t.Fatalf("delayed completion permitted replacement checkout: %d %s", w.Code, w.Body.String())
	}
	now := time.Now().UTC().Truncate(time.Second)
	cutover := now.Add(-time.Hour)
	if _, err := testQueries.ClaimTeamCommercialBillingAnchor(ctx, db.ClaimTeamCommercialBillingAnchorParams{TeamID: teamID, Anchor: cutover}); err == nil || !strings.Contains(err.Error(), "checkout is initializing") {
		t.Fatalf("delayed completion allowed anchor cutover: %v", err)
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET commercial_billing_anchor=$1 WHERE team_id<>$2 AND commercial_billing_anchor IS NULL`, cutover, teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.WithTx(tx).EstablishBillingCutover(ctx, db.EstablishBillingCutoverParams{Cutover: cutover}); err == nil || !strings.Contains(err.Error(), "checkout is initializing") {
		t.Fatalf("delayed completion allowed bulk cutover: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || !account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid || derefString(account.CheckoutSessionID) != "cs_expiry_1" || !account.StripeCheckoutActorID.Valid || account.StripeCheckoutActorID.Bytes != actorID || account.CommercialBillingAnchor.Valid {
		t.Fatalf("unresolved checkout lost its actor/session fence: %+v %v", account, err)
	}
	periodStart := now.Add(-47 * time.Hour)
	subscriptionID := "sub_delayed_" + teamID.String()
	for _, payload := range [][]byte{
		checkoutExpiryWebhookPayload(t, "evt_delayed_completion_"+teamID.String(), "checkout.session.completed", "cs_expiry_1", teamID.String(), stripe.nextCustomerID, subscriptionID, periodStart),
		stripeSubscriptionWebhookPayload(t, "evt_delayed_activation_"+teamID.String(), "customer.subscription.created", subscriptionID, stripe.nextCustomerID, "active", periodStart, periodStart, periodStart.AddDate(0, 1, 0)),
	} {
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
		if w := doRequest(router, req); w.Code != http.StatusOK {
			t.Fatalf("delayed checkout webhook: %d %s", w.Code, w.Body.String())
		}
	}
	account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
	if err != nil || account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid || derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != "active" || !account.StripeActivationUserID.Valid || account.StripeActivationUserID.Bytes != actorID || !account.CommercialBillingAnchor.Valid || !account.CommercialBillingAnchor.Time.Equal(periodStart) {
		t.Fatalf("delayed activation lost original association, actor, or anchor: %+v %v", account, err)
	}
	if len(stripe.checkoutCalls) != 1 || len(stripe.creditGrantCalls) != 1 {
		t.Fatalf("checkout/grant calls = %d/%d, want 1/1", len(stripe.checkoutCalls), len(stripe.creditGrantCalls))
	}
}

func TestIntegration_ExpiredCheckoutLeaseRemainsReclaimable(t *testing.T) {
	for _, operation := range []string{"checkout", "anchor", "bulk"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
			stripe := &expiringCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_abandoned_" + teamID.String()}}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
			}
			if _, err := testPool.Exec(ctx, `UPDATE team_billing_account
				SET checkout_initializing_at=now()-interval '2 days', stripe_checkout_actor_claimed_at=now()-interval '2 days'
				WHERE team_id=$1`, teamID); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			payload := checkoutExpiryWebhookPayload(t, "evt_abandoned_expiry_"+teamID.String(), "checkout.session.expired", "cs_expiry_1", teamID.String(), stripe.nextCustomerID, "", now.Add(-time.Hour))
			req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
			if w := doRequest(router, req); w.Code != http.StatusOK {
				t.Fatalf("matching expiration: %d %s", w.Code, w.Body.String())
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || account.CheckoutInitializingAt.Valid || account.CheckoutSessionID != nil || account.StripeCheckoutActorID.Valid {
				t.Fatalf("expiration retained checkout fence: %+v %v", account, err)
			}
			anchor := now.Add(-time.Hour)
			switch operation {
			case "checkout":
				if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
					t.Fatalf("abandoned checkout remained fenced: %d %s", w.Code, w.Body.String())
				}
			case "anchor":
				if _, err := testQueries.ClaimTeamCommercialBillingAnchor(ctx, db.ClaimTeamCommercialBillingAnchorParams{TeamID: teamID, Anchor: anchor}); err != nil {
					t.Fatalf("abandoned checkout blocked anchor: %v", err)
				}
			case "bulk":
				tx, err := testPool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err := tx.Exec(ctx, `UPDATE team_billing_account SET commercial_billing_anchor=$1 WHERE team_id<>$2 AND commercial_billing_anchor IS NULL`, anchor, teamID); err != nil {
					t.Fatal(err)
				}
				if _, err := testQueries.WithTx(tx).EstablishBillingCutover(ctx, db.EstablishBillingCutoverParams{Cutover: anchor}); err != nil {
					t.Fatalf("abandoned checkout blocked bulk cutover: %v", err)
				}
				account, err := testQueries.WithTx(tx).GetTeamBillingAccount(ctx, teamID)
				if err != nil || account.CheckoutInitializingAt.Valid || !account.CommercialBillingAnchor.Time.Equal(anchor) {
					t.Fatalf("bulk cutover did not reclaim abandoned checkout: %+v %v", account, err)
				}
			}
		})
	}
}

func TestIntegration_CheckoutWithoutSubscriptionFinishesOnAcceptedLifecycle(t *testing.T) {
	for _, activationType := range []string{"customer.subscription.updated", "customer.subscription.resumed"} {
		t.Run(activationType, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, _ := seedTeamAndKeyWithRole(t, "team_owner")
			stripe := &expiringCheckoutStripeClient{fakeStripeClient: &fakeStripeClient{nextCustomerID: "cus_recovery_" + teamID.String()}}
			router := newBillingRouter(t, stripe)
			previousSubID, subscriptionID := "sub_previous_"+teamID.String(), "sub_current_"+teamID.String()
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
				VALUES($1,$2,$3,'canceled',now()-interval '3 days')`, teamID, stripe.nextCustomerID, previousSubID); err != nil {
				t.Fatal(err)
			}
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
			}
			now := time.Now().UTC().Truncate(time.Second)
			send := func(payload []byte) {
				t.Helper()
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("webhook: %d %s", w.Code, w.Body.String())
				}
			}
			send(checkoutExpiryWebhookPayload(t, "evt_complete_"+teamID.String(), "checkout.session.completed", "cs_expiry_1", teamID.String(), stripe.nextCustomerID, "", now))
			send(stripeSubscriptionWebhookPayload(t, "evt_previous_cancel_"+teamID.String(), "customer.subscription.deleted", previousSubID, stripe.nextCustomerID, "canceled", now, now, now.AddDate(0, 1, 0)))
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || !account.CheckoutInitializingAt.Valid || !account.CheckoutCompletedAt.Valid || account.CheckoutSubscriptionID != nil {
				t.Fatalf("previous subscription claimed completed checkout: %+v %v", account, err)
			}
			send(stripeInvoiceWebhookPayload(t, "evt_replacement_invoice_"+teamID.String(), "invoice.payment_succeeded", stripe.nextCustomerID, subscriptionID, "paid", now))
			account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || derefString(account.StripeSubscriptionID) != previousSubID || account.CheckoutSubscriptionID != nil {
				t.Fatalf("invoice replaced lifecycle association: %+v %v", account, err)
			}
			send(stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_new_activation_"+teamID.String(), activationType, subscriptionID, stripe.nextCustomerID, "active", now.Add(time.Second), now, now.AddDate(0, 1, 0), stripe.checkoutCalls[0].Metadata))
			account, err = testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid || derefString(account.CheckoutSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != "active" {
				t.Fatalf("accepted lifecycle did not close the lease while retaining its subscription association: %+v %v", account, err)
			}
			send(stripeSubscriptionWebhookPayload(t, "evt_new_cancel_"+teamID.String(), "customer.subscription.deleted", subscriptionID, stripe.nextCustomerID, "canceled", now.Add(2*time.Second), now, now.AddDate(0, 1, 0)))
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("canceled subscription could not restart checkout: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
