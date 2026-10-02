//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_CanonicalStripeInactiveCheckoutRetainsActivationEvidence(t *testing.T) {
	for _, status := range []string{"past_due", "unpaid", "paused"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
			email := "original" + uuid.NewString()[:8] + "@gmail.com"
			if _, err := testPool.Exec(ctx, `SELECT * FROM upsert_profile_with_promotion_identity($1,$2,true,clock_timestamp(),clock_timestamp())`, actorID, email); err != nil {
				t.Fatal(err)
			}
			enableBillingExportForCheckoutActorTest(t, teamID)
			stripe := &fakeStripeClient{nextCustomerID: "cus_" + teamID.String()}
			router := newBillingRouter(t, stripe)
			if w := do(router, "POST", "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("create Checkout: %d %s", w.Code, w.Body.String())
			}
			var pin uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT stripe_checkout_identity_evidence_version FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&pin); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			eventID := "evt_pin_complete_" + teamID.String()
			subscriptionID := "sub_" + teamID.String()
			completion := strings.ReplaceAll(string(stripeCheckoutWebhookPayload(t, eventID, teamID.String(), stripe.nextCustomerID, subscriptionID, now)), "cs_"+eventID, "cs_test_123")
			send := func(payload []byte) {
				t.Helper()
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("webhook: %d %s", w.Code, w.Body.String())
				}
			}
			send([]byte(completion))
			send(stripeSubscriptionWebhookPayload(t, "evt_pin_inactive_"+teamID.String(), "customer.subscription.updated", subscriptionID, stripe.nextCustomerID, status, now.Add(time.Second), now, now.AddDate(0, 1, 0)))
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || account.CheckoutInitializingAt.Valid || account.CheckoutSessionID != nil || derefString(account.CheckoutSubscriptionID) != subscriptionID {
				t.Fatalf("closed replay lost subscription association: %+v %v", account, err)
			}
			if len(stripe.creditGrantCalls) != 0 {
				t.Fatal("non-active subscription granted promotion")
			}
			if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, actorID); err != nil {
				t.Fatal(err)
			}
			otherActor := canonicalStripeActor(t, uuid.NewString()+"@example.com", true)
			if w := sendStripeActivationWebhook(t, router, "evt_pin_active_"+teamID.String(), teamID, otherActor, now.Add(2*time.Second)); w.Code != http.StatusOK {
				t.Fatalf("later activation: %d %s", w.Code, w.Body.String())
			}
			if len(stripe.creditGrantCalls) != 1 {
				t.Fatalf("later activation grants=%d, want one", len(stripe.creditGrantCalls))
			}
			var original bool
			if err := testPool.QueryRow(ctx, `SELECT stripe_activation_user_id=$2 AND stripe_activation_identity_evidence_version=$3
				AND stripe_activation_identity_key=promotion_identity_key($2,$4,true) FROM team_billing_account WHERE team_id=$1`, teamID, actorID, pin, email).Scan(&original); err != nil || !original {
				t.Fatalf("later activation replaced original actor/evidence: %v %v", original, err)
			}
			var otherConsumed bool
			if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_at IS NOT NULL)`, otherActor).Scan(&otherConsumed); err != nil || otherConsumed {
				t.Fatalf("metadata actor consumed: %v %v", otherConsumed, err)
			}
		})
	}
}
