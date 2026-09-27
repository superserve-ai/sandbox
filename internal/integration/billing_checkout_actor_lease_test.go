//go:build integration

package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func enableBillingExportForCheckoutActorTest(t *testing.T, teamID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_export_enabled', true)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = EXCLUDED.enabled
	`, teamID); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_CheckoutLeaseRefreshesActorOnNewGeneration(t *testing.T) {
	ctx := context.Background()
	teamID, firstKey, firstUserID := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	stripe := &fakeStripeClient{nextCustomerID: "cus_" + teamID.String()}
	router := newBillingRouter(t, stripe)

	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != 200 {
		t.Fatalf("first checkout: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := stripe.checkoutCalls[0].Metadata["activation_user_id"]; got != firstUserID.String() {
		t.Fatalf("first checkout actor = %q, want %q", got, firstUserID)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE team_billing_account
		SET checkout_initializing_at = now() - interval '25 hours',
		    stripe_checkout_actor_claimed_at = now() - interval '1 hour'
		WHERE team_id = $1`, teamID); err != nil {
		t.Fatal(err)
	}
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != 409 {
		t.Fatalf("unresolved old checkout: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if len(stripe.checkoutCalls) != 1 {
		t.Fatalf("checkout calls before expiration = %d, want 1", len(stripe.checkoutCalls))
	}
	now := time.Now().UTC().Truncate(time.Second)
	payload := checkoutExpiryWebhookPayload(t, "evt_actor_expiry_"+teamID.String(), "checkout.session.expired", "cs_test_123", teamID.String(), stripe.nextCustomerID, "", now)
	req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
	if w := doRequest(router, req); w.Code != 200 {
		t.Fatalf("matching checkout expiration: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != 200 {
		t.Fatalf("new checkout generation: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := stripe.checkoutCalls[1].Metadata["activation_user_id"]; got == firstUserID.String() || got == "" {
		t.Fatalf("new checkout generation reused old actor: %q", got)
	}
}

func TestIntegration_CheckoutLeaseBlocksLiveGeneration(t *testing.T) {
	teamID, firstKey, _ := seedTeamAndKeyWithRole(t, "team_owner")
	secondKey := seedKeyForExistingTeamWithRole(t, teamID, "team_owner")
	enableBillingExportForCheckoutActorTest(t, teamID)
	stripe := &fakeStripeClient{nextCustomerID: "cus_" + teamID.String()}
	router := newBillingRouter(t, stripe)

	if w := do(router, "POST", "/stripe/checkout-session", firstKey, checkoutRegressionBody); w.Code != 200 {
		t.Fatalf("first checkout: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(router, "POST", "/stripe/checkout-session", secondKey, checkoutRegressionBody); w.Code != 409 {
		t.Fatalf("live checkout retry: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if len(stripe.checkoutCalls) != 1 {
		t.Fatalf("checkout calls = %d, want 1", len(stripe.checkoutCalls))
	}
}
