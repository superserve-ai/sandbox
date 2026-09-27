//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
)

func TestIntegration_UnassociatedSubscriptionCannotClaimOpenCheckout(t *testing.T) {
	for _, existing := range []string{"first_subscription", "canceled_subscription"} {
		for _, eventType := range []string{"customer.subscription.updated", "customer.subscription.resumed", "customer.subscription.deleted"} {
			for _, generation := range []string{"missing_generation", "wrong_generation"} {
				t.Run(existing+"/"+eventType+"/"+generation, func(t *testing.T) {
					ctx := context.Background()
					teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
					customerID := "cus_" + teamID.String()
					if existing == "canceled_subscription" {
						if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
							(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,stripe_subscription_event_at)
							VALUES($1,$2,$3,'canceled',now()-interval '1 day')`, teamID, customerID, "sub_previous_"+teamID.String()); err != nil {
							t.Fatal(err)
						}
					}
					stripe := &fakeStripeClient{nextCustomerID: customerID}
					router := newBillingRouter(t, stripe)
					if w := do(router, http.MethodPost, "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
						t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
					}
					before, err := testQueries.GetTeamBillingAccount(ctx, teamID)
					if err != nil {
						t.Fatal(err)
					}
					if !before.CheckoutInitializingAt.Valid || !before.StripeCheckoutActorID.Valid || before.CheckoutSubscriptionID != nil {
						t.Fatalf("checkout did not establish an unassociated generation: %+v", before)
					}
					if got := stripe.checkoutCalls[0].Metadata["checkout_generation"]; got != before.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano) {
						t.Fatalf("checkout generation = %q, want persisted generation", got)
					}
					metadata := map[string]string{"activation_user_id": actorID.String()}
					if generation == "wrong_generation" {
						metadata["checkout_generation"] = before.CheckoutInitializingAt.Time.UTC().Add(-time.Second).Format(time.RFC3339Nano)
					}
					status := "active"
					if eventType == "customer.subscription.deleted" {
						status = "canceled"
					}
					now := time.Now().UTC().Truncate(time.Second)
					eventID := "evt_unrelated_" + teamID.String()
					payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, eventType, "sub_unrelated_"+teamID.String(), customerID, status, now, now, now.AddDate(0, 1, 0), metadata)
					for attempt := 0; attempt < 2; attempt++ {
						req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
						if w := doRequest(router, req); w.Code != http.StatusOK {
							t.Fatalf("unrelated lifecycle delivery %d: %d %s", attempt, w.Code, w.Body.String())
						}
					}
					after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, after) {
						t.Errorf("unrelated subscription changed checkout or billing state: before=%+v after=%+v", before, after)
					}
					if len(stripe.creditGrantCalls) != 0 {
						t.Errorf("unrelated subscription issued %d promotion grants", len(stripe.creditGrantCalls))
					}
					var reservedOrRedeemed bool
					if err := testPool.QueryRow(ctx, `SELECT EXISTS (
						SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1
						AND (stripe_redemption_reserved_at IS NOT NULL OR stripe_redemption_at IS NOT NULL)
					)`, actorID).Scan(&reservedOrRedeemed); err != nil {
						t.Fatal(err)
					}
					if reservedOrRedeemed {
						t.Error("unrelated subscription reserved or redeemed the checkout actor's promotion")
					}
				})
			}
		}
	}
}

func TestIntegration_SubscriptionWithCheckoutGenerationCanActivate(t *testing.T) {
	for _, eventType := range []string{"customer.subscription.updated", "customer.subscription.resumed"} {
		t.Run(eventType, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, actorID := seedTeamAndKeyWithRole(t, "team_owner")
			customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
			stripe := &fakeStripeClient{nextCustomerID: customerID}
			router := newBillingRouter(t, stripe)
			if w := do(router, http.MethodPost, "/stripe/checkout-session", key, checkoutRegressionBody); w.Code != http.StatusOK {
				t.Fatalf("checkout: %d %s", w.Code, w.Body.String())
			}
			generation := stripe.checkoutCalls[0].Metadata["checkout_generation"]
			if generation == "" {
				t.Fatal("checkout metadata omitted its generation")
			}
			now := time.Now().UTC().Truncate(time.Second)
			payload := stripeSubscriptionWebhookPayloadWithMetadata(t, "evt_matching_"+teamID.String(), eventType, subscriptionID, customerID, "active", now, now, now.AddDate(0, 1, 0), map[string]string{
				"activation_user_id":  actorID.String(),
				"checkout_generation": generation,
			})
			for attempt := 0; attempt < 2; attempt++ {
				req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("matching lifecycle delivery %d: %d %s", attempt, w.Code, w.Body.String())
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if derefString(account.StripeSubscriptionID) != subscriptionID || derefString(account.StripeSubscriptionStatus) != "active" || !account.TrialEndedAt.Valid || !account.StripeActivationCreditGrantedAt.Valid {
				t.Fatalf("matching checkout generation did not activate billing: %+v", account)
			}
			if len(stripe.creditGrantCalls) != 1 || stripe.creditGrantCalls[0].AmountCents != 9500 {
				t.Fatalf("matching generation grants = %+v, want one $95 grant", stripe.creditGrantCalls)
			}
		})
	}
}

type rejectedPromotionReplayClient struct {
	*ambiguousPromotionClient
	replayErr error
}

func (s *rejectedPromotionReplayClient) CreateBillingCreditGrant(ctx context.Context, params api.StripeCreateBillingCreditGrantParams) (api.StripeBillingCreditGrant, error) {
	if len(s.creditGrantCalls) == 1 {
		s.creditGrantCalls = append(s.creditGrantCalls, params)
		return api.StripeBillingCreditGrant{}, s.replayErr
	}
	return s.ambiguousPromotionClient.CreateBillingCreditGrant(ctx, params)
}

func TestIntegration_AmbiguousPromotionThenRejectedReplayPreservesFence(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusConflict, http.StatusTooManyRequests} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ctx := context.Background()
			teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
				VALUES($1,$2,$3,'incomplete')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			stripe := &rejectedPromotionReplayClient{
				ambiguousPromotionClient: &ambiguousPromotionClient{fakeStripeClient: &fakeStripeClient{}, t: t, userID: userID, teamID: teamID, accepted: make(map[string]string)},
				replayErr:                fmt.Errorf("Stripe returned %d: retry rejected", status),
			}
			router := newBillingRouter(t, stripe)
			now := time.Now().UTC().Truncate(time.Second)
			eventID := "evt_ambiguous_replay_" + teamID.String()
			assertFence := func() {
				t.Helper()
				var fenced bool
				if err := testPool.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM user_promotion_entitlement u JOIN team_billing_account a
					ON a.team_id=u.stripe_redemption_reserved_team_id
					WHERE u.user_id=$1 AND a.team_id=$2 AND u.stripe_redemption_reserved_at IS NOT NULL
					AND u.stripe_redemption_attempted_at IS NOT NULL AND u.stripe_redemption_at IS NULL
					AND a.stripe_activation_user_id=$1 AND a.stripe_activation_credit_reserved_at IS NOT NULL
					AND a.stripe_activation_credit_reservation_event_id=$3 AND a.stripe_activation_credit_grant_id IS NULL
				)`, userID, teamID, eventID).Scan(&fenced); err != nil {
					t.Fatal(err)
				}
				if !fenced {
					t.Error("accepted but unconfirmed promotion lost its durable user or team fence")
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
					t.Fatalf("unconfirmed grant delivery %d: %d %s", attempt, w.Code, w.Body.String())
				}
				assertFence()
			}
			if len(stripe.accepted) != 1 || len(stripe.creditGrantCalls) != 2 {
				t.Fatalf("ambiguous retry: accepted=%d calls=%d", len(stripe.accepted), len(stripe.creditGrantCalls))
			}
			otherTeam, _, _ := seedTeamAndKeyWithRole(t, "team_owner")
			if _, err := testPool.Exec(ctx, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, otherTeam, userID); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO user_role_assignments(team_id,user_id,role_id,scope_type)
				SELECT $1,$2,id,'team' FROM roles WHERE name='team_owner'`, otherTeam, userID); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account
				(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
				VALUES($1,$2,$3,'incomplete')`, otherTeam, "cus_"+otherTeam.String(), "sub_"+otherTeam.String()); err != nil {
				t.Fatal(err)
			}
			otherStripe := &fakeStripeClient{}
			otherRouter := newBillingRouter(t, otherStripe)
			otherEventID := "evt_other_promotion_" + otherTeam.String()
			if w := sendStripeActivationWebhook(t, otherRouter, otherEventID, otherTeam, userID, now); w.Code != http.StatusInternalServerError {
				t.Errorf("competing team activation: %d %s", w.Code, w.Body.String())
			}
			if len(otherStripe.creditGrantCalls) != 0 {
				t.Errorf("same user received %d additional grants on another team", len(otherStripe.creditGrantCalls))
			}
			assertFence()
			for attempt := 0; attempt < 2; attempt++ {
				if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusOK {
					t.Fatalf("reconciled grant delivery %d: %d %s", attempt, w.Code, w.Body.String())
				}
			}
			if len(stripe.accepted) != 1 || len(stripe.creditGrantCalls) != 3 {
				t.Fatalf("reconciled grant: accepted=%d calls=%d", len(stripe.accepted), len(stripe.creditGrantCalls))
			}
			for _, call := range stripe.creditGrantCalls {
				if call.AmountCents != 9500 || call.IdempotencyKey != stripe.creditGrantCalls[0].IdempotencyKey {
					t.Errorf("retry changed promotion amount or idempotency key: %+v", call)
				}
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if !account.StripeActivationCreditGrantedAt.Valid || account.StripeActivationCreditReservedAt.Valid || derefString(account.StripeActivationCreditGrantID) != "credit_"+teamID.String() {
				t.Fatalf("original grant was not reconciled: %+v", account)
			}
			if w := sendStripeActivationWebhook(t, otherRouter, otherEventID, otherTeam, userID, now); w.Code != http.StatusOK {
				t.Fatalf("other team activation after reconciliation: %d %s", w.Code, w.Body.String())
			}
			if len(otherStripe.creditGrantCalls) != 0 {
				t.Errorf("reconciled user received %d additional grants on another team", len(otherStripe.creditGrantCalls))
			}
		})
	}
}
