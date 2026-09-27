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

func TestIntegration_ExpiredAmbiguousStripePromotionRetainsFence(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "active"
		if stale {
			name = "stale after cancellation"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
				VALUES($1,$2,$3,'incomplete')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			stripe := &ambiguousPromotionClient{fakeStripeClient: &fakeStripeClient{}, t: t, userID: userID, teamID: teamID, accepted: make(map[string]string)}
			router := newBillingRouter(t, stripe)
			now := time.Now().UTC().Truncate(time.Second)
			eventID := "evt_expired_attempt_" + teamID.String()
			if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
				t.Fatalf("ambiguous first attempt: %d %s", w.Code, w.Body.String())
			}
			if len(stripe.creditGrantCalls) != 1 || len(stripe.accepted) != 1 {
				t.Fatalf("first provider attempt: calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
			}
			attemptedAt := now.Add(-25 * time.Hour)
			if _, err := testPool.Exec(ctx, `UPDATE user_promotion_entitlement SET stripe_redemption_attempted_at=$2 WHERE user_id=$1`, userID, attemptedAt); err != nil {
				t.Fatal(err)
			}
			var identityKey, evidenceVersion string
			if err := testPool.QueryRow(ctx, `SELECT stripe_activation_identity_key,stripe_activation_identity_evidence_version::text
				FROM team_billing_account WHERE team_id=$1`, teamID).Scan(&identityKey, &evidenceVersion); err != nil {
				t.Fatal(err)
			}
			// The provider no longer remembers the accepted request. Any new call
			// would issue another credit instead of replaying the original result.
			clear(stripe.accepted)
			if stale {
				payload := stripeSubscriptionWebhookPayload(t, "evt_canceled_"+teamID.String(), "customer.subscription.deleted",
					"sub_"+teamID.String(), "cus_"+teamID.String(), "canceled", now.Add(time.Second), now, now.AddDate(0, 1, 0))
				req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("cancellation: %d %s", w.Code, w.Body.String())
				}
			}
			if _, err := testPool.Exec(ctx, `DELETE FROM promotion_identity_current WHERE user_id=$1`, userID); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
					t.Fatalf("expired attempt retry: %d %s", w.Code, w.Body.String())
				}
			}
			if len(stripe.creditGrantCalls) != 1 || len(stripe.accepted) != 0 {
				t.Fatalf("expired retry called provider: calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
			}
			var retained bool
			if err := testPool.QueryRow(ctx, `SELECT
				u.stripe_redemption_reserved_team_id=$1 AND u.stripe_redemption_at IS NULL
				AND u.stripe_redemption_attempted_at=$4
				AND a.stripe_activation_user_id=$2 AND a.stripe_activation_credit_reserved_at IS NOT NULL
				AND a.stripe_activation_credit_reservation_event_id=$3
				AND a.stripe_activation_identity_key=$5 AND a.stripe_activation_identity_evidence_version::text=$6
				AND a.stripe_activation_credit_granted_at IS NULL AND a.stripe_activation_credit_grant_id IS NULL
				AND i.stripe_reserved_team_id=$1 AND i.stripe_reserved_user_id=$2 AND i.stripe_redemption_at IS NULL
				AND e.processed_at IS NULL
				FROM user_promotion_entitlement u
				JOIN team_billing_account a ON a.team_id=u.stripe_redemption_reserved_team_id
				JOIN promotion_identity i ON i.identity_key=a.stripe_activation_identity_key
				JOIN stripe_webhook_event e ON e.event_id=$3
				WHERE u.user_id=$2`, teamID, userID, eventID, attemptedAt, identityKey, evidenceVersion).Scan(&retained); err != nil || !retained {
				t.Fatalf("expired attempt lost durable identity, event or consumption fence: retained=%t err=%v", retained, err)
			}
			if state := canonicalStripeReserve(t, teamID, userID, "evt_newer_"+teamID.String()); state != "blocked" {
				t.Fatalf("later event took ownership of expired ambiguous attempt: %s", state)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO promotion_identity_current(user_id,evidence_version) VALUES($1,$2::uuid)`, userID, evidenceVersion); err != nil {
				t.Fatal(err)
			}
			otherTeam := canonicalStripeTeam(t)
			if state := canonicalStripeReserve(t, otherTeam, userID, "evt_other_team_"+uuid.NewString()); state != "blocked" {
				t.Fatalf("expired ambiguous actor can obtain a new reservation elsewhere: %s", state)
			}
		})
	}
}

func TestIntegration_OldUnattemptedStripePromotionCanStartAndRetry(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
		VALUES($1,$2,$3,'incomplete')`, teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	eventID := "evt_unattempted_old_" + teamID.String()
	if state := canonicalStripeReserve(t, teamID, userID, eventID); state != "acquired" {
		t.Fatalf("initial reserve: %s", state)
	}
	if _, err := testPool.Exec(ctx, `UPDATE user_promotion_entitlement SET stripe_redemption_reserved_at=now()-interval '2 days' WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_activation_credit_reserved_at=now()-interval '2 days' WHERE team_id=$1`, teamID); err != nil {
		t.Fatal(err)
	}
	stripe := &ambiguousPromotionClient{fakeStripeClient: &fakeStripeClient{}, t: t, userID: userID, teamID: teamID, accepted: make(map[string]string)}
	router := newBillingRouter(t, stripe)
	now := time.Now().UTC().Truncate(time.Second)
	if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusInternalServerError {
		t.Fatalf("initial ambiguous grant: %d %s", w.Code, w.Body.String())
	}
	var recentAttempt bool
	if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_attempted_at >= $2 FROM user_promotion_entitlement WHERE user_id=$1`, userID, now).Scan(&recentAttempt); err != nil || !recentAttempt {
		t.Fatalf("old reservation did not establish a fresh first-attempt timestamp: %t %v", recentAttempt, err)
	}
	if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, now); w.Code != http.StatusOK {
		t.Fatalf("fresh idempotent retry: %d %s", w.Code, w.Body.String())
	}
	if len(stripe.creditGrantCalls) != 2 || len(stripe.accepted) != 1 {
		t.Fatalf("fresh retry calls=%d accepted=%d", len(stripe.creditGrantCalls), len(stripe.accepted))
	}
	var redeemed bool
	if err := testPool.QueryRow(ctx, `SELECT u.stripe_redemption_at IS NOT NULL AND u.stripe_redemption_reserved_team_id IS NULL
		AND a.stripe_activation_credit_granted_at IS NOT NULL AND a.stripe_activation_credit_reserved_at IS NULL
		AND i.stripe_redemption_at IS NOT NULL AND i.stripe_reserved_team_id IS NULL
		FROM user_promotion_entitlement u JOIN team_billing_account a ON a.team_id=$1
		JOIN promotion_identity i ON i.identity_key=a.stripe_activation_identity_key WHERE u.user_id=$2`, teamID, userID).Scan(&redeemed); err != nil || !redeemed {
		t.Fatalf("successful retry did not finalize each fence: %t %v", redeemed, err)
	}
}
