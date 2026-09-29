//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type activationRevocationStripe struct {
	mu                                       sync.Mutex
	teamID                                   uuid.UUID
	customer, grantID                        string
	voided, failVoid, ambiguous, failBalance bool
	expires                                  *int64
	balance                                  int64
	creates, voids, expiresCount             int
}

func (s *activationRevocationStripe) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	grant := func() map[string]any {
		g := map[string]any{"id": s.grantID, "customer": s.customer, "category": "promotional",
			"amount":               map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": 9500}},
			"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
			"metadata":             map[string]string{"activation_identity": "stripe-activation-credit-" + s.teamID.String()}, "expires_at": s.expires}
		if s.voided {
			g["voided_at"] = time.Now().Unix()
		}
		return g
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/billing/credit_grants":
		s.creates++
		_ = json.NewEncoder(w).Encode(grant())
	case r.Method == "GET" && r.URL.Path == "/v1/billing/credit_grants":
		if r.URL.Query().Get("customer") != s.customer {
			t.Error("grant discovery missing customer filter")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{grant()}, "has_more": false})
	case r.Method == "GET" && r.URL.Path == "/v1/billing/credit_grants/"+s.grantID:
		_ = json.NewEncoder(w).Encode(grant())
	case r.Method == "POST" && r.URL.Path == "/v1/billing/credit_grants/"+s.grantID+"/void":
		s.voids++
		if s.failVoid {
			http.Error(w, "temporary Stripe failure", 503)
			return
		}
		s.voided = true
		if s.ambiguous {
			http.Error(w, "response lost after void", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(grant())
	case r.Method == "POST" && r.URL.Path == "/v1/billing/credit_grants/"+s.grantID+"/expire":
		s.expiresCount++
		stamp := time.Now().Unix()
		s.expires = &stamp
		_ = json.NewEncoder(w).Encode(grant())
	case r.Method == "GET" && r.URL.Path == "/v1/billing/credit_balance_summary":
		if s.failBalance {
			http.Error(w, "Stripe read unavailable", 503)
			return
		}
		available := s.balance
		if s.voided || s.expires != nil && *s.expires <= time.Now().Unix() {
			available = 0
		}
		if r.URL.Query().Get("filter[type]") == "credit_grant" {
			if r.URL.Query().Get("filter[credit_grant]") != s.grantID {
				t.Error("read unrelated grant")
			}
		} else {
			// A separate manual grant remains spendable after revocation.
			available += 2500
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"customer": s.customer, "balances": []any{map[string]any{
			"available_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": available}},
			"ledger_balance":    map[string]any{"monetary": map[string]any{"currency": "usd", "value": available}},
		}}})
	default:
		t.Errorf("unexpected Stripe call (including unrelated grant mutation): %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func TestIntegration_StripeActivationCreditRevocation(t *testing.T) {
	for _, scenario := range []string{"scheduled", "legacy_missing_id", "terminal", "deleted", "stale", "previous_subscription", "unrelated_subscription", "same_second", "transient", "ambiguous", "consumed", "expired", "already_voided", "local_finalization_failure", "partial_reconciled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			teamID, key, userID := seedTeamAndKeyWithRole(t, "team_owner")
			customer, sub, grantID := "cus_"+teamID.String(), "sub_"+teamID.String(), "cred_"+teamID.String()
			at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, teamID, customer); err != nil {
				t.Fatal(err)
			}
			stripe := &activationRevocationStripe{teamID: teamID, customer: customer, grantID: grantID, balance: 9500}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stripe.serve(t, w, r) }))
			defer server.Close()
			client := api.NewStripeBillingClient(&config.Config{StripeSecretKey: "sk_test_example", StripeAPIVersion: "2025-06-30", StripeAPIBaseURL: server.URL})
			router := newBillingRouter(t, client)
			if w := sendStripeActivationWebhook(t, router, "evt_activate_"+teamID.String(), teamID, userID, at); w.Code != 200 {
				t.Fatalf("activate: %d %s", w.Code, w.Body.String())
			}
			before, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if derefString(before.StripeActivationCreditGrantID) != grantID {
				t.Fatalf("activation did not persist grant: %+v", before)
			}
			var redeemedAt time.Time
			if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_at FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_team_id=$2`, userID, teamID).Scan(&redeemedAt); err != nil {
				t.Fatal(err)
			}
			send := func(eventID, eventType, subscription, status string, scheduled bool, created time.Time) *httptest.ResponseRecorder {
				payload := stripeSubscriptionWebhookPayload(t, eventID, eventType, subscription, customer, status, created, at, at.AddDate(0, 1, 0))
				var event map[string]any
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Fatal(err)
				}
				event["data"].(map[string]any)["object"].(map[string]any)["cancel_at_period_end"] = scheduled
				payload, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
				return doRequest(router, req)
			}
			if scenario == "legacy_missing_id" {
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_activation_credit_grant_id=NULL,
					stripe_activation_credit_reserved_at=NULL, stripe_activation_credit_reservation_event_id=NULL WHERE team_id=$1`, teamID); err != nil {
					t.Fatal(err)
				}
			}
			eventType, status, scheduled := "customer.subscription.updated", "active", true
			canceledAt := at.Add(time.Second)
			if scenario == "terminal" {
				status, scheduled = "canceled", false
			}
			if scenario == "deleted" {
				eventType, status, scheduled = "customer.subscription.deleted", "canceled", false
			}
			if scenario == "same_second" {
				canceledAt = at
			}
			if scenario == "stale" {
				if w := send("evt_newer_"+teamID.String(), eventType, sub, "active", false, at.Add(5*time.Second)); w.Code != 200 {
					t.Fatalf("newer state: %d", w.Code)
				}
			}
			if scenario == "previous_subscription" {
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2,
                    stripe_subscription_event_at=$3 WHERE team_id=$1`, teamID, "sub_newer_"+teamID.String(), at.Add(5*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			stripe.mu.Lock()
			switch scenario {
			case "transient":
				stripe.failVoid = true
			case "partial_reconciled":
				stripe.balance = 5000
			case "ambiguous":
				stripe.ambiguous = true
			case "consumed":
				stripe.balance = 0
			case "expired":
				stamp := at.Unix()
				stripe.expires = &stamp
			case "already_voided":
				stripe.voided = true
			}
			stripe.mu.Unlock()
			removeFailure := func() {}
			if scenario == "local_finalization_failure" {
				if _, err := testPool.Exec(ctx, `CREATE FUNCTION fail_activation_revocation_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected completion failure'; END; $$;
                    CREATE TRIGGER fail_activation_revocation_completion BEFORE UPDATE ON stripe_activation_credit_revocation FOR EACH ROW EXECUTE FUNCTION fail_activation_revocation_completion();`); err != nil {
					t.Fatal(err)
				}
				removeFailure = func() {
					if _, err := testPool.Exec(ctx, `DROP TRIGGER IF EXISTS fail_activation_revocation_completion ON stripe_activation_credit_revocation; DROP FUNCTION IF EXISTS fail_activation_revocation_completion();`); err != nil {
						t.Error(err)
					}
				}
				t.Cleanup(removeFailure)
			}
			eventID := "evt_cancel_" + teamID.String()
			if scenario == "unrelated_subscription" {
				if w := send(eventID, eventType, "sub_unrelated_"+teamID.String(), status, scheduled, canceledAt); w.Code != 500 {
					t.Fatalf("unrelated cancellation: %d %s", w.Code, w.Body.String())
				}
				if _, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer); err == nil {
					t.Fatal("unrelated cancellation recorded revocation intent")
				}
				stripe.mu.Lock()
				voids := stripe.voids
				stripe.mu.Unlock()
				if voids != 0 {
					t.Fatalf("unrelated cancellation issued %d voids", voids)
				}
				return
			}
			first := send(eventID, eventType, sub, status, scheduled, canceledAt)
			if scenario == "transient" || scenario == "local_finalization_failure" {
				if first.Code != 500 {
					t.Fatalf("failure returned %d: %s", first.Code, first.Body.String())
				}
				pending, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer)
				event, eventErr := testQueries.GetStripeWebhookEvent(ctx, eventID)
				if err != nil || eventErr != nil || pending.CompletedAt.Valid || event.ProcessedAt.Valid {
					t.Fatalf("failure marked complete: %+v %+v %v %v", pending, event, err, eventErr)
				}
				removeFailure()
				stripe.mu.Lock()
				stripe.failVoid = false
				stripe.mu.Unlock()
				// Reversal reconciles durable pending intent even before the failed event retries.
				if scenario == "transient" {
					if w := send("evt_reverse_pending_"+teamID.String(), "customer.subscription.updated", sub, "active", false, at.Add(10*time.Second)); w.Code != 200 {
						t.Fatalf("reverse pending: %d %s", w.Code, w.Body.String())
					}
				}
				first = send(eventID, eventType, sub, status, scheduled, canceledAt)
			}
			if first.Code != 200 {
				t.Fatalf("cancel: %d %s", first.Code, first.Body.String())
			}
			revoked, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer)
			if err != nil || !revoked.CompletedAt.Valid || derefString(revoked.StripeGrantID) != grantID {
				t.Fatalf("revocation=%+v err=%v", revoked, err)
			}
			projected, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "stale" && (!projected.StripeSubscriptionEventAt.Time.Equal(at.Add(5*time.Second)) || projected.CancelAtPeriodEnd) {
				t.Fatal("stale cancellation changed current projection")
			}
			if scenario == "previous_subscription" && (derefString(projected.StripeSubscriptionID) != "sub_newer_"+teamID.String() || projected.CancelAtPeriodEnd) {
				t.Fatal("old cancellation changed replacement projection")
			}
			if scenario == "same_second" && !projected.CancelAtPeriodEnd {
				t.Fatal("same-second cancellation was dropped")
			}
			if w := send(eventID, eventType, sub, status, scheduled, canceledAt); w.Code != 200 {
				t.Fatalf("duplicate: %d", w.Code)
			}
			responses := make(chan *httptest.ResponseRecorder, 2)
			for _, suffix := range []string{"a", "b"} {
				go func(suffix string) {
					responses <- send("evt_cancel_distinct_"+suffix+"_"+teamID.String(), eventType, sub, status, scheduled, canceledAt)
				}(suffix)
			}
			for i := 0; i < 2; i++ {
				if w := <-responses; w.Code != 200 {
					t.Fatalf("distinct concurrent duplicate: %d %s", w.Code, w.Body.String())
				}
			}
			if w := send("evt_reverse_"+teamID.String(), "customer.subscription.updated", sub, "active", false, at.Add(20*time.Second)); w.Code != 200 {
				t.Fatalf("reversal: %d", w.Code)
			}
			replacement := "sub_replacement_" + teamID.String()
			checkoutEvent := "evt_checkout_replacement_" + teamID.String()
			if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_session_id=$2,
                checkout_initializing_at=now(), checkout_completed_at=NULL, checkout_subscription_id=NULL
                WHERE team_id=$1`, teamID, "cs_"+checkoutEvent); err != nil {
				t.Fatal(err)
			}
			checkoutPayload := stripeCheckoutWebhookPayload(t, checkoutEvent, teamID.String(), customer, replacement, at.Add(25*time.Second))
			checkoutRequest := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(checkoutPayload)))
			checkoutRequest.Header.Set("Content-Type", "application/json")
			checkoutRequest.Header.Set("Stripe-Signature", stripeSignature(t, checkoutPayload, time.Now().UTC()))
			if w := doRequest(router, checkoutRequest); w.Code != 200 {
				t.Fatalf("replacement checkout: %d %s", w.Code, w.Body.String())
			}
			if w := send("evt_replacement_"+teamID.String(), "customer.subscription.created", replacement, "active", false, at.Add(30*time.Second)); w.Code != 200 {
				t.Fatalf("replacement: %d %s", w.Code, w.Body.String())
			}
			after, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil {
				t.Fatal(err)
			}
			if derefString(after.StripeActivationCreditGrantID) != grantID || after.StripeActivationCreditGrantedAt != before.StripeActivationCreditGrantedAt || after.StripeActivationUserID != before.StripeActivationUserID {
				t.Fatal("revocation changed activation identity/history")
			}
			var finalRedemption time.Time
			if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_at FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_team_id=$2`, userID, teamID).Scan(&finalRedemption); err != nil || !finalRedemption.Equal(redeemedAt) {
				t.Fatalf("redemption changed: %v %v", finalRedemption, err)
			}
			stripe.mu.Lock()
			creates, voids, expiresCount := stripe.creates, stripe.voids, stripe.expiresCount
			stripe.mu.Unlock()
			wantVoids := 1
			if scenario == "consumed" || scenario == "expired" || scenario == "already_voided" || scenario == "partial_reconciled" {
				wantVoids = 0
			}
			if scenario == "transient" {
				wantVoids = 2
			}
			wantExpires := 0
			if scenario == "partial_reconciled" || scenario == "consumed" {
				wantExpires = 1
			}
			if expiresCount != wantExpires {
				t.Fatalf("expires=%d want=%d", expiresCount, wantExpires)
			}
			if creates != 1 || voids != wantVoids {
				t.Fatalf("creates=%d voids=%d want=1/%d", creates, voids, wantVoids)
			}
			summary := do(router, "GET", "/billing/summary", key, "")
			if summary.Code != 200 {
				t.Fatalf("summary: %d %s", summary.Code, summary.Body.String())
			}
			body := mustJSON(t, summary)
			if body["credit_source"] != "stripe" || body["stripe_credit_balance_usd"] != float64(25) {
				t.Fatalf("unrelated credit not preserved: %v", body)
			}
			stripe.mu.Lock()
			stripe.failBalance = true
			stripe.mu.Unlock()
			unavailable := do(router, "GET", "/billing/summary", key, "")
			if unavailable.Code != 200 {
				t.Fatalf("unavailable summary: %d", unavailable.Code)
			}
			if mustJSON(t, unavailable)["credit_status"] != "unavailable" {
				t.Fatal("Stripe read failure fabricated a balance")
			}
		})
	}
}

func TestIntegration_BillingRecoveryRevokesHistoricalActivationCredit(t *testing.T) {
	for _, scenario := range []string{"canceled", "canceled_unrelated_history", "remote_scheduled", "remote_scheduled_unrelated_history", "missing_id_paginated", "transient", "pending_reservation"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
			customer, sub, grantID := "cus_"+teamID.String(), "sub_"+teamID.String(), "cred_"+teamID.String()
			var localID *string
			if scenario != "missing_id_paginated" {
				localID = &grantID
			}
			status := "canceled"
			if strings.HasPrefix(scenario, "remote_scheduled") {
				status = "active"
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,
                stripe_subscription_status,stripe_activation_credit_grant_id,stripe_activation_credit_granted_at,
                stripe_activation_user_id,trial_ended_at) VALUES($1,$2,$3,$4,$5,now(),$6,now())`, teamID, customer, sub, status, localID, userID); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(scenario, "unrelated_history") {
				eventID := "evt_unrelated_history_" + teamID.String()
				at := time.Now().UTC().Add(-time.Hour)
				payload := stripeSubscriptionWebhookPayload(t, eventID, "customer.subscription.deleted", "sub_unrelated_"+teamID.String(), customer, "canceled", at, at, at.AddDate(0, 1, 0))
				if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,'customer.subscription.deleted',$2)`, eventID, payload); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "pending_reservation" {
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account
                    SET stripe_activation_credit_grant_id=NULL, stripe_activation_credit_granted_at=NULL
                    WHERE team_id=$1`, teamID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
                VALUES($1,now(),$2) ON CONFLICT(user_id) DO UPDATE SET stripe_redemption_at=now(),stripe_redemption_team_id=$2`, userID, teamID); err != nil {
				t.Fatal(err)
			}
			if scenario == "pending_reservation" {
				if _, err := testPool.Exec(ctx, `UPDATE user_promotion_entitlement
                    SET stripe_redemption_at=NULL, stripe_redemption_team_id=NULL
                    WHERE user_id=$1`, userID); err != nil {
					t.Fatal(err)
				}
				eventID := "evt_pending_recovery_" + teamID.String()
				if state := canonicalStripeReserve(t, teamID, userID, eventID); state != "acquired" {
					t.Fatalf("pending reservation: %s", state)
				}
				// The remote grant exists, but its creation response was lost before finalization.
				if _, err := testQueries.MarkStripePromotionAttempt(ctx, db.MarkStripePromotionAttemptParams{
					TeamID: pgtype.UUID{Bytes: teamID, Valid: true}, UserID: userID, EventID: &eventID,
				}); err != nil {
					t.Fatalf("pending activation attempt: %v", err)
				}
			}
			var userBefore string
			if err := testPool.QueryRow(ctx, `SELECT row_to_json(u)::text FROM user_promotion_entitlement u WHERE user_id=$1`, userID).Scan(&userBefore); err != nil {
				t.Fatal(err)
			}
			stripe := &activationRevocationStripe{teamID: teamID, customer: customer, grantID: grantID, balance: 9500, failVoid: scenario == "transient"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/v1/subscriptions/"+sub {
					_ = json.NewEncoder(w).Encode(map[string]any{"id": sub, "customer": customer, "status": "active", "cancel_at_period_end": true})
					return
				}
				if r.Method == "GET" && r.URL.Path == "/v1/billing/credit_grants" {
					if r.URL.Query().Get("starting_after") == "" {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "cred_manual", "customer": customer}}, "has_more": true})
					} else {
						if r.URL.Query().Get("starting_after") != "cred_manual" {
							t.Error("unexpected recovery cursor")
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
							"id": grantID, "customer": customer, "category": "promotional",
							"amount":               map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": 9500}},
							"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
							"metadata":             map[string]string{"activation_identity": "stripe-activation-credit-" + teamID.String()},
						}}, "has_more": false})
					}
					return
				}
				stripe.serve(t, w, r)
			}))
			defer server.Close()
			args := []string{"-revoke-activation", "-team", teamID.String()}
			dry := runBillingRecoveryCommand(t, server.URL, args...)
			if dry["outcome"] != "candidate" {
				t.Fatalf("dry run: %v", dry)
			}
			var hasIntent bool
			if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_activation_credit_revocation WHERE team_id=$1)`, teamID).Scan(&hasIntent); err != nil || hasIntent {
				t.Fatalf("dry run mutated intent: %v %v", hasIntent, err)
			}
			result := runBillingRecoveryCommand(t, server.URL, append(args, "-apply")...)
			if scenario == "transient" {
				if result["outcome"] != "unresolved" {
					t.Fatalf("transient cleanup: %v", result)
				}
				pending, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer)
				if err != nil || pending.CompletedAt.Valid {
					t.Fatalf("lost pending cleanup: %+v %v", pending, err)
				}
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status='active',cancel_at_period_end=false WHERE team_id=$1`, teamID); err != nil {
					t.Fatal(err)
				}
				stripe.mu.Lock()
				stripe.failVoid = false
				stripe.mu.Unlock()
				result = runBillingRecoveryCommand(t, server.URL, append(args, "-apply")...)
			}
			if result["outcome"] != "reconciled" {
				t.Fatalf("apply: %v", result)
			}
			repeat := runBillingRecoveryCommand(t, server.URL, append(args, "-apply")...)
			if repeat["outcome"] != "reconciled" {
				t.Fatalf("repeat: %v", repeat)
			}
			complete, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer)
			if err != nil || !complete.CompletedAt.Valid || derefString(complete.ActivationGrantID) != grantID {
				t.Fatalf("completion: %+v %v", complete, err)
			}
			var userAfter string
			if err := testPool.QueryRow(ctx, `SELECT row_to_json(u)::text FROM user_promotion_entitlement u WHERE user_id=$1`, userID).Scan(&userAfter); err != nil {
				t.Fatalf("redemption history changed: %v", err)
			}
			if scenario != "pending_reservation" && userAfter != userBefore {
				t.Fatalf("redemption history changed: before=%s after=%s", userBefore, userAfter)
			}
			if scenario == "pending_reservation" {
				var redeemed bool
				if err := testPool.QueryRow(ctx, `SELECT stripe_redemption_at IS NOT NULL AND stripe_redemption_reserved_team_id IS NULL FROM user_promotion_entitlement WHERE user_id=$1`, userID).Scan(&redeemed); err != nil || !redeemed {
					t.Fatalf("pending reservation was not finalized: redeemed=%t err=%v", redeemed, err)
				}
			}
			stripe.mu.Lock()
			creates, voids := stripe.creates, stripe.voids
			stripe.mu.Unlock()
			wantVoids := 1
			if scenario == "transient" {
				wantVoids = 2
			}
			if creates != 0 || voids != wantVoids {
				t.Fatalf("creates=%d voids=%d", creates, voids)
			}
		})
	}
}

func TestIntegration_StripeCancellationBeforeActivationBlocksBonus(t *testing.T) {
	for _, scenario := range []string{"scheduled", "scheduled_trialing", "scheduled_past_due", "scheduled_first_created", "scheduled_first_created_trialing", "canceled", "deleted", "unrelated", "checkout_associated", "checkout_generation", "checkout_expired", "first_created"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
			customer, subscription := "cus_"+teamID.String(), "sub_"+teamID.String()
			if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status)
				VALUES($1,$2,$3,'incomplete')`, teamID, customer, subscription); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason)
				VALUES($1,5,5,'signup trial credit')`, teamID); err != nil {
				t.Fatal(err)
			}
			stripe := &fakeStripeClient{}
			router := newBillingRouter(t, stripe)
			at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			metadata := map[string]string{"activation_user_id": userID.String()}
			firstCreated := strings.Contains(scenario, "first_created")
			if strings.HasPrefix(scenario, "checkout_") || firstCreated {
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=NULL WHERE team_id=$1`, teamID); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(scenario, "checkout_") {
				var checkoutSubscription *string
				if scenario == "checkout_associated" {
					checkoutSubscription = &subscription
				}
				if _, err := testPool.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=$2,
					stripe_checkout_actor_id=$3, checkout_subscription_id=$4 WHERE team_id=$1`, teamID, at, userID, checkoutSubscription); err != nil {
					t.Fatal(err)
				}
				metadata["checkout_generation"] = at.Format(time.RFC3339Nano)
				if scenario == "checkout_expired" {
					if err := testQueries.RecordStripeCheckoutExpiration(ctx, db.RecordStripeCheckoutExpirationParams{
						TeamID: teamID, StripeCustomerID: customer, CheckoutGeneration: at, CheckoutSessionID: "cs_" + teamID.String(),
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
			eventID, eventType, status := "evt_cancel_before_activation_"+teamID.String(), "customer.subscription.updated", "canceled"
			if strings.HasPrefix(scenario, "scheduled") {
				status = "active"
				if strings.HasSuffix(scenario, "trialing") {
					status = "trialing"
				}
				if scenario == "scheduled_past_due" {
					status = "past_due"
				}
			}
			if firstCreated {
				eventType = "customer.subscription.created"
			}
			if scenario == "deleted" {
				eventType = "customer.subscription.deleted"
			}
			if scenario == "unrelated" {
				subscription = "sub_unrelated_" + teamID.String()
			}
			payload := stripeSubscriptionWebhookPayloadWithMetadata(t, eventID, eventType, subscription, customer, status, at, at, at.AddDate(0, 1, 0), metadata)
			if strings.HasPrefix(scenario, "scheduled") {
				var event map[string]any
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Fatal(err)
				}
				event["data"].(map[string]any)["object"].(map[string]any)["cancel_at_period_end"] = true
				var err error
				payload, err = json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
				req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC()))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
				}
			}
			if scenario == "checkout_expired" {
				if _, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("expired checkout recorded cancellation: %v", err)
				}
				return
			}
			if scenario != "unrelated" {
				revocation, err := testQueries.GetStripeActivationCreditRevocation(ctx, customer)
				if err != nil || !revocation.CompletedAt.Valid || revocation.StripeGrantID != nil {
					t.Fatalf("missing completed no-grant cancellation: %+v %v", revocation, err)
				}
			}
			if strings.HasPrefix(scenario, "scheduled") {
				account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
				if err != nil || !account.CancelAtPeriodEnd || account.StripeActivationCreditReservedAt.Valid ||
					account.StripeActivationCreditGrantedAt.Valid || derefString(account.StripeActivationCreditGrantID) != "" || len(stripe.creditGrantCalls) != 0 {
					t.Fatalf("scheduled cancellation reserved or granted activation credit: %+v calls=%d err=%v", account, len(stripe.creditGrantCalls), err)
				}
				if eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, teamID); err != nil || !eligible {
					t.Fatalf("scheduled cancellation removed paid-through access: eligible=%v err=%v", eligible, err)
				}
				var trialEnded bool
				var remaining float64
				if err := testPool.QueryRow(ctx, `SELECT a.trial_ended_at IS NOT NULL, g.remaining_usd
					FROM team_billing_account a JOIN team_credit_grant g ON g.team_id=a.team_id
					WHERE a.team_id=$1 AND g.reason='signup trial credit'`, teamID).Scan(&trialEnded, &remaining); err != nil || !trialEnded || remaining != 0 {
					t.Fatalf("scheduled activation retained trial: ended=%v remaining=%v err=%v", trialEnded, remaining, err)
				}
				ended := stripeSubscriptionWebhookPayload(t, "evt_end_"+teamID.String(), "customer.subscription.deleted", subscription, customer, "canceled", at.Add(time.Second), at, at.AddDate(0, 1, 0))
				req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(ended)))
				req.Header.Set("Stripe-Signature", stripeSignature(t, ended, time.Now().UTC()))
				if w := doRequest(router, req); w.Code != http.StatusOK {
					t.Fatalf("end subscription: %d %s", w.Code, w.Body.String())
				}
				var eligible bool
				if err := testPool.QueryRow(ctx, `SELECT team_sandbox_billing_eligible($1)`, teamID).Scan(&eligible); err != nil || eligible {
					t.Fatalf("canceled subscription regained trial eligibility: %v %v", eligible, err)
				}
			}
			for i, created := range []time.Time{at.Add(-time.Second), at.Add(2 * time.Second), at.Add(3 * time.Second)} {
				if w := sendStripeActivationWebhook(t, router, fmt.Sprintf("evt_later_activation_%s_%d", teamID, i), teamID, userID, created); w.Code != http.StatusOK {
					t.Fatalf("activation: %d %s", w.Code, w.Body.String())
				}
			}
			wantGrants := 0
			if scenario == "unrelated" {
				wantGrants = 1
			}
			if len(stripe.creditGrantCalls) != wantGrants {
				t.Fatalf("created %d grants, want %d", len(stripe.creditGrantCalls), wantGrants)
			}
			account, err := testQueries.GetTeamBillingAccount(ctx, teamID)
			if err != nil || derefString(account.StripeSubscriptionStatus) != "active" || account.CancelAtPeriodEnd || account.StripeActivationCreditReservedAt.Valid {
				t.Fatalf("activation projection or reservation is incorrect: %+v %v", account, err)
			}
		})
	}
}
