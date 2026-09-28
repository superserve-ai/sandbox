package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestRevocationAuditDoesNotActivateOrGuessIdentity(t *testing.T) {
	for _, scenario := range []string{"canceled_user_promotion", "scheduled_user_promotion", "paused", "unpaid", "missing", "multiple", "wrong_owner", "conflicting_identity", "excluded"} {
		t.Run(scenario, func(t *testing.T) {
			team := uuid.New()
			customer, sub, grantID := "cus_example", "sub_example", "cred_example"
			account := billingAccount{TeamID: team, CustomerID: &customer, SubscriptionID: &sub, GrantID: &grantID, UserPromotion: true}
			if scenario == "missing" || scenario == "multiple" {
				account.GrantID = nil
			}
			if scenario == "canceled_user_promotion" {
				account.Status = stringPtrForTest("canceled")
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" {
					t.Errorf("audit mutated Stripe: %s %s", r.Method, r.URL)
					http.Error(w, "mutation", 400)
					return
				}
				if r.URL.Path == "/v1/subscriptions/"+sub {
					status := "active"
					scheduled := true
					if scenario == "paused" || scenario == "unpaid" {
						status = scenario
						scheduled = false
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": sub, "customer": customer, "status": status, "cancel_at_period_end": scheduled})
					return
				}
				grant := map[string]any{"id": grantID, "customer": customer, "category": "promotional",
					"amount":               map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": 9500}},
					"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
					"metadata":             map[string]string{"activation_identity": "stripe-activation-credit-" + team.String()}}
				if scenario == "wrong_owner" {
					grant["customer"] = "cus_other"
				}
				if scenario == "conflicting_identity" {
					grant["metadata"] = map[string]string{"activation_identity": "other-promotion"}
				}
				if r.URL.Path == "/v1/billing/credit_grants" {
					data := []any{}
					if scenario == "multiple" {
						data = []any{grant, grant}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": false})
					return
				}
				if r.URL.Path != "/v1/billing/credit_grants/"+grantID {
					t.Errorf("unexpected lookup: %s", r.URL)
				}
				_ = json.NewEncoder(w).Encode(grant)
			}))
			defer server.Close()
			var excluded *uuid.UUID
			if scenario == "excluded" {
				excluded = &team
			}
			result := auditRevocation(t.Context(), nil, stripeClient{baseURL: server.URL, version: "2025-06-30", secret: "sk_test_example", httpClient: server.Client()}, account, excluded, false)
			want := "unresolved"
			switch scenario {
			case "canceled_user_promotion", "scheduled_user_promotion":
				want = "candidate"
			case "paused", "unpaid", "excluded":
				want = "skipped"
			}
			if result["outcome"] != want {
				t.Fatalf("result=%v want=%s", result, want)
			}
			if scenario == "excluded" && calls != 0 {
				t.Fatal("excluded account called Stripe")
			}
		})
	}
}
