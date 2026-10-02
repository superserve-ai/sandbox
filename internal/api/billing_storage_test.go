package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/config"
)

func TestStorageCheckoutPreload(t *testing.T) {
	h := &Handlers{Config: &config.Config{StripeCheckoutPriceIDs: []string{"price_cpu", "price_memory", "price_storage"}}}
	states := h.billingResourceStates(false)
	ids, err := billingCheckoutPriceIDs(states)
	if err != nil || !reflect.DeepEqual(ids, []string{"price_cpu", "price_memory", "price_storage"}) {
		t.Fatalf("preload prices=%v err=%v", ids, err)
	}
	if states[2].Billable || !states[2].Tracked {
		t.Fatal("preload changed tracked/billable state")
	}
	enabled := false
	states[2].SubscriptionEnabled = &enabled
	states[2].Billable = true
	ids, err = billingCheckoutPriceIDs(states)
	if err != nil || len(ids) != 2 {
		t.Fatalf("subscription inclusion is not independent: %v %v", ids, err)
	}
	legacy := (&Handlers{Config: &config.Config{StripeCheckoutPriceIDs: []string{"price_cpu", "price_memory"}}}).billingResourceStates(false)
	if _, err = billingCheckoutPriceIDs(legacy); err != nil {
		t.Fatalf("legacy compute checkout: %v", err)
	}
}

func TestStorageSubscriptionReadiness(t *testing.T) {
	for _, tc := range []struct {
		name      string
		initial   int
		reconcile bool
		failure   string
	}{
		{"preload", 0, true, ""}, {"already ready", 1, true, ""}, {"verify missing", 0, false, "has 0"},
		{"duplicate", 2, true, "has 2"}, {"wrong price", 1, true, "conflicting"},
		{"wrong customer", 1, false, "association"}, {"wrong meter", 1, false, "mapping"},
		{"wrong rate", 1, false, "canonical"}, {"anchor changed", 0, true, "anchor changed"},
		{"price scoped credit missing storage", 1, false, "price scope"},
		{"price scoped credit includes storage", 1, false, ""},
		{"metered startup credit", 1, false, ""},
		{"expired price scoped credit missing storage", 1, false, ""},
		{"voided price scoped credit missing storage", 1, false, ""},
		{"paginated duplicate", 2, false, "has 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, posts, subReads := tc.initial, 0, 0
			price := func(id string) map[string]any {
				return map[string]any{"id": id, "product": "prod_storage", "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": "0.0108", "recurring": map[string]any{"usage_type": "metered", "meter": "mtr_storage", "interval": "month", "interval_count": 1}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				out := any(nil)
				switch r.URL.Path {
				case "/v1/prices/price_storage":
					p := price("price_storage")
					if tc.name == "wrong rate" {
						p["unit_amount_decimal"] = "1"
					}
					out = p
				case "/v1/billing/meters/mtr_storage":
					formula := "sum"
					if tc.name == "wrong meter" {
						formula = "last"
					}
					out = map[string]any{"event_name": "storage_gib_hours", "status": "active", "default_aggregation": map[string]string{"formula": formula}, "customer_mapping": map[string]string{"type": "by_id", "event_payload_key": "stripe_customer_id"}, "value_settings": map[string]string{"event_payload_key": "value"}}
				case "/v1/subscriptions/sub_example":
					subReads++
					customer := "cus_example"
					anchor := 1234
					if tc.name == "wrong customer" {
						customer = "cus_other"
					}
					if tc.name == "anchor changed" && subReads > 1 {
						anchor++
					}
					out = map[string]any{"id": "sub_example", "customer": customer, "status": "active", "billing_cycle_anchor": anchor}
				case "/v1/subscription_items":
					if r.Method == http.MethodPost {
						posts++
						if err := r.ParseForm(); err != nil {
							t.Error(err)
						}
						if r.Form.Get("proration_behavior") != "none" || r.Form.Get("subscription") != "sub_example" || r.Form.Get("price") != "price_storage" || len(r.Form) != 3 || r.Header.Get("Idempotency-Key") != "storage-item:sub_example:price_storage" {
							t.Errorf("unsafe item request: %v", r.Form)
						}
						items++
						out = map[string]string{"id": "si_storage"}
					} else {
						data := []any{}
						start, end := 0, items
						more := false
						if tc.name == "paginated duplicate" {
							if r.URL.Query().Get("starting_after") == "" {
								end = 1
								more = true
							} else {
								start = 1
							}
						}
						for i := start; i < end; i++ {
							id := "price_storage"
							if tc.name == "wrong price" {
								id = "price_wrong"
							}
							data = append(data, map[string]any{"id": fmt.Sprintf("si_%d", i), "price": price(id)})
						}
						out = map[string]any{"data": data, "has_more": more}
					}
				case "/v1/billing/credit_grants":
					scope := map[string]any{"price_type": "metered"}
					if strings.Contains(tc.name, "price scoped") {
						id := "price_cpu"
						if strings.Contains(tc.name, "includes") {
							id = "price_storage"
						}
						scope = map[string]any{"prices": []any{map[string]string{"id": id}}}
					}
					grant := map[string]any{"id": "cg_example", "applicability_config": map[string]any{"scope": scope}}
					if strings.HasPrefix(tc.name, "expired") {
						grant["expires_at"] = 1
					}
					if strings.HasPrefix(tc.name, "voided") {
						grant["voided_at"] = 1
					}
					out = map[string]any{"data": []any{grant}, "has_more": false}
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.Error(w, "unexpected", 404)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			client := &stripeHTTPClient{baseURL: server.URL, secretKey: "sk_test_example", apiVersion: "2025-06-30.basil", httpClient: server.Client()}
			p := StripeStorageSubscriptionParams{SubscriptionID: "sub_example", CustomerID: "cus_example", PriceID: "price_storage", EventName: "storage_gib_hours", UnitAmountDecimal: "0.0108", Reconcile: tc.reconcile}
			err := client.EnsureStorageSubscription(context.Background(), p)
			if tc.failure != "" {
				if err == nil || !strings.Contains(err.Error(), tc.failure) {
					t.Fatalf("error=%v want %s", err, tc.failure)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = client.EnsureStorageSubscription(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			wantPosts := 0
			if tc.initial == 0 {
				wantPosts = 1
			}
			if posts != wantPosts {
				t.Fatalf("rerun created %d items, want %d", posts, wantPosts)
			}
		})
	}
}
