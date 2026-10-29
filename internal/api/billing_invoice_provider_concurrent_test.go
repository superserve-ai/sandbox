package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Two writers can install the rounding price at the same moment. The loser
// removes its own copy so retries find exactly one item.
func TestInvoiceRoundingItemInstalledConcurrentlyIsRemoved(t *testing.T) {
	price := map[string]any{"id": "price_round", "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": "1", "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": "mtr_round"}}
	items := []map[string]any{{"id": "si_base", "price": map[string]any{"id": "price_cpu"}}}
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var out any
		switch {
		case r.URL.Path == "/v1/prices/price_round":
			out = price
		case r.URL.Path == "/v1/billing/meters":
			out = map[string]any{"data": []any{map[string]any{"id": "mtr_round", "event_name": "round", "status": "active", "default_aggregation": map[string]string{"formula": "sum"}, "customer_mapping": map[string]string{"type": "by_id", "event_payload_key": "stripe_customer_id"}, "value_settings": map[string]string{"event_payload_key": "value"}}}}
		case r.URL.Path == "/v1/subscriptions/sub_example":
			out = map[string]any{"id": "sub_example", "customer": "cus_example", "status": "active", "items": map[string]any{"data": items}}
		case r.URL.Path == "/v1/subscriptions":
			out = map[string]any{"data": []any{map[string]any{"id": "sub_example", "customer": "cus_example", "status": "active"}}, "has_more": false}
		case r.URL.Path == "/v1/subscription_items" && r.Method == http.MethodPost:
			items = append(items, map[string]any{"id": "si_theirs", "price": price}, map[string]any{"id": "si_mine", "price": price})
			out = map[string]any{"id": "si_mine", "price": price}
		case strings.HasPrefix(r.URL.Path, "/v1/subscription_items/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/v1/subscription_items/")
			deleted = append(deleted, id)
			kept := []map[string]any{}
			for _, item := range items {
				if item["id"] != id {
					kept = append(kept, item)
				}
			}
			items = kept
			out = map[string]any{"id": id, "deleted": true}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	client := &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2025-01-01", secretKey: "sk_test"}
	_, err := client.ensureInvoiceSubscriptionValidated(t.Context(), invoiceAccount{Customer: "cus_example", Subscription: "sub_example", Price: "price_round", Event: "round"}, true, false, nil)
	if err == nil || !strings.Contains(err.Error(), "concurrently") {
		t.Fatalf("expected the concurrent install to fail, got %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "si_mine" || len(items) != 2 || items[1]["id"] != "si_theirs" {
		t.Fatalf("our copy was not removed: deleted=%v items=%v", deleted, items)
	}
}
