package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvoiceCollectionPaymentEvidence(t *testing.T) {
	for _, tc := range []struct{ name, status, want string }{
		{"unconfirmed", "requires_confirmation", "ready"},
		{"processing", "processing", "processing"},
		{"intent succeeded but invoice open", "succeeded", "processing"},
		{"authentication", "requires_action", "requires_action"},
		{"unattempted without method", "requires_payment_method", "ready"},
		{"declined", "requires_payment_method", "requires_payment_method"},
		{"canceled intent", "canceled", "review_required"},
		{"capture", "requires_capture", "review_required"},
		{"wrong customer", "requires_confirmation", "review_required"},
		{"wrong invoice", "requires_confirmation", "review_required"},
		{"wrong mode", "requires_confirmation", "review_required"},
		{"partial evidence", "requires_confirmation", "review_required"},
		{"multiple payments", "requires_confirmation", "review_required"},
		{"previous error", "requires_confirmation", "review_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pi := map[string]any{"id": "pi_example", "customer": "cus_example", "currency": "usd", "status": tc.status}
			payment := map[string]any{"invoice": "in_example", "currency": "usd", "status": "open", "payment": map[string]any{"type": "payment_intent", "payment_intent": pi}}
			data := []any{payment}
			switch tc.name {
			case "wrong customer":
				pi["customer"] = "cus_other"
			case "wrong invoice":
				payment["invoice"] = "in_other"
			case "wrong mode":
				pi["livemode"] = true
			case "multiple payments":
				data = append(data, payment)
			case "previous error", "declined":
				pi["last_payment_error"] = map[string]any{"code": "card_declined"}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v1/invoice_payments" || r.URL.Query().Get("invoice") != "in_example" || r.URL.Query().Get("expand[]") != "data.payment.payment_intent" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": tc.name == "partial evidence"})
			}))
			defer server.Close()
			client := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-05-27.dahlia", httpClient: server.Client()}
			state, err := client.invoicePaymentState(t.Context(), StripeInvoiceAmounts{ID: "in_example", Customer: "cus_example", Currency: "usd"})
			if err != nil || state != tc.want {
				t.Fatalf("state=%s err=%v want=%s", state, err, tc.want)
			}
		})
	}
}

func TestInvoiceCollectionSettlementFingerprint(t *testing.T) {
	var inv StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(`{"id":"in_example","customer":"cus_example","currency":"usd","status":"open","amount_due":500,"amount_remaining":500,"total":500,"lines":{"data":[{"id":"il_b","amount":200},{"id":"il_a","amount":300}]},"status_transitions":{"finalized_at":100}}`), &inv); err != nil {
		t.Fatal(err)
	}
	saved := invoiceSettlementHash(inv)
	inv.Status = "paid"
	zero := int64(0)
	inv.AmountRemaining = &zero
	inv.StatusTransitions.PaidAt = 200
	inv.Lines.Data[0], inv.Lines.Data[1] = inv.Lines.Data[1], inv.Lines.Data[0]
	if invoiceSettlementHash(inv) != saved {
		t.Fatal("payment or line ordering invalidated final settlement")
	}
	inv.Lines.Data[0].Amount++
	inv.Lines.Data[1].Amount--
	if invoiceSettlementHash(inv) == saved {
		t.Fatal("offsetting line mutations escaped immutable settlement check")
	}
}
