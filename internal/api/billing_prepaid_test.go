package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPrepaidAmountsUseFiveDollarSteps(t *testing.T) {
	for amount, want := range map[int64]bool{0: false, 499: false, 500: true, 750: false, 1000: true, 100000000: true, 100000500: false} {
		if validPrepaidAmount(amount) != want {
			t.Fatalf("amount %d", amount)
		}
	}
}

func TestPrepaidGrantFormIsPaidNonExpiringMetered(t *testing.T) {
	id := uuid.New()
	raw, err := prepaidCreditRequest(id, "cus_example", 2500, "checkout")
	if err != nil {
		t.Fatal(err)
	}
	form, err := prepaidGrantForm(raw)
	if err != nil || form.Get("category") != "paid" || form.Has("expires_at") || form.Get("applicability_config[scope][price_type]") != "metered" || form.Get("metadata[prepaid_purchase_id]") != id.String() {
		t.Fatal(form, err)
	}
}

func TestInvoiceCreditLedgerPagesBeyondOneHundredGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/billing/credit_balance_summary" {
			fmt.Fprint(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":100}}}]}`)
			return
		}
		page := 0
		if r.URL.Query().Get("starting_after") != "" {
			page = 1
		}
		data := []map[string]any{}
		for i := 0; i < 100; i++ {
			data = append(data, map[string]any{"id": fmt.Sprintf("credgr_%d_%d", page, i), "applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": page == 0})
	}))
	defer srv.Close()
	c := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	total, err := c.invoiceCreditLedger(t.Context(), "cus_example", time.Now().Unix())
	if err != nil || total != 200*100 {
		t.Fatal(total, err)
	}
}

func TestPrepaidCheckoutGenerationCreationBoundary(t *testing.T) {
	generation := time.Date(2026, 1, 1, 0, 0, 0, 900000000, time.UTC)
	for _, tc := range []struct {
		remaining time.Duration
		want      bool
	}{
		{30*time.Minute - time.Second, false},
		{30 * time.Minute, false},
		{30*time.Minute + time.Second, true},
		{23 * time.Hour, true},
	} {
		if got := prepaidCheckoutGenerationCanCreate(generation, generation.Add(tc.remaining)); got != tc.want {
			t.Fatalf("remaining %v: got %v want %v", tc.remaining, got, tc.want)
		}
	}
}

func TestNewPrepaidAmountMaximum(t *testing.T) {
	for amount, want := range map[int64]bool{-500: false, 0: false, 499: false, 500: true, 750: false, 999500: true, 1000000: true, 1000001: false, 1000500: false, 100000000: false} {
		if got := validNewPrepaidAmount(amount); got != want {
			t.Fatalf("amount %d: got %v want %v", amount, got, want)
		}
	}
}
