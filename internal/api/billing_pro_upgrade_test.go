package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProUpgradeProrationPreservesMonthEnd(t *testing.T) {
	start := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	end := time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC)
	at := time.Date(2027, 2, 14, 12, 0, 0, 0, time.UTC)
	amount, err := proratedProAmount(25000, start, end, at)
	if err != nil || amount != 12500 {
		t.Fatalf("prorated fee=%d, %v", amount, err)
	}
	if _, err = proratedProAmount(25000, start, end, end); err == nil {
		t.Fatal("accepted an expired quote")
	}
	b := invoiceBase{Price: "price_pro", Amount: 25000, Months: 1, Anchor: start, StartsAt: end.Unix()}
	if fee, _, _, err := b.expectedFee(start); err != nil || fee != 0 {
		t.Fatalf("charged before recurring start: %d %v", fee, err)
	}
	fee, _, next, err := b.expectedFee(end)
	if err != nil || fee != 25000 || next != time.Date(2027, 3, 31, 12, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("recurring calendar changed: %d %d %v", fee, next, err)
	}
	b.SeparateFees[0] = end.Unix()
	if fee, _, _, err := b.expectedFee(end); err != nil || fee != 0 {
		t.Fatalf("charged an already paid catch-up boundary: %d %v", fee, err)
	}
	if fee, _, _, err := b.expectedFee(time.Unix(next, 0)); err != nil || fee != 25000 {
		t.Fatalf("waived an ordinary renewal: %d %v", fee, err)
	}
}

func TestProUpgradeCheckoutIsOneOffAndSavesCard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"mode": "payment", "line_items[0][price_data][unit_amount]": "12500", "line_items[0][quantity]": "1", "payment_intent_data[setup_future_usage]": "off_session", "allow_promotion_codes": "true", "invoice_creation[enabled]": "true", "payment_intent_data[metadata][pro_upgrade_id]": "upgrade", "line_items[0][price_data][product]": "prod_pro"} {
			if r.Form.Get(key) != want {
				t.Errorf("%s=%s", key, r.Form.Get(key))
			}
		}
		if r.Form.Has("subscription_data[billing_mode][type]") || r.Form.Has("line_items[0][price]") {
			t.Error("one-off checkout included recurring terms")
		}
		_, _ = w.Write([]byte(`{"id":"cs_example","url":"https://checkout.stripe.com/example"}`))
	}))
	defer srv.Close()
	c := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	_, err := c.CreateCheckoutSession(t.Context(), StripeCreateCheckoutSessionParams{OneOffAmount: 12500, OneOffProduct: "prod_pro", OneOffName: "Prorated Pro", CustomerID: "cus_example", BasePriceID: "price_pro", Flexible: true, AllowPromotionCodes: true, Metadata: map[string]string{"pro_upgrade_id": "upgrade"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProUpgradeFullPromotionRequiresCardSetup(t *testing.T) {
	u := proUpgrade{ID: uuid.New(), Customer: "cus_example", Amount: 12500}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/invoices/in_example":
			_, _ = w.Write([]byte(`{"id":"in_example","customer":"cus_example","status":"paid","currency":"usd","amount_paid":0,"amount_due":0,"amount_remaining":0,"starting_balance":0,"ending_balance":0,"status_transitions":{"paid_at":100},"lines":{"data":[{"amount":12500,"quantity":1,"currency":"usd"}]}}`))
		case "/v1/customers/cus_example":
			_, _ = w.Write([]byte(`{"id":"cus_example","invoice_settings":{"default_payment_method":null}}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	s := StripeRetrievedCheckoutSession{Currency: "usd", AmountSubtotal: 12500, AmountTotal: 0, PaymentStatus: "no_payment_required", InvoiceID: "in_example"}
	s.TotalDetails.Discount = 12500
	method, evidence, err := c.verifyProUpgradePayment(t.Context(), u, s, true)
	if err != nil || method != "" || !json.Valid(evidence) {
		t.Fatalf("full promotion: method=%q evidence=%s err=%v", method, evidence, err)
	}
}

func TestProUpgradeCatchupNeverInventsOrdinaryRenewals(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	installed := end.Add(-time.Hour)
	h := &Handlers{Now: func() time.Time { return end.AddDate(0, 2, 0) }}
	if err := h.catchUpProUpgrade(t.Context(), nil, proUpgrade{End: end, BaseCreated: &installed}, proOffer{}, nil); err != nil {
		t.Fatal(err)
	}
}
