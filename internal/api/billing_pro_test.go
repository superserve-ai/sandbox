package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestProInvoiceFeeIsolation(t *testing.T) {
	end := int64(0)
	inv := StripeInvoiceAmounts{ID: "in_example", Status: "paid", Currency: "usd", Subtotal: 255000, Total: 155000, AmountDue: 155000, EndingBalance: &end, PretaxCredits: []StripeInvoicePretaxCredit{{Type: "credit_balance_transaction", Amount: 100000, CreditBalanceTransaction: "cbtxn_example"}}}
	plan := billing.InvoiceClosePlan{ExpectedCents: 135000, BaseCents: 120000}
	if err := verifyInvoicePlanSettlement(inv, plan, 100000, 0); err != nil {
		t.Fatal(err)
	}
	inv.Total -= 1
	if err := verifyInvoicePlanSettlement(inv, plan, 100000, 0); err == nil {
		t.Fatal("accepted incorrect invoice total")
	}
	inv.Total = 100000
	inv.PretaxCredits[0].Amount = 155000
	if err := verifyInvoicePlanSettlement(inv, plan, 155000, 0); err == nil {
		t.Fatal("allowed credit to consume the base fee")
	}
}
func TestProAnnualFeeSchedule(t *testing.T) {
	anchor := time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC)
	b := invoiceBase{Price: "price_base", Amount: 1200000, Months: 12, Anchor: anchor}
	if amount, _, _, err := b.expectedFee(time.Date(2024, 3, 29, 12, 0, 0, 0, time.UTC)); err != nil || amount != 0 {
		t.Fatalf("monthly usage repeated annual fee: %d %v", amount, err)
	}
	amount, start, end, err := b.expectedFee(time.Date(2025, 2, 28, 12, 0, 0, 0, time.UTC))
	if err != nil || amount != 1200000 || start != time.Date(2025, 2, 28, 12, 0, 0, 0, time.UTC).Unix() || end != time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("wrong annual boundaries: %d %d %d %v", amount, start, end, err)
	}
}

func TestProFeeScheduleIgnoresTimestampLocation(t *testing.T) {
	for _, tc := range []struct {
		name, anchor, boundary, end string
		months                      int32
	}{
		{"monthly renewal", "2026-09-15T20:46:30Z", "2026-10-15T20:46:30Z", "2026-11-15T20:46:30Z", 1},
		{"month-end clamping", "2026-01-31T01:30:00Z", "2026-02-28T01:30:00Z", "2026-03-31T01:30:00Z", 1},
		{"annual leap day", "2024-02-29T23:30:00Z", "2025-02-28T23:30:00Z", "2026-02-28T23:30:00Z", 12},
	} {
		for _, offset := range []int{-5 * 3600, 9 * 3600} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, offset), func(t *testing.T) {
				anchor, _ := time.Parse(time.RFC3339, tc.anchor)
				boundary, _ := time.Parse(time.RFC3339, tc.boundary)
				end, _ := time.Parse(time.RFC3339, tc.end)
				zone := time.FixedZone("stored timestamp", offset)
				b := invoiceBase{Price: "price_base", Amount: 120000, Months: tc.months, Anchor: anchor.In(zone)}
				amount, gotStart, gotEnd, err := b.expectedFee(boundary.In(zone))
				if err != nil || amount != b.Amount || gotStart != boundary.Unix() || gotEnd != end.Unix() {
					t.Fatalf("fee period changed with timestamp location: amount=%d start=%d end=%d err=%v", amount, gotStart, gotEnd, err)
				}
			})
		}
	}
}
func TestProInvoiceRequiresCashEvidence(t *testing.T) {
	for _, tc := range []struct {
		name             string
		amount           int64
		status, customer string
		outOfBand        bool
		starting         int64
		want             bool
		creditAmount     int64
	}{
		{"paid", 120000, "succeeded", "cus_example", false, 0, true, 0},
		{"discounted base", 120000, "succeeded", "cus_example", false, 0, false, 1},
		{"carried usage balance", 120030, "succeeded", "cus_example", false, 30, true, 0},
		{"no cash", 0, "succeeded", "cus_example", false, 0, false, 0},
		{"pending cash", 120000, "processing", "cus_example", false, 0, false, 0},
		{"wrong payer", 120000, "succeeded", "cus_other", false, 0, false, 0},
		{"out of band", 120000, "succeeded", "cus_example", true, 0, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/invoices/in_example":
					fmt.Fprintf(w, `{"id":"in_example","customer":"cus_example","status":"paid","currency":"usd","total":120000,"amount_due":%d,"starting_balance":%d,"ending_balance":0,"amount_paid":%d,"amount_remaining":0,"paid_out_of_band":%t,"status_transitions":{"paid_at":100},"parent":{"subscription_details":{"subscription":"sub_example"}},"lines":{"data":[{"quantity":1,"amount":120000,"currency":"usd","pretax_credit_amounts":[{"type":"discount","amount":%d}],"period":{"start":100,"end":200},"pricing":{"price_details":{"price":"price_base"}},"parent":{"subscription_item_details":{"subscription":"sub_example"}}}]}}`, 120000+tc.starting, tc.starting, 120000+tc.starting, tc.outOfBand, tc.creditAmount)
				case "/v1/invoice_payments":
					fmt.Fprintf(w, `{"data":[{"id":"inpay_example","invoice":"in_example","status":"paid","currency":"usd","amount_paid":%d,"payment":{"type":"payment_intent","payment_intent":"pi_example"}}]}`, tc.amount)
				case "/v1/payment_intents/pi_example":
					fmt.Fprintf(w, `{"id":"pi_example","status":%q,"customer":%q,"currency":"usd","amount_received":%d,"latest_charge":"ch_example"}`, tc.status, tc.customer, 120000+tc.starting)
				case "/v1/charges/ch_example":
					fmt.Fprintf(w, `{"id":"ch_example","customer":"cus_example","payment_intent":"pi_example","currency":"usd","paid":true,"captured":true,"amount_captured":%d,"amount_refunded":0}`, 120000+tc.starting)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
			_, paid, err := client.verifyProInvoice(t.Context(), "in_example", proOffer{Price: "price_base", Amount: 120000}, "cus_example", "sub_example")
			if tc.want && (!paid || err != nil) {
				t.Fatalf("valid payment rejected: %v", err)
			}
			if !tc.want && paid {
				t.Fatal("unverified payment accepted")
			}
		})
	}
}
func TestProMixedIntervalCalendar(t *testing.T) {
	anchor := time.Date(2026, 1, 30, 12, 0, 0, 0, time.UTC)
	raw := fmt.Sprintf(`{"id":"sub_example","billing_mode":{"type":"flexible"},"billing_cycle_anchor":%d,"items":{"data":[{"quantity":1,"price":{"id":"price_base","currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":"1200000","recurring":{"usage_type":"licensed","interval":"year","interval_count":1}},"current_period_start":%d,"current_period_end":%d},{"price":{"id":"price_cpu"},"current_period_start":%d,"current_period_end":%d}]}}`, anchor.Unix(), anchor.Unix(), anchor.AddDate(1, 0, 0).Unix(), anchor.Unix(), time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC).Unix())
	var sub invoiceSubscription
	if err := json.Unmarshal([]byte(raw), &sub); err != nil {
		t.Fatal(err)
	}
	b := invoiceBase{Price: "price_base", Amount: 1200000, Months: 12, Anchor: anchor}
	filtered, err := b.stripSubscription(sub)
	if err != nil {
		t.Fatal(err)
	}
	if err = invoiceCalendarCompatible(anchor, filtered, "price_round"); err != nil {
		t.Fatal(err)
	}
	if len(sub.Items.Data) != 2 {
		t.Fatal("mutated provider evidence")
	}
	b.Amount = 120000
	if _, err = b.stripSubscription(sub); err == nil {
		t.Fatal("accepted mismatched fixed fee")
	}
}

func TestProNegativeRoundingExcludesLicensedProduct(t *testing.T) {
	var inv StripeInvoiceAmounts
	if err := json.Unmarshal([]byte(`{"id":"in_mixed","status":"draft","lines":{"data":[{"quantity":1,"amount":120000,"currency":"usd","period":{"start":100,"end":200},"pricing":{"unit_amount_decimal":"120000","price_details":{"price":"price_base","product":"prod_base"}},"parent":{"subscription_item_details":{"subscription":"sub_example"}}},{"pricing":{"price_details":{"price":"price_cpu","product":"prod_usage"}}},{"pricing":{"price_details":{"price":"price_memory","product":"prod_usage"}}}]}}`), &inv); err != nil {
		t.Fatal(err)
	}
	products, err := proRoundingProducts(inv, "price_base")
	if err != nil || len(products) != 1 || products[0] != "prod_usage" {
		t.Fatalf("rounding scope: %v %v", products, err)
	}
	var posted bool
	created := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/invoices/in_mixed":
			_ = json.NewEncoder(w).Encode(inv)
		case "/v1/coupons/rounding_in_mixed":
			if !posted {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("expand[]") != "applies_to" {
				fmt.Fprint(w, `{"id":"rounding_in_mixed","amount_off":1,"currency":"usd"}`)
				return
			}
			fmt.Fprint(w, `{"id":"rounding_in_mixed","amount_off":1,"currency":"usd","applies_to":{"products":["prod_usage"]}}`)
		case "/v1/coupons":
			_ = r.ParseForm()
			posted = true
			created++
			if r.Form.Get("expand[]") != "applies_to" {
				fmt.Fprint(w, `{"id":"rounding_in_mixed","amount_off":1,"currency":"usd"}`)
				return
			}
			if got := r.Form["applies_to[products][]"]; len(got) != 1 || got[0] != "prod_usage" {
				t.Errorf("discount reaches base product: %v", got)
			}
			fmt.Fprint(w, `{"id":"rounding_in_mixed","amount_off":1,"currency":"usd","applies_to":{"products":["prod_usage"]}}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
		}
	}))
	defer server.Close()
	c := &stripeHTTPClient{baseURL: server.URL, apiVersion: "2026-07-29.dahlia", httpClient: server.Client()}
	if err := c.applyInvoiceDiscount(t.Context(), inv.ID, 1, "rounding", products...); err != nil || !posted {
		t.Fatalf("scoped adjustment: %v", err)
	}
	if err := c.applyInvoiceDiscount(t.Context(), inv.ID, 1, "rounding", products...); err != nil || created != 1 {
		t.Fatalf("scoped coupon recovery: creates=%d err=%v", created, err)
	}
	b := invoiceBase{Price: "price_base", Amount: 120000}
	if err := b.validateLine(inv.Lines.Data[0], "sub_example", 100, 200); err != nil {
		t.Fatal(err)
	}
	inv.Lines.Data[0].PretaxCredits = []StripeInvoicePretaxCredit{{Type: "discount", Amount: 0}}
	if err := b.validateLine(inv.Lines.Data[0], "sub_example", 100, 200); err != nil {
		t.Fatalf("zero discount on excluded base: %v", err)
	}
	inv.Lines.Data[0].PretaxCredits = []StripeInvoicePretaxCredit{{Type: "discount", Amount: 1}}
	if err := b.validateLine(inv.Lines.Data[0], "sub_example", 100, 200); err == nil {
		t.Fatal("accepted rounding discount on licensed base")
	}
	inv.Lines.Data[1].Pricing.PriceDetails.Product = "prod_base"
	if _, err := proRoundingProducts(inv, "price_base"); err == nil {
		t.Fatal("accepted shared base and usage product")
	}
}

func TestProFinalUsageInvoiceDoesNotRenewBase(t *testing.T) {
	anchor := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	b := invoiceBase{Price: "price_base", Amount: 120000, Months: 1, Anchor: anchor, TerminatedAt: anchor.AddDate(0, 2, 0).Unix()}
	if amount, _, _, err := b.expectedFee(anchor.AddDate(0, 1, 0)); err != nil || amount != 120000 {
		t.Fatalf("historical renewal lost its base: %d %v", amount, err)
	}
	if amount, _, _, err := b.expectedFee(anchor.AddDate(0, 2, 0)); err != nil || amount != 0 {
		t.Fatalf("cancellation bought another term: %d %v", amount, err)
	}
}

func TestFrozenProResourceMappingsAreUnique(t *testing.T) {
	for _, duplicate := range []string{"price", "event", "meter"} {
		t.Run(duplicate, func(t *testing.T) {
			terms := []StripeCheckoutResourceTerms{
				{PriceID: "price_cpu", UnitAmountDecimal: "5", MeterID: "meter_cpu", EventName: "cpu"},
				{PriceID: "price_memory", UnitAmountDecimal: "2", MeterID: "meter_memory", EventName: "memory"},
			}
			switch duplicate {
			case "price":
				terms[1].PriceID = terms[0].PriceID
			case "event":
				terms[1].EventName = terms[0].EventName
			case "meter":
				terms[1].MeterID = terms[0].MeterID
			}
			var sub invoiceSubscription
			raw := fmt.Sprintf(`{"items":{"data":[{"price":{"id":%q,"currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":"5","recurring":{"usage_type":"metered","interval":"month","interval_count":1,"meter":%q}}},{"price":{"id":%q,"currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":"2","recurring":{"usage_type":"metered","interval":"month","interval_count":1,"meter":%q}}}]}}`, terms[0].PriceID, terms[0].MeterID, terms[1].PriceID, terms[1].MeterID)
			if err := json.Unmarshal([]byte(raw), &sub); err != nil {
				t.Fatal(err)
			}
			if err := validateFrozenProResources(sub, terms, ""); err == nil {
				t.Fatal("accepted duplicate resource mapping")
			}
		})
	}
}

func TestPendingInvoiceRoundingAcceptsOnlyTheRoundingItem(t *testing.T) {
	terms := []StripeCheckoutResourceTerms{{PriceID: "price_cpu", UnitAmountDecimal: "5", MeterID: "meter_cpu", EventName: "cpu"}}
	item := func(id, product, unit, meter string) string {
		return fmt.Sprintf(`{"price":{"id":%q,"product":%q,"active":true,"currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":%q,"recurring":{"usage_type":"metered","interval":"month","interval_count":1,"meter":%q}}}`, id, product, unit, meter)
	}
	cpu := item("price_cpu", "prod_cpu", "5", "meter_cpu")
	rounding := item("price_rounding", invoiceRoundingProduct, "1", "meter_rounding")
	for _, tc := range []struct {
		name, recorded string
		items          []string
		ok             bool
	}{
		{"pending rounding item", "", []string{cpu, rounding}, true},
		{"no rounding item yet", "", []string{cpu}, true},
		{"recorded price", "price_rounding", []string{cpu, rounding}, true},
		{"different extra item", "", []string{cpu, rounding, item("price_other", "prod_other", "1", "meter_other")}, false},
		{"extra item without rounding", "", []string{cpu, item("price_other", "prod_other", "1", "meter_other")}, false},
		{"two rounding items", "", []string{cpu, rounding, item("price_rounding_2", invoiceRoundingProduct, "1", "meter_rounding")}, false},
		{"rounding product at another amount", "", []string{cpu, item("price_rounding", invoiceRoundingProduct, "2", "meter_rounding")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sub invoiceSubscription
			if err := json.Unmarshal([]byte(`{"items":{"data":[`+strings.Join(tc.items, ",")+`]}}`), &sub); err != nil {
				t.Fatal(err)
			}
			r, err := pendingInvoiceRounding(sub, tc.recorded)
			if err == nil {
				err = validateFrozenProResources(sub, terms, r)
			}
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v, want %v (%v)", err == nil, tc.ok, err)
			}
		})
	}
}

func TestProCreditNotesRespectUsageScope(t *testing.T) {
	for _, line := range []string{"il_usage", "il_base", ""} {
		t.Run(line, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"data":[{"invoice":"in_example","customer":"cus_example","currency":"usd","status":"issued","post_payment_amount":100,"lines":{"data":[{"type":"invoice_line_item","invoice_line_item":%q}]}}]}`, line)
			}))
			defer srv.Close()
			var inv proPaidInvoice
			if err := json.Unmarshal([]byte(`{"id":"in_example","customer":"cus_example","post_payment_credit_notes_amount":100,"lines":{"data":[{"id":"il_base","pricing":{"price_details":{"price":"price_base"}}},{"id":"il_usage","pricing":{"price_details":{"price":"price_cpu"}}}]}}`), &inv); err != nil {
				t.Fatal(err)
			}
			c := &stripeHTTPClient{baseURL: srv.URL, httpClient: srv.Client(), apiVersion: "2026-07-29.dahlia"}
			err := c.verifyProCreditNotes(t.Context(), inv, "price_base")
			if (err == nil) != (line == "il_usage") {
				t.Fatalf("credit-note scope result: %v", err)
			}
		})
	}
}
