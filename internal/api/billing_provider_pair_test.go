package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type pairFixture struct {
	p              ProviderPairVerificationInput
	fee, usage     invoiceSubscription
	invoice        proPaidInvoice
	extra          bool
	truncated      bool
	merchant       string
	couponDuration string
	couponProducts []string
	pending        bool
	extraInvoice   bool
	requests       []string
	serve          func(http.ResponseWriter, *http.Request) bool
}

func newPairFixture(t *testing.T) *pairFixture {
	t.Helper()
	f := &pairFixture{merchant: "acct_example", couponDuration: "once"}
	f.p = ProviderPairVerificationInput{
		Identity:   ProviderPairIdentity{OperationID: uuid.New(), TeamID: uuid.New(), AssignmentID: uuid.New(), AcceptanceID: uuid.New(), ApprovalSemanticRevision: 1, TermsDigest: strings.Repeat("a", 64), Merchant: f.merchant, APIVersion: "2026-05-27.dahlia"},
		Terms:      ProviderPairTerms{FeePriceID: "price_fee", FeeProductID: "example_annual_product", FeeAmount: 1200000, Currency: "usd", FeeMonths: 12},
		CustomerID: "cus_example", FeeSubscriptionID: "sub_fee", UsageSubscriptionID: "sub_usage", FeeItemID: "si_fee", WaiverCouponID: "waiver_example", WaiverInvoiceID: "in_initial", Anchor: time.Date(2028, 1, 31, 14, 23, 45, 0, time.UTC),
	}
	f.couponProducts = []string{f.p.Terms.FeeProductID}
	for _, r := range []string{"vcpu", "memory_gib", "storage_gib"} {
		f.p.Terms.Resources = append(f.p.Terms.Resources, StripeCheckoutResourceTerms{ResourceKey: r, PriceID: "price_" + r, MeterID: "mtr_" + r, EventName: r, UnitAmountDecimal: "1"})
	}
	f.p.Terms.Rounding = StripeCheckoutResourceTerms{ResourceKey: "rounding", PriceID: "price_rounding", MeterID: "mtr_rounding", EventName: "rounding", UnitAmountDecimal: "1"}
	var err error
	f.p.Identity.ProviderTermsDigest, err = f.p.Terms.Digest()
	if err != nil {
		t.Fatal(err)
	}
	decode := func(s string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(s), v); err != nil {
			t.Fatal(err)
		}
	}
	decode(`{"id":"sub_fee","customer":"cus_example","status":"active","collection_method":"charge_automatically","billing_mode":{"type":"flexible"},"latest_invoice":"in_initial","items":{"data":[{"id":"si_fee","quantity":1,"price":{"id":"price_fee","product":"example_annual_product","active":true,"currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":"1200000","recurring":{"usage_type":"licensed","interval":"year","interval_count":1}}}]}}`, &f.fee)
	f.fee.StartDate = f.p.Anchor.Unix()
	f.fee.BillingCycleAnchor = f.p.Anchor.Unix()
	f.fee.Metadata = pairMetadata(f.p.Identity, "fee")
	f.fee.Items.Data[0].Start = f.p.Anchor.Unix()
	f.fee.Items.Data[0].End = annualBoundary(f.p.Anchor, 12).Unix()
	decode(`{"id":"sub_usage","customer":"cus_example","status":"active","collection_method":"charge_automatically","billing_mode":{"type":"flexible"},"pause_collection":{"behavior":"keep_as_draft"}}`, &f.usage)
	f.usage.StartDate = f.p.Anchor.Unix()
	f.usage.BillingCycleAnchor = f.p.Anchor.Unix()
	f.usage.Metadata = pairMetadata(f.p.Identity, "usage")
	for _, r := range append(append([]StripeCheckoutResourceTerms{}, f.p.Terms.Resources...), f.p.Terms.Rounding) {
		var item invoiceSubscriptionItem
		decode(`{"price":{"active":true,"currency":"usd","billing_scheme":"per_unit","unit_amount_decimal":"1","recurring":{"usage_type":"metered","interval":"month","interval_count":1}}}`, &item)
		item.ID = "si_" + r.ResourceKey
		item.Price.ID = r.PriceID
		item.Price.Product = "prod_" + r.ResourceKey
		item.Price.Recurring.Meter = r.MeterID
		item.Start = f.p.Anchor.Unix()
		item.End = annualBoundary(f.p.Anchor, 1).Unix()
		f.usage.Items.Data = append(f.usage.Items.Data, item)
	}
	decode(`{"id":"in_initial","customer":"cus_example","currency":"usd","status":"paid","billing_reason":"subscription_create","subtotal":1200000,"ending_balance":0,"amount_remaining":0,"parent":{"subscription_details":{"subscription":"sub_fee"}},"discounts":[{"id":"di_waiver","source":{"coupon":"waiver_example"}}],"total_discount_amounts":[{"amount":1200000}],"lines":{"data":[{"id":"il_fee","amount":1200000,"currency":"usd","quantity":1,"pricing":{"price_details":{"price":"price_fee","product":"example_annual_product"}},"parent":{"subscription_item_details":{"subscription":"sub_fee","subscription_item":"si_fee","proration":false}}}]}}`, &f.invoice)
	f.invoice.Lines.Data[0].Period.Start = f.p.Anchor.Unix()
	f.invoice.Lines.Data[0].Period.End = annualBoundary(f.p.Anchor, 12).Unix()
	suffix := uuid.NewString()
	f.p.CustomerID = "cus_" + suffix
	f.p.FeeSubscriptionID = "sub_fee_" + suffix
	f.p.UsageSubscriptionID = "sub_usage_" + suffix
	f.p.WaiverInvoiceID = "in_" + suffix
	f.fee.ID = f.p.FeeSubscriptionID
	f.fee.Customer = f.p.CustomerID
	f.fee.LatestInvoice = f.p.WaiverInvoiceID
	f.usage.ID = f.p.UsageSubscriptionID
	f.usage.Customer = f.p.CustomerID
	f.invoice.ID = f.p.WaiverInvoiceID
	f.invoice.Customer = f.p.CustomerID
	f.invoice.Parent.SubscriptionDetails.Subscription = f.p.FeeSubscriptionID
	f.invoice.Lines.Data[0].Parent.SubscriptionItemDetails.Subscription = f.p.FeeSubscriptionID
	return f
}

func (f *pairFixture) client(t *testing.T) *stripeHTTPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		if f.serve != nil && f.serve(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("verification attempted mutation: %s", r.Method)
			http.Error(w, "read only", 405)
			return
		}
		if r.Header.Get("Stripe-Version") != f.p.Identity.APIVersion {
			t.Error("API version not pinned")
		}
		var value any
		switch r.URL.Path {
		case "/v1/account":
			value = map[string]any{"id": f.merchant}
		case "/v1/customers/" + f.p.CustomerID:
			value = map[string]any{"id": f.p.CustomerID, "livemode": f.p.Identity.Live, "metadata": pairMetadata(f.p.Identity, "customer")}
		case "/v1/subscriptions/" + f.p.FeeSubscriptionID:
			value = f.fee
		case "/v1/subscriptions/" + f.p.UsageSubscriptionID:
			value = f.usage
		case "/v1/prices/price_fee":
			value = f.fee.Items.Data[0].Price
		case "/v1/prices/price_vcpu", "/v1/prices/price_memory_gib", "/v1/prices/price_storage_gib", "/v1/prices/price_rounding":
			for _, item := range f.usage.Items.Data {
				if item.Price.ID == strings.TrimPrefix(r.URL.Path, "/v1/prices/") {
					value = item.Price
				}
			}
		case "/v1/subscriptions":
			if r.URL.Query().Get("customer") != f.p.CustomerID || r.URL.Query().Get("status") != "all" {
				t.Error("inventory not scoped")
			}
			list := []invoiceSubscription{f.fee, f.usage}
			if f.extra {
				other := f.usage
				other.ID = "sub_other"
				list = append(list, other)
			}
			value = map[string]any{"data": list, "has_more": f.truncated}
		case "/v1/billing/meters":
			meters := []any{}
			for _, term := range append(append([]StripeCheckoutResourceTerms{}, f.p.Terms.Resources...), f.p.Terms.Rounding) {
				meters = append(meters, map[string]any{"id": term.MeterID, "event_name": term.EventName, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
			}
			value = map[string]any{"data": meters}
		case "/v1/coupons/waiver_example":
			coupon := map[string]any{"id": f.p.WaiverCouponID, "duration": f.couponDuration, "percent_off": json.RawMessage(`100.0`), "livemode": f.p.Identity.Live, "metadata": pairMetadata(f.p.Identity, "waiver")}
			for _, field := range r.URL.Query()["expand[]"] {
				if field == "applies_to" {
					coupon["applies_to"] = map[string]any{"products": f.couponProducts}
				}
			}
			value = coupon
		case "/v1/invoices/" + f.p.WaiverInvoiceID:
			value = f.invoice
		case "/v1/invoiceitems":
			if r.URL.Query().Get("pending") != "true" || r.URL.Query().Get("customer") != f.p.CustomerID {
				t.Error("pending items not scoped")
			}
			items := []any{}
			if f.pending {
				items = append(items, map[string]any{"id": "ii_pending", "amount": 1200000})
			}
			value = map[string]any{"data": items}
		case "/v1/invoices":
			invoices := []proPaidInvoice{f.invoice}
			if r.URL.Query().Get("subscription") == f.p.UsageSubscriptionID {
				invoices = nil
			}
			if f.extraInvoice {
				other := f.invoice
				other.ID = "in_other"
				invoices = append(invoices, other)
			}
			value = map[string]any{"data": invoices}
		case "/v1/billing/credit_grants":
			value = map[string]any{"data": []any{}}
		case "/v1/invoice_payments":
			value = map[string]any{"data": []any{map[string]any{"id": "ip_example", "invoice": f.invoice.ID, "status": "paid", "currency": "usd", "amount_paid": f.invoice.AmountPaid, "payment": map[string]any{"type": "payment_intent", "payment_intent": "pi_example"}}}}
		case "/v1/payment_intents/pi_example":
			value = map[string]any{"id": "pi_example", "customer": f.p.CustomerID, "status": "succeeded", "currency": "usd", "amount_received": f.invoice.AmountPaid, "latest_charge": "ch_example"}
		case "/v1/charges/ch_example":
			value = map[string]any{"id": "ch_example", "customer": f.p.CustomerID, "currency": "usd", "payment_intent": "pi_example", "paid": true, "captured": true, "amount_captured": f.invoice.AmountPaid}
		default:
			t.Errorf("unexpected provider read %s", r.URL.String())
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return &stripeHTTPClient{baseURL: srv.URL, httpClient: srv.Client(), apiVersion: f.p.Identity.APIVersion}
}

func TestProviderPairCollectionSeparatesLicensedFee(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pairFixture)
	}{
		{"annual", nil},
		{"monthly successor licensed only", func(f *pairFixture) {
			f.fee.Items.Data[0].Price.ID = "price_monthly"
			f.fee.Items.Data[0].Price.UnitAmountDecimal = "120000"
			f.fee.Items.Data[0].Price.Recurring.Interval = "month"
		}},
		{"extra fee meter", func(f *pairFixture) { f.fee.Items.Data = append(f.fee.Items.Data, f.usage.Items.Data[0]) }},
		{"missing hold", func(f *pairFixture) { f.usage.PauseCollection = nil }},
		{"extra customer subscription", func(f *pairFixture) { f.extra = true }},
		{"changed usage price", func(f *pairFixture) { f.usage.Items.Data[0].Price.UnitAmountDecimal = "99" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPairFixture(t)
			if tc.change != nil {
				tc.change(f)
			}
			b := ContractProviderBinding{Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeSubscriptionID: f.p.FeeSubscriptionID, Anchor: f.p.Anchor, FeeAnchor: f.p.Anchor}
			a := invoiceAccount{Pair: &b, Customer: b.CustomerID, Subscription: b.UsageSubscriptionID, Price: b.Terms.Rounding.PriceID, Meter: b.Terms.Rounding.MeterID, Event: b.Terms.Rounding.EventName}
			got, err := f.client(t).ensureInvoiceSubscription(t.Context(), a, true, false)
			valid := tc.name == "annual" || tc.name == "monthly successor licensed only"
			if !valid {
				if err == nil {
					t.Fatal("unsafe credit-consuming inventory accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			amount, _, _, err := got.Base.expectedFee(annualBoundary(f.p.Anchor, 12))
			if err != nil || amount != 0 {
				t.Fatalf("usage collection injected fee: %d %v", amount, err)
			}
		})
	}
}

func TestProviderPairPinnedPricePreflight(t *testing.T) {
	for _, changed := range []bool{false, true} {
		f := newPairFixture(t)
		if changed {
			f.usage.Items.Data[0].Price.UnitAmountDecimal = "2"
		}
		h := Handlers{Stripe: f.client(t)}
		err := h.VerifyProviderPairTerms(t.Context(), f.p.Identity, f.p.Terms)
		if !changed && err != nil {
			t.Fatal(err)
		}
		if changed && err == nil {
			t.Fatal("changed provider price accepted")
		}
	}
}

func TestProviderPairVerification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pairFixture)
	}{
		{"valid", nil},
		{"wrong merchant", func(f *pairFixture) { f.merchant = "acct_other" }},
		{"wrong fee item", func(f *pairFixture) { f.fee.Items.Data[0].ID = "si_other" }},
		{"different usage anchor", func(f *pairFixture) { f.usage.StartDate++ }},
		{"missing hold", func(f *pairFixture) { f.usage.PauseCollection = nil }},
		{"hold expires", func(f *pairFixture) { f.usage.PauseCollection.ResumesAt = f.p.Anchor.Unix() + 1 }},
		{"extra subscription", func(f *pairFixture) { f.extra = true }},
		{"incomplete inventory", func(f *pairFixture) { f.truncated = true }},
		{"changed resource price", func(f *pairFixture) { f.usage.Items.Data[0].Price.UnitAmountDecimal = "2" }},
		{"fee consumes metered credits", func(f *pairFixture) { f.fee.Items.Data[0].Price.Recurring.Meter = "mtr_fee" }},
		{"missing coupon restriction", func(f *pairFixture) { f.couponProducts = nil }},
		{"wrong coupon product", func(f *pairFixture) { f.couponProducts = []string{"prod_other"} }},
		{"extra coupon product", func(f *pairFixture) { f.couponProducts = append(f.couponProducts, "prod_other") }},
		{"repeat waiver", func(f *pairFixture) { f.couponDuration = "forever" }},
		{"replacement recurring discount", func(f *pairFixture) { f.fee.Discounts = []string{"di_forever"} }},
		{"manual tax", func(f *pairFixture) { f.fee.DefaultTaxRates = []json.RawMessage{json.RawMessage(`"txr_tax"`)} }},
		{"item discount", func(f *pairFixture) {
			f.fee.Items.Data[0].Discounts = []json.RawMessage{json.RawMessage(`"di_forever"`)}
		}},
		{"pending adjustment", func(f *pairFixture) { f.pending = true }},
		{"extra fee obligation", func(f *pairFixture) { f.extraInvoice = true }},
		{"credit funded fee", func(f *pairFixture) {
			f.invoice.PretaxCredits = []StripeInvoicePretaxCredit{{Type: "credit_balance_transaction", Amount: 1200000, CreditBalanceTransaction: "cbtxn_example"}}
		}},
		{"cash is not waiver", func(f *pairFixture) { f.invoice.AmountPaid = 1200000 }},
		{"wrong invoice parent", func(f *pairFixture) { f.invoice.Parent.SubscriptionDetails.Subscription = f.p.UsageSubscriptionID }},
		{"wrong invoice window", func(f *pairFixture) { f.invoice.Lines.Data[0].Period.End++ }},
		{"foreign operation", func(f *pairFixture) { f.fee.Metadata["operation_id"] = uuid.NewString() }},
		{"changed pinned terms", func(f *pairFixture) { f.p.Terms.Resources[0].PriceID = "price_new" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPairFixture(t)
			if tc.change != nil {
				tc.change(f)
			}
			got, err := f.client(t).verifyInitialProviderPair(t.Context(), f.p)
			if tc.change == nil {
				if err != nil {
					t.Fatal(err)
				}
				if got.seal == ([32]byte{}) || got.seal != pairSeal(got) {
					t.Fatal("missing verification evidence")
				}
				got.Input.FeeItemID = "si_replaced"
				if got.seal == pairSeal(got) {
					t.Fatal("mutable verification accepted")
				}
			} else if err == nil {
				t.Fatal("unsafe pair accepted")
			}
		})
	}
}

func TestProviderPairPaymentRequiresExactCashSibling(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pairFixture, *ContractProviderBinding)
	}{
		{"paid", nil},
		{"waived", func(f *pairFixture, b *ContractProviderBinding) {
			f.invoice.AmountPaid = 0
			f.invoice.AmountDue = 0
			f.invoice.Total = 0
		}},
		{"usage invoice", func(f *pairFixture, b *ContractProviderBinding) {
			f.invoice.Parent.SubscriptionDetails.Subscription = b.UsageSubscriptionID
		}},
		{"wrong item", func(f *pairFixture, b *ContractProviderBinding) {
			f.invoice.Lines.Data[0].Parent.SubscriptionItemDetails.SubscriptionItem = "si_old"
		}},
		{"wrong period", func(f *pairFixture, b *ContractProviderBinding) { f.invoice.Lines.Data[0].Period.Start++ }},
		{"cash shortfall", func(f *pairFixture, b *ContractProviderBinding) { f.invoice.AmountPaid-- }},
		{"wrong merchant", func(f *pairFixture, b *ContractProviderBinding) { f.merchant = "acct_other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPairFixture(t)
			f.invoice.Discounts = nil
			f.invoice.DiscountAmounts = nil
			f.invoice.Total = 1200000
			f.invoice.AmountPaid = 1200000
			f.invoice.AmountDue = 1200000
			f.invoice.StatusTransitions.PaidAt = f.p.Anchor.Unix() + 1
			end := annualBoundary(f.p.Anchor, 12)
			b := ContractProviderBinding{ContractID: uuid.New(), Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeSubscriptionID: f.p.FeeSubscriptionID, FeeItemID: f.p.FeeItemID, Anchor: f.p.Anchor, FeeAnchor: f.p.Anchor, StartsAt: f.p.Anchor, EndsAt: &end}
			if tc.change != nil {
				tc.change(f, &b)
			}
			_, err := f.client(t).verifyProviderPairPayment(t.Context(), b, f.invoice.ID)
			if tc.change == nil && err != nil {
				t.Fatal(err)
			}
			if tc.change != nil && err == nil {
				t.Fatal("invalid cash evidence accepted")
			}
		})
	}
}
