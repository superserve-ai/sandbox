package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestYCReconciliationIsolatesSlowTeams(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	slow, healthy := uuid.New(), uuid.New()
	started, refreshed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runYCReconciliationBatch(ctx, []uuid.UUID{slow, healthy}, func(work context.Context, team uuid.UUID) {
			if team == slow {
				close(started)
				<-work.Done()
				return
			}
			<-started
			if work.Err() == nil {
				close(refreshed)
			}
		})
	}()
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("slow team prevented healthy refresh")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not stop on shutdown")
	}
}

func ycTestSubscription() (invoiceSubscription, StripeCreateCheckoutSessionParams, ycApproval) {
	live := false
	in := ycApproval{Customer: "cus_pilot", Live: &live}
	sub := invoiceSubscription{ID: "sub_pilot", Customer: in.Customer, Status: "active", CollectionMethod: "charge_automatically", StartDate: time.Date(2026, 10, 16, 4, 34, 43, 0, time.UTC).Unix()}
	sub.BillingMode.Type = "flexible"
	sub.BillingCycleAnchor = sub.StartDate
	price := storagePrice{ID: "price_annual", Product: "prod_annual", Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1200000"}
	price.Recurring.Interval = "year"
	price.Recurring.IntervalCount = 1
	price.Recurring.UsageType = "licensed"
	sub.Items.Data = []invoiceSubscriptionItem{{ID: "si_annual", Quantity: 1, Price: price, Start: sub.StartDate, End: time.Unix(sub.StartDate, 0).AddDate(1, 0, 0).Unix()}}
	p := StripeCreateCheckoutSessionParams{BasePriceID: price.ID, ResourceTerms: []StripeCheckoutResourceTerms{{PriceID: "price_cpu"}, {PriceID: "price_memory"}, {PriceID: "price_storage"}}}
	return sub, p, in
}
func TestYCAnnualOnlyAdoption(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*invoiceSubscription)
		valid  bool
	}{
		{"annual-only", func(s *invoiceSubscription) {}, true},
		{"absolute-annual-cancellation", func(s *invoiceSubscription) { s.CancelAt = s.Items.Data[0].End }, true},
		{"absolute-early-cancellation", func(s *invoiceSubscription) { s.CancelAt = s.Items.Data[0].End - 1 }, false},
		{"absolute-late-cancellation", func(s *invoiceSubscription) { s.CancelAt = s.Items.Data[0].End + 1 }, false},
		{"relative-cancellation-normalized-later", func(s *invoiceSubscription) {
			s.CancelAtPeriodEnd = true
			s.CancelAt = s.StartDate + 30*24*60*60
		}, true},
		{"wrong-mode", func(s *invoiceSubscription) { s.LiveMode = true }, false},
		{"wrong-customer", func(s *invoiceSubscription) { s.Customer = "cus_other" }, false},
		{"future-discount", func(s *invoiceSubscription) { s.Discounts = []string{"di_other"} }, false},
		{"schedule", func(s *invoiceSubscription) { s.Schedule = "sched_other" }, false},
		{"wrong-price", func(s *invoiceSubscription) { s.Items.Data[0].Price.UnitAmountDecimal = "100" }, false},
		{"reset-term", func(s *invoiceSubscription) { s.Items.Data[0].Start++ }, false},
		{"partial-resource", func(s *invoiceSubscription) {
			s.Items.Data = append(s.Items.Data, invoiceSubscriptionItem{Price: storagePrice{ID: "price_cpu"}})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, in := ycTestSubscription()
			tc.mutate(&s)
			err := validateYCSubscription(s, p, in)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestYCAdoptionValidatesExistingResourceTerms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*storagePrice)
		valid  bool
	}{
		{"matching", func(p *storagePrice) {}, true},
		{"amount", func(p *storagePrice) { p.UnitAmountDecimal = "2" }, false},
		{"meter", func(p *storagePrice) { p.Recurring.Meter = "mtr_other" }, false},
		{"currency", func(p *storagePrice) { p.Currency = "eur" }, false},
		{"interval", func(p *storagePrice) { p.Recurring.Interval = "year" }, false},
		{"usage", func(p *storagePrice) { p.Recurring.UsageType = "licensed" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, params, approval := ycTestSubscription()
			for i := range params.ResourceTerms {
				term := &params.ResourceTerms[i]
				term.UnitAmountDecimal, term.MeterID, term.EventName = "1", "mtr_"+term.PriceID, term.PriceID
				price := storagePrice{ID: term.PriceID, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1"}
				price.Recurring.Interval, price.Recurring.IntervalCount = "month", 1
				price.Recurring.UsageType, price.Recurring.Meter = "metered", term.MeterID
				sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{Price: price})
			}
			tc.mutate(&sub.Items.Data[1].Price)
			if err := validateYCSubscription(sub, params, approval); (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
func TestYCPaymentMethodUsesSubscriptionOverride(t *testing.T) {
	for _, tc := range []struct {
		name, override, owner string
		ready                 bool
	}{
		{"no-card", "", "", false}, {"customer-default", "", "cus_pilot", true}, {"override-other-owner", "pm_override", "cus_other", false}, {"valid-override", "pm_override", "cus_pilot", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/customers/cus_pilot" {
					pm := "pm_default"
					if tc.name == "no-card" {
						pm = ""
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "cus_pilot", "livemode": false, "invoice_settings": map[string]any{"default_payment_method": pm}})
					return
				}
				expected := "pm_default"
				if tc.override != "" {
					expected = tc.override
				}
				if r.URL.Path != "/v1/payment_methods/"+expected {
					t.Errorf("unexpected method %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": expected, "customer": tc.owner, "livemode": false, "type": "card", "card": map[string]any{"exp_month": 12, "exp_year": time.Now().Year() + 1}})
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-05-27.dahlia", httpClient: srv.Client()}
			ready, err := client.ycPaymentMethod(t.Context(), "cus_pilot", invoiceSubscription{DefaultPaymentMethod: tc.override}, false)
			if ready != tc.ready {
				t.Fatalf("ready=%v error=%v", ready, err)
			}
		})
	}
}

func TestYCLeapDayAnniversary(t *testing.T) {
	sub, p, in := ycTestSubscription()
	anchor := time.Date(2024, 2, 29, 12, 34, 56, 0, time.UTC)
	want := time.Date(2025, 2, 28, 12, 34, 56, 0, time.UTC)
	sub.StartDate = anchor.Unix()
	sub.BillingCycleAnchor = sub.StartDate
	sub.Items.Data[0].Start = sub.StartDate
	sub.Items.Data[0].End = want.Unix()
	if !ycAnnualEnd(anchor).Equal(want) {
		t.Fatal("annual boundary did not clamp")
	}
	if err := validateYCSubscription(sub, p, in); err != nil {
		t.Fatal(err)
	}
}
