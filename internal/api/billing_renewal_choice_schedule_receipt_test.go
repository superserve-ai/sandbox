package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewalChoiceMonthlyCalendarMismatchStopsBeforeCreation(t *testing.T) {
	k, op, request, response, _ := renewalReceiptFixture(t, "monthly")
	op.Binding.Anchor = time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	k.Boundary = annualBoundary(op.Binding.Anchor, 12)
	op.Steps = nil
	if _, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: op.Binding.Anchor, Boundary: k.Boundary}); err == nil {
		t.Fatal("created a schedule for unsupported fee calendar")
	}
	// A saved older request must not be confirmed by the new verifier either.
	form, _ := url.ParseQuery(request.Form)
	form.Set("phases[0][start_date]", strconv.FormatInt(op.Binding.Anchor.Unix(), 10))
	form.Set("phases[0][end_date]", strconv.FormatInt(k.Boundary.Unix(), 10))
	form.Set("phases[1][start_date]", strconv.FormatInt(k.Boundary.Unix(), 10))
	request.Form, request.BindingHash = form.Encode(), renewalHash(op.Binding)
	op.Steps = []renewalChoiceStep{{Request: request, State: "dispatched"}}
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { writes.Add(1) }))
	defer server.Close()
	p := &renewalScheduleProvider{Client: &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: renewalStripeVersion}, Merchant: op.Binding.Merchant, Verifier: &fixtureRenewalVerifier{}, BoundaryWritesVerified: true}
	if _, err := p.DispatchStep(t.Context(), k, op, request); err == nil || writes.Load() != 0 {
		t.Fatal("saved unsupported request bypassed calendar gate", err, writes.Load())
	}
	response["current_phase"] = map[string]any{"start_date": op.Binding.Anchor.Unix(), "end_date": k.Boundary.Unix()}
	phases := response["phases"].([]any)
	phases[0].(map[string]any)["start_date"] = op.Binding.Anchor.Unix()
	phases[0].(map[string]any)["end_date"] = k.Boundary.Unix()
	phases[1].(map[string]any)["start_date"] = k.Boundary.Unix()
	phases[1].(map[string]any)["end_date"] = annualBoundary(k.Boundary, 1).Unix()
	raw, _ := json.Marshal(response)
	if _, err := verifyRenewalScheduleReceipt(k, op, request, raw, k.Boundary.Add(-time.Hour)); err == nil {
		t.Fatal("confirmed a Monthly period rejected by payment cadence")
	}
}

func renewalReceiptFixture(t *testing.T, choice string) (renewalChoiceKey, renewalChoiceOperation, renewalChoiceStepRequest, map[string]any, time.Time) {
	t.Helper()
	s, store, a := newRenewalFixture(t)
	a.monthly = true
	op := *submitRenewal(t, s, a, choice).Requested
	phase := func(start, end time.Time, price string, discounts []any) map[string]any {
		return map[string]any{"start_date": start.Unix(), "end_date": end.Unix(), "items": []any{map[string]any{"price": price, "plan": price, "quantity": 1, "discounts": []any{}, "tax_rates": []any{}, "billing_thresholds": nil, "metadata": map[string]any{}}}, "collection_method": "charge_automatically", "proration_behavior": "none", "discounts": discounts, "currency": "usd", "automatic_tax": map[string]any{"enabled": false, "liability": nil, "disabled_reason": nil}, "default_payment_method": nil, "description": nil, "metadata": map[string]any{}, "add_invoice_items": []any{}, "default_tax_rates": []any{}, "application_fee_percent": nil, "billing_cycle_anchor": nil, "billing_thresholds": nil, "invoice_settings": nil, "on_behalf_of": nil, "transfer_data": nil, "trial_end": nil}
	}
	first := phase(op.Binding.Anchor, a.key.Boundary, "price_annual", []any{map[string]any{"coupon": "coupon_once", "discount": nil, "promotion_code": nil}})
	raw, _ := json.Marshal(first)
	current, err := renewalSchedulePhaseForm(raw, "phases[0]", "charge_automatically")
	if err != nil {
		t.Fatal(err)
	}
	r, err := buildRenewalScheduleStep(a.key, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Schedule: "sub_sched_fixture", Owned: true, Anchor: op.Binding.Anchor, Boundary: a.key.Boundary, CurrentPhase: current})
	if err != nil {
		t.Fatal(err)
	}
	op.Steps = []renewalChoiceStep{{Request: r, State: "dispatched"}}
	phases := []any{first}
	endBehavior := "release"
	if choice == "monthly" {
		phases = append(phases, phase(a.key.Boundary, annualBoundary(a.key.Boundary, 1), "price_monthly", []any{}))
	} else if choice == "free" {
		endBehavior = "cancel"
	}
	response := map[string]any{"id": r.Schedule, "object": "subscription_schedule", "customer": op.Binding.Customer, "subscription": op.Binding.Fee, "livemode": op.Binding.Live, "status": "active", "billing_mode": map[string]any{"type": "flexible"}, "renewal_interval": nil, "end_behavior": endBehavior, "current_phase": map[string]any{"start_date": op.Binding.Anchor.Unix(), "end_date": a.key.Boundary.Unix()}, "phases": phases, "pause_schedules": []any{}, "default_settings": map[string]any{"collection_method": "charge_automatically", "billing_cycle_anchor": "automatic", "automatic_tax": map[string]any{"enabled": false}, "invoice_settings": map[string]any{"issuer": map[string]any{"type": "self"}}}}
	return a.key, op, r, response, store.now
}

func TestRenewalChoiceScheduleReceiptRejectsChangedTerms(t *testing.T) {
	for _, choice := range []string{"annual", "monthly", "free"} {
		t.Run(choice, func(t *testing.T) {
			k, op, r, response, now := renewalReceiptFixture(t, choice)
			raw, _ := json.Marshal(response)
			proof, err := verifyRenewalScheduleReceipt(k, op, r, raw, now)
			if err != nil || proof.Choice == nil || proof.Choice.Outcome != "confirmed" {
				t.Fatal(proof, err)
			}
			if _, err = verifyRenewalScheduleReceipt(k, op, r, raw, k.Boundary); err == nil {
				t.Fatal("late response became historical proof")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"foreign schedule":      func(r map[string]any) { r["id"] = "sub_sched_foreign" },
		"wrong fee sibling":     func(r map[string]any) { r["subscription"] = "sub_usage" },
		"current discount lost": func(r map[string]any) { r["phases"].([]any)[0].(map[string]any)["discounts"] = []any{} },
		"future discount added": func(r map[string]any) {
			r["phases"].([]any)[1].(map[string]any)["discounts"] = []any{map[string]any{"coupon": "coupon_once"}}
		},
		"unknown phase setting": func(r map[string]any) { r["phases"].([]any)[0].(map[string]any)["new_billing_setting"] = true },
		"extra fee item": func(r map[string]any) {
			p := r["phases"].([]any)[1].(map[string]any)
			p["items"] = append(p["items"].([]any), map[string]any{"price": "price_extra", "quantity": 1})
		},
		"automatic tax enabled": func(r map[string]any) {
			r["default_settings"].(map[string]any)["automatic_tax"] = map[string]any{"enabled": true}
		},
	} {
		t.Run(name, func(t *testing.T) {
			k, op, r, response, now := renewalReceiptFixture(t, "monthly")
			mutate(response)
			raw, _ := json.Marshal(response)
			if _, err := verifyRenewalScheduleReceipt(k, op, r, raw, now); err == nil {
				t.Fatal("changed provider terms confirmed")
			}
		})
	}
}

func TestRenewalChoiceScheduleTransportVerifiesResponseWithoutCallbackIO(t *testing.T) {
	k, op, r, response, _ := renewalReceiptFixture(t, "monthly")
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		writes.Add(1)
		if req.Method != http.MethodPost || req.URL.Path != r.Path {
			t.Error("unexpected provider I/O")
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	v := &fixtureRenewalVerifier{}
	p := &renewalScheduleProvider{Client: &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: renewalStripeVersion}, Merchant: op.Binding.Merchant, Verifier: v, BoundaryWritesVerified: true}
	proof, err := p.DispatchStep(t.Context(), k, op, r)
	if err != nil || writes.Load() != 1 || proof.Choice == nil {
		t.Fatal("response verification escaped pure callback", proof, err, writes.Load())
	}
	created := op
	created.Steps = nil
	create, err := buildRenewalScheduleStep(k, created, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: op.Binding.Anchor, Boundary: k.Boundary})
	if err != nil {
		t.Fatal(err)
	}
	created.Steps = []renewalChoiceStep{{Request: create, State: "dispatched"}}
	raw, _ := json.Marshal(response)
	proof, err = verifyRenewalScheduleReceipt(k, created, create, raw, time.Now().UTC())
	if err != nil || proof.Choice != nil || proof.Schedule != r.Schedule {
		t.Fatal("creation receipt confirmed choice", proof, err)
	}
}
