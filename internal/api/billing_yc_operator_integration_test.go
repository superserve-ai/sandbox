//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestYCOperatorAnnualOnlyAdoption(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint("depleted-grant-", existing), func(t *testing.T) { runYCOperatorAdoption(t, existing, "card") })
	}
}
func TestYCOperatorComputeOnlyCredits(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) { runYCOperatorAdoption(t, existing, "card", false, true) })
	}
}

var ycOperatorPlanPrices map[string]string

// Repricing Pro annual moves catalog checkout to a new Stripe price; YC keeps
// STRIPE_PRO_ANNUAL_PRICE_ID at the fixed YC amount.
func TestYCOperatorAdoptionIgnoresPlanCatalogRepricing(t *testing.T) {
	fixture := newEntitlementFixture(t, true, true)
	if _, err := fixture.h.Pool.Exec(t.Context(), `UPDATE billing_plan SET charge_amount_cents=1500000 WHERE offer_key='pro_annual'`); err != nil {
		t.Fatal(err)
	}
	ycOperatorPlanPrices = map[string]string{"pro_annual": "price_pro_annual_repriced"}
	t.Cleanup(func() {
		ycOperatorPlanPrices = nil
		if _, err := fixture.h.Pool.Exec(context.Background(), `UPDATE billing_plan SET charge_amount_cents=1200000 WHERE offer_key='pro_annual'`); err != nil {
			t.Error(err)
		}
	})
	runYCOperatorAdoption(t, false, "card")
}

func TestYCOperatorLinkAdoption(t *testing.T) { runYCOperatorAdoption(t, true, "link") }

func TestYCOperatorLinkCreatesSubscriptionOnce(t *testing.T) {
	runYCOperatorAdoption(t, false, "link", true)
}

func TestYCOperatorCalendarRecoveryBeforeBillingChecks(t *testing.T) {
	for _, state := range []string{"provider_pending", "enrolling", "active", "renewed", "renewal_pending", "ended"} {
		renewal := state == "renewed" || state == "renewal_pending" || state == "ended"
		for _, failure := range []string{"missing", "unavailable", "invoice-unavailable"} {
			for _, conflict := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/conflict-%t", state, failure, conflict), func(t *testing.T) {
					runYCOperatorAdoptionWithRecoveryFailure(t, false, "card", failure, state, false, true, true, conflict, renewal)
				})
			}
		}
	}
}

func TestYCOperatorEndedCalendarRecovery(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprint(conflict), func(t *testing.T) {
			runYCOperatorAdoptionWithRecoveryFailure(t, false, "card", "", "ended", false, true, true, conflict, true)
		})
	}
}

func runYCOperatorAdoption(t *testing.T, existing bool, methodType string, create ...bool) {
	runYCOperatorAdoptionWithRecoveryFailure(t, existing, methodType, "", "", create...)
}

func runYCOperatorAdoptionWithRecoveryFailure(t *testing.T, existing bool, methodType, recoveryFailure, recoveryState string, create ...bool) {
	computeOnly := len(create) > 1 && create[1]
	newSubscription := len(create) > 0 && create[0]
	subscriptionCreated := !newSubscription
	subscriptionWrites := 0
	fixture := newEntitlementFixture(t, true, true)
	h := fixture.h
	team, err := h.DB.CreateTeam(t.Context(), "yc-operator-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Pool.Exec(t.Context(), `UPDATE team SET home_region='use' WHERE id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	customer := "cus_" + team.ID.String()
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, team.ID, customer); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	anchor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	renewalPending := len(create) > 4 && create[4]
	if renewalPending {
		anchor = anchor.AddDate(-1, -1, 0)
	}
	legacy := len(create) > 1 && create[1]
	if legacy {
		if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team.ID, anchor.AddDate(0, 0, -13), anchor.AddDate(0, 0, 18)); err != nil {
			t.Fatal(err)
		}
	}
	sub, p, in := ycTestSubscription()
	sub.ID = "sub_" + team.ID.String()
	sub.Customer = customer
	sub.StartDate = anchor.Unix()
	sub.BillingCycleAnchor = sub.StartDate
	sub.LatestInvoice = "in_first"
	sub.Items.Data[0].Start = sub.StartDate
	sub.Items.Data[0].End = ycAnnualEnd(anchor).Unix()
	sub.Items.Data[0].Price.Active = true
	p.ResourceTerms = nil
	h.Config = &config.Config{TeamCreationRegion: "use", StripeProAnnualPriceID: p.BasePriceID, StripePlanPriceIDs: ycOperatorPlanPrices, BillingUsageEntitlementsEnabled: true}
	prices := map[string]storagePrice{p.BasePriceID: sub.Items.Data[0].Price}
	rates, err := h.DB.ListActivePricingRatesForTeam(t.Context(), db.ListActivePricingRatesForTeamParams{TeamID: team.ID, EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"vcpu", "memory_gib", "storage_gib"}
	if computeOnly {
		keys = keys[:2]
	}
	for _, key := range keys {
		id := "price_" + key
		h.Config.BillingResources = append(h.Config.BillingResources, config.BillingResourceConfig{ResourceKey: key, UsageUnit: "second", StripePriceID: id, StripeEventName: key, Tracked: true, Billable: true, CheckoutEnabled: true})
		amount := ""
		for _, rate := range rates {
			if rate.Resource == key && rate.Unit == "second" {
				v, _ := rate.PriceUsd.Value()
				r, ok := new(big.Rat).SetString(fmt.Sprint(v))
				if !ok {
					t.Fatal("rate")
				}
				amount = new(big.Rat).Mul(r, big.NewRat(360000, 1)).FloatString(12)
			}
		}
		if amount == "" {
			t.Fatal("missing rate", key)
		}
		price := storagePrice{ID: id, Product: "prod_" + key, Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: amount}
		price.Recurring.UsageType = "metered"
		price.Recurring.Interval = "month"
		price.Recurring.IntervalCount = 1
		price.Recurring.Meter = "mtr_" + key
		prices[id] = price
	}
	rounding := storagePrice{ID: "price_round", Product: invoiceRoundingProduct, Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1"}
	rounding.Recurring.UsageType = "metered"
	rounding.Recurring.Interval = "month"
	rounding.Recurring.IntervalCount = 1
	rounding.Recurring.Meter = "mtr_round"
	prices[rounding.ID] = rounding
	grant := testEntitlementGrant()
	grant.ID = "credgr_" + team.ID.String()
	grant.Customer = customer
	grant.Amount.Monetary.Value = 3000000
	grant.Created = now.Unix() - 1
	grant.EffectiveAt = grant.Created
	grant.ExpiresAt = anchor.AddDate(0, 1, 0).Unix() + 1
	grant.Metadata = nil
	grant.Applicability.Scope.Prices = grant.Applicability.Scope.Prices[:len(keys)+1]
	for i, key := range append(append([]string{}, keys...), "round") {
		grant.Applicability.Scope.Prices[i].ID = "price_" + key
	}
	card := false
	methodUnavailable := false
	invoiceUnavailable := false
	setupReady := false
	methodOwner := "acct_customer"
	writes := 0
	grantWrites := 0
	issued := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		output := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.Method == http.MethodPost {
			writes++
			_ = r.ParseForm()
		}
		switch {
		case r.URL.Path == "/v1/account":
			output(map[string]any{"id": "acct_fixture"})
		case r.URL.Path == "/v1/customers/"+customer:
			pm := ""
			if card {
				pm = "pm_card"
			}
			output(map[string]any{"id": customer, "livemode": false, "customer_account": "acct_customer", "invoice_settings": map[string]any{"default_payment_method": pm}})
		case r.URL.Path == "/v1/payment_methods/pm_card":
			if methodUnavailable {
				http.Error(w, "payment lookup unavailable", http.StatusServiceUnavailable)
				return
			}
			method := map[string]any{"id": "pm_card", "customer_account": methodOwner, "livemode": false, "type": methodType}
			if methodType == "card" {
				method["card"] = map[string]any{"exp_month": 12, "exp_year": now.Year() + 2}
			}
			output(method)
		case r.URL.Path == "/v1/setup_intents":
			status := "requires_action"
			if setupReady {
				status = "succeeded"
			}
			output(map[string]any{"data": []any{map[string]any{"id": "seti_fixture", "customer_account": methodOwner, "livemode": false, "payment_method": "pm_card", "status": status, "usage": "off_session"}}})
		case r.URL.Path == "/v1/invoices/in_first":
			if invoiceUnavailable {
				http.Error(w, "invoice lookup unavailable", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprintf(w, `{"id":"in_first","customer":%q,"status":"paid","currency":"usd","subtotal":1200000,"total":0,"amount_due":0,"amount_paid":0,"amount_remaining":0,"starting_balance":0,"ending_balance":0,"total_discount_amounts":[{"amount":1200000}],"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"amount":1200000,"currency":"usd","quantity":1,"period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":%q}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, customer, sub.ID, sub.StartDate, sub.Items.Data[0].End, p.BasePriceID, sub.ID)
		case strings.HasPrefix(r.URL.Path, "/v1/coupons/"):
			coupon := map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/coupons/"), "duration": "once", "percent_off": 100}
			if r.URL.Query().Get("expand[]") == "applies_to" {
				coupon["applies_to"] = map[string]any{"products": []string{sub.Items.Data[0].Price.Product}}
			}
			output(coupon)
		case r.URL.Path == "/v1/subscriptions":
			if r.Method == http.MethodPost {
				subscriptionWrites++
				operation := r.Form.Get("metadata[yc_operation]")
				if operation == "" || r.Header.Get("Idempotency-Key") != "yc-subscription:"+operation || r.Form.Get("collection_method") != "charge_automatically" {
					t.Error("subscription creation lost durable authority")
				}
				subscriptionCreated = true
				sub.Metadata = map[string]string{"yc_operation": operation}
				output(sub)
			} else if subscriptionCreated {
				output(map[string]any{"data": []invoiceSubscription{sub}})
			} else {
				output(map[string]any{"data": []invoiceSubscription{}})
			}
		case r.URL.Path == "/v1/subscriptions/"+sub.ID:
			if r.Method == http.MethodPost {
				if r.Form.Has("metadata[yc_usage_attached]") {
					if sub.Metadata == nil {
						sub.Metadata = map[string]string{}
					}
					sub.Metadata["yc_usage_attached"] = r.Form.Get("metadata[yc_usage_attached]")
					for i := 0; i < 3; i++ {
						id := r.Form.Get(fmt.Sprintf("items[%d][price]", i))
						if id == "" {
							break
						}
						sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{ID: "si_" + id, Price: prices[id], Start: anchor.Unix(), End: anchor.AddDate(0, 1, 0).Unix()})
					}
					if r.Form.Get("proration_behavior") != "none" {
						t.Error("unexpected proration")
					}
				}
				if r.Form.Has("pause_collection[behavior]") {
					sub.PauseCollection = &struct {
						Behavior  string `json:"behavior"`
						ResumesAt int64  `json:"resumes_at"`
					}{Behavior: "keep_as_draft"}
				}
			}
			output(sub)
		case r.URL.Path == "/v1/subscription_items":
			item := invoiceSubscriptionItem{ID: "si_round", Price: rounding, Start: anchor.Unix(), End: anchor.AddDate(0, 1, 0).Unix()}
			sub.Items.Data = append(sub.Items.Data, item)
			output(item)
		case r.URL.Path == "/v1/prices":
			output(map[string]any{"data": []storagePrice{rounding}})
		case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
			output(prices[strings.TrimPrefix(r.URL.Path, "/v1/prices/")])
		case r.URL.Path == "/v1/billing/meters":
			meters := []any{}
			for _, key := range []string{"vcpu", "memory_gib", "storage_gib", "round"} {
				event := key
				if key == "round" {
					event = invoiceRoundingEvent
				}
				meters = append(meters, map[string]any{"id": "mtr_" + key, "event_name": event, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
			}
			output(map[string]any{"data": meters})
		case r.URL.Path == "/v1/billing/credit_grants":
			if r.Method == http.MethodPost {
				grantWrites++
				grant.Metadata = map[string]string{"entitlement_id": r.Form.Get("metadata[entitlement_id]")}
				grant.Amount.Monetary.Value, _ = strconv.ParseInt(r.Form.Get("amount[monetary][value]"), 10, 64)
				grant.Created = time.Now().Unix()
				grant.EffectiveAt = grant.Created
				for i := range grant.Applicability.Scope.Prices {
					grant.Applicability.Scope.Prices[i].ID = r.Form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i))
				}
				issued = true
				http.Error(w, "lost response", 503)
				return
			}
			grants := []entitlementGrant{}
			if existing || issued {
				grants = append(grants, grant)
			}
			output(map[string]any{"data": grants})
		case r.URL.Path == "/v1/billing/credit_grants/"+grant.ID:
			output(grant)
		case r.URL.Path == "/v1/billing/credit_balance_summary":
			output(map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": 0}}}}})
		case r.URL.Path == "/v1/invoices" || r.URL.Path == "/v1/billing/credit_balance_transactions":
			output(map[string]any{"data": []any{}})
		default:
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer srv.Close()
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	in.CompanyIdentity = "https://www.ycombinator.com/companies/fixture-" + team.ID.String()
	in.Merchant = "acct_fixture"
	in.Region = "use"
	in.Customer = customer
	in.Subscription = sub.ID
	in.ExistingSubscriptionApproved = true
	if newSubscription {
		in.Subscription = ""
		in.ExistingSubscriptionApproved = false
	}
	in.SignupEmail = "founder@example.com"
	in.FounderEmail = in.SignupEmail
	in.Evidence = "operator-fixture"
	if existing {
		in.ExistingGrantID = grant.ID
	}
	approve := func() {
		t.Helper()
		raw, _ := json.Marshal(in)
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Params = gin.Params{{Key: "team_id", Value: team.ID.String()}}
		c.Set("actor_id", uuid.New())
		c.Request = httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader(raw))
		c.Request.Header.Set("Content-Type", "application/json")
		h.YCApprove(c)
		if rec.Code != 200 {
			t.Fatalf("approval: %d %s", rec.Code, rec.Body)
		}
	}
	approve()
	approve()
	if writes != 0 {
		t.Fatal("approval wrote provider state")
	}
	if err = h.reconcileYC(t.Context(), team.ID); err == nil || !strings.Contains(err.Error(), "payment_method_required") {
		t.Fatal("expected pending card", err)
	}
	eligible, err := h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
	if err != nil || eligible {
		t.Fatal("usage before card", err)
	}
	card = true
	if methodType == "link" {
		if err = h.reconcileYC(t.Context(), team.ID); err == nil {
			t.Fatal("pending Link setup activated")
		}
		if eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID); err != nil || eligible {
			t.Fatal("pending Link enabled usage", err)
		}
	}
	setupReady = true
	if len(create) > 2 && create[2] {
		// Model an older worker's completed operation before transition receipts
		// existed, retaining its contract, waiver, enrollment and anniversary.
		if _, err = h.Pool.Exec(t.Context(), `UPDATE billing_yc_operation SET starts_at=$2,ends_at=$3 WHERE team_id=$1`, team.ID, anchor, ycAnnualEnd(anchor)); err != nil {
			t.Fatal(err)
		}
		o, err := h.ycOperation(t.Context(), team.ID)
		if err != nil {
			t.Fatal(err)
		}
		f := &ycCalendarFixture{h: h, o: o}
		if recoveryState != "provider_pending" {
			f.savePartial(t)
		}
		state := "active"
		if renewalPending {
			state = "renewal_pending"
		}
		if recoveryState != "" {
			state = recoveryState
		}
		f.exec(t, `UPDATE billing_yc_operation SET state=$2 WHERE team_id=$1`, team.ID, state)
		if state == "ended" {
			sub.Status = "canceled"
		}
		conflict := len(create) > 3 && create[3]
		if conflict {
			f.exec(t, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,12)`, team.ID, anchor.AddDate(0, 0, -13), anchor.AddDate(0, 0, 18))
		}
		anchorChanged := len(create) > 5 && create[5]
		if anchorChanged {
			sub.BillingCycleAnchor += 3600
		}
		card = recoveryFailure != "missing"
		methodUnavailable = recoveryFailure == "unavailable"
		invoiceUnavailable = recoveryFailure == "invoice-unavailable"
		var before []byte
		if err = h.Pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT to_jsonb(w) FROM billing_contract_waiver w WHERE team_id=$1),'null'::jsonb)`, team.ID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			err = h.reconcileYC(t.Context(), team.ID)
			wantError := ""
			if recoveryFailure == "missing" {
				wantError = "payment_method_required"
			} else if recoveryFailure == "unavailable" {
				wantError = "payment lookup unavailable"
			} else if recoveryFailure == "invoice-unavailable" {
				wantError = "invoice lookup unavailable"
			}
			if conflict {
				wantError = "yc_calendar_conflict"
			}
			if anchorChanged {
				wantError = "anniversary changed"
			}
			if (wantError != "" && (err == nil || !strings.Contains(err.Error(), wantError))) || (wantError == "" && err != nil) {
				t.Fatal("pre-rollout active operation", err)
			}
		}
		var preserved, reconciled bool
		if err = h.Pool.QueryRow(t.Context(), `SELECT COALESCE((SELECT to_jsonb(w) FROM billing_contract_waiver w WHERE team_id=$1),'null'::jsonb)=$2::jsonb,EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE team_id=$1)`, team.ID, before).Scan(&preserved, &reconciled); err != nil || !preserved || reconciled == (conflict || anchorChanged) {
			t.Fatal("active recovery lost authority or completion evidence", err)
		}
		if anchorChanged {
			var unchanged bool
			if err = h.Pool.QueryRow(t.Context(), `SELECT count(*)=1 AND bool_and(period_start=$2 AND period_end=$3) FROM team_billing_period WHERE team_id=$1`, team.ID, anchor.AddDate(0, 0, -13), anchor.AddDate(0, 0, 18)).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("provider drift changed calendar", err)
			}
		}
		if recoveryFailure != "" {
			if recoveryFailure != "invoice-unavailable" {
				eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
				if err != nil || eligible {
					t.Fatal("calendar recovery bypassed payment readiness", err)
				}
			}
			var retained bool
			end := anchor
			if conflict {
				end = anchor.AddDate(0, 0, 18)
			}
			if err = h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='open')`, team.ID, anchor.AddDate(0, 0, -13), end).Scan(&retained); err != nil || !retained {
				t.Fatal("readiness failure lost historical interval", err)
			}
		}
		if state == "provider_pending" {
			var unadopted bool
			if err = h.Pool.QueryRow(t.Context(), `SELECT o.state='provider_pending' AND a.stripe_subscription_id IS NULL AND a.commercial_billing_anchor IS NULL AND NOT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE id=o.contract_id) FROM billing_yc_operation o JOIN team_billing_account a USING(team_id) WHERE o.team_id=$1`, team.ID).Scan(&unadopted); err != nil || !unadopted {
				t.Fatal("calendar recovery prematurely adopted contract", err)
			}
		}
		if state == "ended" {
			current, err := h.ycOperation(t.Context(), team.ID)
			if err != nil || current.State != "ended" || current.Subscription != sub.ID || sub.Status != "canceled" {
				t.Fatal("calendar recovery reactivated ended subscription", err)
			}
		}
		if writes != 0 {
			t.Fatal("calendar recovery changed provider state")
		}
		return
	}
	for i := 0; i < 3; i++ {
		err = h.reconcileYC(t.Context(), team.ID)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal("activation", err)
	}
	o, err := h.ycOperation(t.Context(), team.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o.State != "active" || o.Subscription != sub.ID || !o.Start.Time.Equal(anchor) || !o.End.Time.Equal(ycAnnualEnd(anchor)) {
		t.Fatal("activation reset identity or term", o.State)
	}
	if legacy {
		var retained bool
		if err = h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='open') AND EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE team_id=$1)`, team.ID, anchor.AddDate(0, 0, -13), anchor).Scan(&retained); err != nil || !retained {
			t.Fatal("legacy interval not retained", err)
		}
	}
	eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
	if err != nil || !eligible {
		t.Fatal("usage after card", err)
	}
	if len(sub.Items.Data) != len(keys)+2 {
		t.Fatalf("duplicated or missing resources: %d", len(sub.Items.Data))
	}
	if err = h.reconcileYC(t.Context(), team.ID); err != nil {
		t.Fatal("repeat activation", err)
	}
	if newSubscription && subscriptionWrites != 1 {
		t.Fatalf("created %d subscriptions", subscriptionWrites)
	}
	if !existing {
		before, _ := json.Marshal(o)
		if _, err = h.reconcileUsageEntitlement(t.Context(), o.Contract); err == nil {
			t.Fatal("expected lost response")
		}
		for i := 0; i < 2; i++ {
			if _, err = h.reconcileUsageEntitlement(t.Context(), o.Contract); err != nil {
				t.Fatal(err)
			}
		}
		e, eerr := h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: team.ID, Kind: "metered_usage"})
		if eerr != nil || e.State != "issued" || grantWrites != 1 || grant.Amount.Monetary.Value != 3000000 {
			t.Fatal("full grant recovery", e.State, grantWrites, eerr)
		}
		after, _ := h.ycOperation(t.Context(), team.ID)
		afterRaw, _ := json.Marshal(after)
		if !bytes.Equal(before, afterRaw) {
			t.Fatal("issuance rewrote frozen operation")
		}
		scope := []string{"price_round"}
		for _, key := range keys {
			scope = append(scope, "price_"+key)
		}
		if err = creditScope(grant, customer, anchor.AddDate(0, 1, 0).Unix(), scope); err != nil {
			t.Fatal(err)
		}
	}
	var receipts int
	if err = h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1`, o.Contract).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("waiver fabricated cash", receipts, err)
	}
	if existing {
		e, eerr := h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: team.ID, Kind: "metered_usage"})
		if eerr != nil || e.State != "issued" || e.IssuanceSource != "adopted" || e.StripeCreditGrantID == nil || *e.StripeCreditGrantID != grant.ID {
			t.Fatal("existing grant was not adopted", eerr)
		}
		account, enrolled, eerr := h.invoiceAccount(t.Context(), team.ID)
		if eerr != nil || !enrolled {
			t.Fatal(eerr)
		}
		plan := billing.InvoiceClosePlan{InvoiceEnd: anchor.AddDate(0, 1, 0).Unix()}
		for _, key := range keys {
			plan.Resources = append(plan.Resources, billing.InvoiceCloseResource{PriceID: "price_" + key})
		}
		if eerr = h.prepareEntitlementCredits(t.Context(), billing.ExportPeriod{TeamID: team.ID, Start: anchor, End: anchor.AddDate(0, 1, 0)}, account, "in_overage", &plan, h.Stripe.(*stripeHTTPClient)); eerr != nil {
			t.Fatal("depleted adopted grant blocked overages", eerr)
		}
		if plan.CreditBeforeCents != 0 {
			t.Fatal("fabricated remaining credit")
		}
	}
	methodOwner = "acct_other"
	if err = h.reconcileYC(t.Context(), team.ID); err == nil {
		t.Fatal("foreign payment method accepted")
	}
	eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
	if err != nil || eligible {
		t.Fatal("usage survived invalid payment ownership", err)
	}
	methodOwner = "acct_customer"
	if err = h.reconcileYC(t.Context(), team.ID); err != nil {
		t.Fatal(err)
	}
	card = false
	_ = h.reconcileYC(t.Context(), team.ID)
	eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
	if err != nil || eligible {
		t.Fatal("usage survived removed payment method", err)
	}
}
