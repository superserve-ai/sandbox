//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
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
func TestYCOperatorLinkAdoption(t *testing.T) { runYCOperatorAdoption(t, true, "link") }

func TestYCOperatorLinkCreatesSubscriptionOnce(t *testing.T) {
	runYCOperatorAdoption(t, false, "link", true)
}

func runYCOperatorAdoption(t *testing.T, existing bool, methodType string, create ...bool) {
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
	h.Config = &config.Config{TeamCreationRegion: "use", StripeProAnnualPriceID: p.BasePriceID, BillingUsageEntitlementsEnabled: true}
	prices := map[string]storagePrice{p.BasePriceID: sub.Items.Data[0].Price}
	rates, err := h.DB.ListActivePricingRatesForTeam(t.Context(), db.ListActivePricingRatesForTeamParams{TeamID: team.ID, EffectiveAt: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"vcpu", "memory_gib", "storage_gib"} {
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
		price := storagePrice{ID: id, Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: amount}
		price.Recurring.UsageType = "metered"
		price.Recurring.Interval = "month"
		price.Recurring.IntervalCount = 1
		price.Recurring.Meter = "mtr_" + key
		prices[id] = price
	}
	rounding := storagePrice{ID: "price_round", Active: true, Currency: "usd", BillingScheme: "per_unit", UnitAmountDecimal: "1"}
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
	for i, key := range []string{"vcpu", "memory_gib", "storage_gib", "round"} {
		grant.Applicability.Scope.Prices[i].ID = "price_" + key
	}
	card := false
	setupReady := false
	methodOwner := "acct_customer"
	writes := 0
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
			fmt.Fprintf(w, `{"id":"in_first","customer":%q,"status":"paid","currency":"usd","subtotal":1200000,"total":0,"amount_due":0,"amount_paid":0,"amount_remaining":0,"starting_balance":0,"ending_balance":0,"total_discount_amounts":[{"amount":1200000}],"parent":{"subscription_details":{"subscription":%q}},"lines":{"data":[{"amount":1200000,"currency":"usd","quantity":1,"period":{"start":%d,"end":%d},"pricing":{"price_details":{"price":%q}},"parent":{"subscription_item_details":{"subscription":%q}}}]}}`, customer, sub.ID, sub.StartDate, sub.Items.Data[0].End, p.BasePriceID, sub.ID)
		case strings.HasPrefix(r.URL.Path, "/v1/coupons/"):
			output(map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/coupons/"), "duration": "once", "percent_off": 100, "applies_to": map[string]any{"products": []string{sub.Items.Data[0].Price.Product}}})
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
			grants := []entitlementGrant{}
			if existing {
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
	eligible, err = h.DB.IsTeamSandboxBillingEligible(t.Context(), team.ID)
	if err != nil || !eligible {
		t.Fatal("usage after card", err)
	}
	if len(sub.Items.Data) != 5 {
		t.Fatalf("duplicated or missing resources: %d", len(sub.Items.Data))
	}
	if err = h.reconcileYC(t.Context(), team.ID); err != nil {
		t.Fatal("repeat activation", err)
	}
	if newSubscription && subscriptionWrites != 1 {
		t.Fatalf("created %d subscriptions", subscriptionWrites)
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
		for _, key := range []string{"vcpu", "memory_gib", "storage_gib"} {
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
