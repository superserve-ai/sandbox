//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegrationFundingCreditOwnedDraftReservesUsageOnce(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	start := at.Add(-time.Hour)
	customer, subscription := "cus_"+team.String(), "sub_"+team.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'canceled',$4)`, team, customer, subscription, start)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_rounding','rounding','meter_rounding',$4)`, team, customer, subscription, start)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, start, at)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,3600,0,0)`, team, start, at)
	planKey := "draft-" + team.String()
	exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'Draft funding')`, planKey)
	exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0,$2)`, planKey, start.Add(-time.Hour))
	exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, planKey, start.Add(-time.Hour))
	period := billing.ExportPeriod{TeamID: team, Start: start, End: at}
	inv, plan := fundingOwnedDraftFixture(period, customer, subscription)
	inv.ID = "in_" + team.String()
	for i := range plan.Resources {
		if err := h.Pool.QueryRow(t.Context(), `SELECT billing_meter_accounting_snapshot($1,$2,$3,$4)`, team, start, at, plan.Resources[i].Resource).Scan(&plan.Resources[i].Snapshot); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(plan)
	exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,plan) VALUES($1,$2,$3,$4,'prepared',$5)`, team, start, at, inv.ID, raw)
	g := entitlementGrant{ID: "credgr_" + team.String(), Customer: customer, Created: start.Unix(), EffectiveAt: start.Unix(), ExpiresAt: at.Add(time.Hour).Unix()}
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 1000
	g.Applicability.Scope.PriceType = "metered"
	foreign := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/billing/credit_grants":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []entitlementGrant{g}})
		case "/v1/billing/credit_grants/" + g.ID:
			_ = json.NewEncoder(w).Encode(g)
		case "/v1/billing/credit_balance_summary":
			_, _ = w.Write([]byte(`{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":1000}},"available_balance":{"monetary":{"currency":"usd","value":640}}}]}`))
		case "/v1/invoices":
			invoices := []StripeInvoiceAmounts{inv}
			if foreign {
				invoices = append(invoices, StripeInvoiceAmounts{ID: "in_foreign", Customer: customer, Status: "draft", BillingReason: "manual", Total: 1000})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": invoices})
		default:
			t.Errorf("unexpected provider request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	account := db.TeamBillingAccount{TeamID: team, StripeCustomerID: &customer, StripeSubscriptionID: &subscription}
	observation, err := h.observeFundingCredit(t.Context(), team, account, at)
	if err != nil || observation.SpendableUSD != "6.400000" {
		t.Fatalf("owned draft rejected or double counted: %+v %v", observation, err)
	}
	foreign = true
	if _, err = h.observeFundingCredit(t.Context(), team, account, at); err == nil {
		t.Fatal("foreign draft reservation treated as owned measured usage")
	}
}

func TestIntegrationFundingCreditAcceptsRenewalDraftBeforeClosePlan(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	start := at.Add(-time.Hour)
	customer, subscription := "cus_"+team.String(), "sub_"+team.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, customer, subscription, start)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_rounding','rounding','meter_rounding',$4)`, team, customer, subscription, start)
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, start, at)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,3600,0,0)`, team, start, at)
	planKey := "renewal-" + team.String()
	exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'Renewal funding')`, planKey)
	exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0,$2)`, planKey, start.Add(-time.Hour))
	exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, planKey, start.Add(-time.Hour))
	// The provider has drafted the renewal invoice; the close worker has not
	// planned it yet, so no close row exists.
	inv, _ := fundingOwnedDraftFixture(billing.ExportPeriod{TeamID: team, Start: start, End: at}, customer, subscription)
	inv.ID = "in_" + team.String()
	g := entitlementGrant{ID: "credgr_" + team.String(), Customer: customer, Created: start.Unix(), EffectiveAt: start.Unix(), ExpiresAt: at.Add(time.Hour).Unix()}
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 1000
	g.Applicability.Scope.PriceType = "metered"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/billing/credit_grants":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []entitlementGrant{g}})
		case "/v1/billing/credit_grants/" + g.ID:
			_ = json.NewEncoder(w).Encode(g)
		case "/v1/billing/credit_balance_summary":
			_, _ = w.Write([]byte(`{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":1000}},"available_balance":{"monetary":{"currency":"usd","value":640}}}]}`))
		case "/v1/invoices":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []StripeInvoiceAmounts{inv}})
		default:
			t.Errorf("unexpected provider request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	cfg := config.Config{}
	if h.Config != nil {
		cfg = *h.Config
	}
	cfg.BillingResources = []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_cpu", CheckoutEnabled: true}, {ResourceKey: "memory_gib", StripePriceID: "price_memory", CheckoutEnabled: true}}
	h.Config = &cfg
	account := db.TeamBillingAccount{TeamID: team, StripeCustomerID: &customer, StripeSubscriptionID: &subscription}
	observation, err := h.observeFundingCredit(t.Context(), team, account, at)
	if err != nil || observation.SpendableUSD != "6.400000" {
		t.Fatalf("unplanned renewal draft rejected or double counted: %+v %v", observation, err)
	}
	planned := inv
	for _, mutate := range []func(*StripeInvoiceAmounts){
		func(d *StripeInvoiceAmounts) { d.Lines.Data[0].Parent.SubscriptionItemDetails = nil },
		func(d *StripeInvoiceAmounts) { d.Lines.Data[0].Pricing.PriceDetails = nil },
		func(d *StripeInvoiceAmounts) {
			price := *d.Lines.Data[0].Pricing.PriceDetails
			price.Price = "price_manual"
			d.Lines.Data[0].Pricing.PriceDetails = &price
		},
	} {
		inv = planned
		inv.Lines.Data = append([]StripeInvoiceAmountLine(nil), planned.Lines.Data...)
		mutate(&inv)
		if _, err = h.observeFundingCredit(t.Context(), team, account, at); err == nil {
			t.Fatal("unplanned draft line outside the subscription resources treated as owned usage")
		}
	}
	inv = planned
	inv.PeriodEnd = at.Add(time.Hour).Unix()
	if _, err = h.observeFundingCredit(t.Context(), team, account, at); err == nil {
		t.Fatal("draft for an unknown local period treated as owned usage")
	}
	// A provider cycle offset from the local period drafts over its own window.
	offset := start.Add(30 * time.Minute)
	exec(`INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$6,$3,$7)`, team, start, at, customer, subscription, offset, offset.Unix())
	inv, _ = fundingOwnedDraftFixture(billing.ExportPeriod{TeamID: team, Start: offset, End: at}, customer, subscription)
	inv.ID = "in_" + team.String()
	if observation, err = h.observeFundingCredit(t.Context(), team, account, at); err != nil || observation.SpendableUSD != "6.400000" {
		t.Fatalf("offset-calendar renewal draft rejected: %+v %v", observation, err)
	}
}

func TestIntegrationFundingCreditPreservesReleasedPriceScope(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	customer, subscription := "cus_"+team.String(), "sub_"+team.String()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status) VALUES($1,$2,$3,'canceled')`, team, customer, subscription)
	params := StripeCreateCheckoutSessionParams{CustomerID: customer, ResourceTerms: []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "price_old_cpu", MeterID: "meter_old_cpu", EventName: "cpu_old"}, {ResourceKey: "memory_gib", PriceID: "price_old_memory", MeterID: "meter_old_memory", EventName: "memory_old"}}}
	raw, _ := json.Marshal(params)
	exec(`UPDATE billing_signup_choice SET offer_key='pro_monthly',state='committed',generation=now(),actor_id=$2,base_price_id='price_base',request_payload=$3,subscription_id=$4 WHERE team_id=$1`, team, uuid.New(), raw, subscription)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id) VALUES($1,$2,$3,'price_rounding','rounding','meter_rounding')`, team, customer, subscription)
	h.Config = &config.Config{BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_new_cpu"}, {ResourceKey: "memory_gib", StripePriceID: "price_new_memory"}, {ResourceKey: "storage_gib", StripePriceID: "price_new_storage"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/subscriptions/"+subscription {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": subscription, "customer": customer, "status": "canceled", "items": map[string]any{"data": []map[string]string{{"id": "si_example"}}}})
	}))
	defer server.Close()
	h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	for _, released := range []bool{false, true} {
		if released {
			if err := h.commitFreeFundingPlan(t.Context(), team, uuid.New()); err != nil {
				t.Fatal(err)
			}
		}
		prices, err := h.fundingCreditResourcePrices(t.Context(), team, customer)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(prices, ",") != "price_old_cpu,price_old_memory,price_rounding" {
			t.Fatalf("release=%v wrong purchased scope %v", released, prices)
		}
		states, err := h.billingSubscriptionResourceStates(t.Context(), team, subscription, false)
		if err != nil || len(states) != 2 || states[0].StripePriceID != "price_old_cpu" || states[0].StripeEventName != "cpu_old" || states[0].PurchasedTerms.MeterID != "meter_old_cpu" {
			t.Fatalf("release=%v historical exporter lost purchased terms: %+v %v", released, states, err)
		}
	}
}

func TestIntegrationFundingCreditReplacementPAYGScope(t *testing.T) {
	h, team := fundingTransitionFixture(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	customer, subscription := "cus_"+team.String(), "sub_replacement_"+team.String()
	now := time.Now().UTC()
	anchor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, customer, subscription, anchor)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id) VALUES($1,$2,$3,'price_rounding','rounding','meter_rounding')`, team, customer, subscription)
	planKey := "replacement-" + team.String()
	exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'Replacement funding')`, planKey)
	exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0.001,$2)`, planKey, anchor.Add(-time.Hour))
	exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, planKey, anchor.Add(-time.Hour))
	h.Config = &config.Config{StripeCheckoutPriceIDs: []string{"price_covered_cpu", "price_covered_memory"}}
	sub := invoiceSubscription{ID: subscription, Customer: customer, Status: "active", BillingCycleAnchor: anchor.Unix()}
	for _, resource := range []string{"cpu", "memory"} {
		price := storagePrice{ID: "price_covered_" + resource, Currency: "usd", Active: true, BillingScheme: "per_unit", UnitAmountDecimal: "360"}
		price.Recurring.UsageType, price.Recurring.Interval, price.Recurring.IntervalCount, price.Recurring.Meter = "metered", "month", 1, "meter_"+resource
		sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{ID: "si_" + resource, Price: price, Start: anchor.Unix(), End: anchor.AddDate(0, 1, 0).Unix()})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/subscriptions/" + subscription:
			_ = json.NewEncoder(w).Encode(sub)
		case "/v1/billing/meters":
			_, _ = w.Write([]byte(`{"data":[{"id":"meter_cpu","event_name":"cpu_vcpu_hours","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}},{"id":"meter_memory","event_name":"memory_gib_hours","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}}]}`))
		default:
			t.Errorf("unexpected provider request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	h.Stripe = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	prices, err := h.fundingCreditResourcePrices(t.Context(), team, customer)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(prices, ",") != "price_covered_cpu,price_covered_memory,price_rounding" {
		t.Fatalf("replacement PAYG lost credit scope: %v", prices)
	}
	sub.Customer = "cus_other"
	if _, err = h.fundingCreditResourcePrices(t.Context(), team, customer); err == nil {
		t.Fatal("replacement provider mismatch accepted")
	}
}

func TestIntegrationFundingCreditReservesProviderInvoiceCents(t *testing.T) {
	for _, periods := range []int{1, 2} {
		t.Run(string(rune('0'+periods))+"-periods", func(t *testing.T) {
			h, team := fundingTransitionFixture(t)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := h.Pool.Exec(t.Context(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
			start := at.Add(-time.Duration(periods) * time.Hour)
			plan := "rounding-" + team.String()
			exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'Funding rounding')`, plan)
			exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.000001666667,$2),($1,'memory_gib','second',0.000001666667,$2),($1,'storage_gib','second',0,$2)`, plan, start.Add(-time.Hour))
			exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, plan, start.Add(-time.Hour))
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
			for i := 0; i < periods; i++ {
				lo := start.Add(time.Duration(i) * time.Hour)
				hi := lo.Add(time.Hour)
				memory := 0
				if periods == 1 {
					memory = 3686400
				}
				exec(`INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, lo, hi)
				exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,3600,$4,0)`, team, lo, hi, memory)
			}
			var cost, snapshot string
			var coverage []byte
			if err := h.Pool.QueryRow(t.Context(), fundingUnsettledCreditSQL, team, at, start, true).Scan(&cost, &snapshot, &coverage); err != nil {
				t.Fatal(err)
			}
			net, err := fundingNetSpendableUSD("0.02", cost)
			if err != nil || net != "0.000000" {
				t.Fatalf("provider line cents under-reserved: cost=%s net=%s err=%v", cost, net, err)
			}
			if err := h.Pool.QueryRow(t.Context(), fundingUnsettledCreditSQL, team, at, start, false).Scan(&cost, &snapshot, &coverage); err != nil {
				t.Fatal(err)
			}
			net, err = fundingNetSpendableUSD("0.02", cost)
			if err != nil || net == "0.000000" {
				t.Fatalf("local six-decimal funds rounded to provider cents: cost=%s net=%s err=%v", cost, net, err)
			}
		})
	}
}

func TestIntegrationFundingCreditLocalUnfinalizedAndExpiry(t *testing.T) {
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires migrated disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	h := &Handlers{Pool: pool, DB: db.New(pool)}
	team, err := h.DB.CreateTeam(t.Context(), "funding-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	start := at.Add(-time.Hour)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_status,trial_ended_at) VALUES($1,$2,'canceled',now())`, team.ID, "cus_"+team.ID.String())
	exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at,expires_at) VALUES($1,10,10,'operator grant',$2,$3)`, team.ID, start, at.Add(30*time.Second))
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_hourly_rollups',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team.ID)
	exec(`INSERT INTO team_billing_usage_hourly(team_id,hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,3600,0,0)`, team.ID, start, at)
	plan := "funding-" + team.ID.String()
	exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'Funding test')`, plan)
	exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0,$2),($1,'storage_gib','second',0,$2)`, plan, start.Add(-time.Hour))
	exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team.ID, plan, start.Add(-time.Hour))
	account := db.TeamBillingAccount{TeamID: team.ID}
	observation, err := h.observeFundingCredit(t.Context(), team.ID, account, at)
	if err != nil || observation.SpendableUSD != "6.400000" {
		t.Fatalf("unfinalized consumption: %+v %v", observation, err)
	}
	if !observation.ValidUntil.Equal(at.Add(30 * time.Second)) {
		t.Fatalf("expiry not clipped: %v", observation.ValidUntil)
	}
	sandbox := uuid.New()
	exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id) VALUES($1,$2,'funding-live','deleted',1,1024,'default')`, sandbox, team.ID)
	exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at) VALUES($1,$2,1,1024,$3)`, sandbox, team.ID, at)
	observation, err = h.observeFundingCredit(t.Context(), team.ID, account, at.Add(15*time.Second))
	if err != nil || observation.SpendableUSD != "6.385000" {
		t.Fatalf("open interval consumption omitted: %+v %v", observation, err)
	}
	// Invoice finalization atomically debits the balance and closes its usage.
	// A new observation must neither resurrect nor double-debit that $3.60.
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE team_credit_grant SET remaining_usd=6.4 WHERE team_id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',now(),3.6,3.6,0)`, team.ID, start, at); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	observation, err = h.observeFundingCredit(t.Context(), team.ID, account, at)
	if err != nil || observation.SpendableUSD != "6.400000" {
		t.Fatalf("finalized consumption double counted: %+v %v", observation, err)
	}
	observation, err = h.observeFundingCredit(t.Context(), team.ID, account, at.Add(time.Minute))
	if err != nil || observation.SpendableUSD != "0.000000" {
		t.Fatalf("expired manual credit allowed: %+v %v", observation, err)
	}
}
