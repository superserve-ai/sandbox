//go:build integration

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

type proCashFixture struct {
	*invoiceCashFixture
	grantCreates *atomic.Int64
}

// A historical synthetic unpaid close exercises the real collector and SQL
// intent barrier. All elapsed dates and Stripe transport are local fixtures.
func newProCashFixture(t *testing.T, prior string, protectedSeconds, paidSeconds, credit int64, mutations ...func(*billing.InvoiceClosePlan, *StripeInvoiceAmounts)) (*proCashFixture, uuid.UUID) {
	return newProCashFixtureMode(t, prior, protectedSeconds, paidSeconds, credit, false, mutations...)
}

func newProCashFixtureMode(t *testing.T, prior string, protectedSeconds, paidSeconds, credit int64, producer bool, mutations ...func(*billing.InvoiceClosePlan, *StripeInvoiceAmounts)) (*proCashFixture, uuid.UUID) {
	t.Helper()
	h, team := newPlanAssignmentFixture(t)
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	f := &invoiceCashFixture{h: h, team: team, start: end.AddDate(0, -1, 0), end: end}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	customer, sub, invoice := "cus_"+team.String(), "sub_"+team.String(), "in_"+team.String()
	version, err := h.planTermsForPricingVersion(t.Context(), "pro_monthly", "v2")
	if err != nil {
		t.Fatal(err)
	}
	contract, upgrade, assignment := uuid.New(), uuid.New(), uuid.New()
	paidStart := f.start.Add(180 * time.Second)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, customer, sub, f.start)
	exec(`INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_kind,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'pro_monthly',$3,$4,$5,'price_pro',25000,1,'metered_usage',$6,'monthly',$7)`, contract, team, f.end, customer, sub, max(credit, 1), f.start)
	if prior != "" {
		exec(`INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason) VALUES($1,$2,$2,jsonb_build_object('kind',$2::text,'pricing_version','v2'),'{"max_concurrent":1}',$3,'signup','historical diagnostic predecessor')`, team, prior, f.start.Add(-time.Hour))
		exec(`UPDATE team_plan_assignment SET effective_to=$2 WHERE team_id=$1 AND effective_to IS NULL`, team, paidStart)
	}
	exec(`INSERT INTO team_plan_assignment(id,team_id,plan_version_id,plan_key,kind,terms,limits,effective_from,source,reason,contract_id,idempotency_key) VALUES($1,$2,$3,'pro_monthly','subscription','{"kind":"subscription","pricing_version":"v2"}','{"max_concurrent":1}',$4,'checkout','verified diagnostic payment',$5::uuid,'checkout:'||($5::uuid)::text)`, assignment, team, version.VersionID, paidStart, contract)
	params := StripeCreateCheckoutSessionParams{FirstPaidProCycle: prior == planKindFree, BasePriceID: "price_pro", ResourceTerms: []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "price_cpu", UnitAmountDecimal: "3600", MeterID: "meter_cpu", EventName: "cpu"}, {ResourceKey: "memory_gib", PriceID: "price_memory", UnitAmountDecimal: "0", MeterID: "meter_memory", EventName: "memory"}}, PlanTerms: &StripeCheckoutPlanTerms{VersionID: version.VersionID, Amount: 25000, Months: 1, Credit: max(credit, 1)}}
	payload, _ := json.Marshal(params)
	var initialGrant *string
	if credit > 0 {
		id := "cred_" + upgrade.String()
		initialGrant = &id
	}
	exec(`INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state,payment_evidence,grant_id,contract_id,bridge_credit_cents)
 VALUES($1,$2,$3,$4,$5,'pro_monthly',$6,$7,$7,$8,$7,25000,'active','{"verified":true}',$9,$10,$11)`, upgrade, team, uuid.New(), customer, sub, payload, f.start, f.end, initialGrant, contract, credit)
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','meter_round',$4)`, team, customer, sub, f.start.Add(-time.Hour))
	exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, f.start, f.end)
	sandbox := uuid.New()
	exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id) VALUES($1,$2,'renewal-diagnostic','deleted',1,1024,'default')`, sandbox, team)
	for _, part := range []struct {
		start   time.Time
		seconds int64
	}{{f.start, protectedSeconds}, {paidStart, paidSeconds}} {
		if part.seconds == 0 {
			continue
		}
		exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason) VALUES($1,$2,1,1024,$3,$4,'deleted')`, sandbox, team, part.start, part.start.Add(time.Duration(part.seconds)*time.Second))
	}
	gross := protectedSeconds + paidSeconds
	applied := min(gross, credit)
	remainingCredit := credit - applied
	net := gross - applied
	exec(`INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,$4,$5,0)`, team, f.start, f.end, gross, gross*1024)
	var snapshot []byte
	if err = h.Pool.QueryRow(t.Context(), `SELECT billing_meter_accounting_snapshot($1,$2,$3,'cpu')`, team, f.start, f.end).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	var grant entitlementGrant
	grant.ID, grant.Customer, grant.Category, grant.Priority = "cred_"+upgrade.String(), customer, "paid", 50
	grant.Amount.Type, grant.Amount.Monetary.Currency, grant.Amount.Monetary.Value = "monetary", "usd", max(credit, 1)
	grant.Metadata = map[string]string{"pro_upgrade_id": upgrade.String()}
	grant.Applicability.Scope.PriceType = "metered"
	grant.ExpiresAt = int64(0)
	if params.FirstPaidProCycle {
		grant.ExpiresAt = f.end.Unix() + 1
	}
	grant.EffectiveAt = f.start.Unix()
	grantRaw, _ := json.Marshal(grant)
	plan := billing.InvoiceClosePlan{AdjustmentTimestamp: f.end.Add(-time.Second).Unix(), CreditVersion: 1, CreditPrices: []string{"price_cpu", "price_memory", "price_round"}, CreditGrants: []billing.InvoiceCreditGrant{{ID: grant.ID, Before: credit, ExpiresAt: grant.ExpiresAt, Evidence: grantRaw}}, BaseCents: 25000, BasePeriodStart: f.end.Unix(), BasePeriodEnd: f.end.AddDate(0, 1, 0).Unix(), InvoiceStart: f.start.Unix(), InvoiceEnd: f.end.Unix(), Customer: customer, Subscription: sub, ExpectedCents: gross, CreditBeforeCents: credit, Resources: []billing.InvoiceCloseResource{{Resource: "cpu", PriceID: "price_cpu", UnitUSD: "36", ExpectedCents: gross, ProviderCents: gross, Snapshot: snapshot}}}
	raw := fmt.Sprintf(`{"id":%q,"customer":%q,"currency":"usd","status":"open","billing_reason":"subscription_cycle","collection_method":"charge_automatically","subtotal":%d,"total":%d,"amount_due":%d,"amount_remaining":%d,"ending_balance":0,"period_start":%d,"period_end":%d,"parent":{"subscription_details":{"subscription":%q}},"total_pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":%d,"credit_balance_transaction":"cbtxn_diag"}],"lines":{"data":[
 {"id":"il_cpu","amount":%d,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"3600","price_details":{"price":"price_cpu"}},"parent":{"subscription_item_details":{"subscription":%q}},"pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":%d,"credit_balance_transaction":"cbtxn_diag"}]},
 {"id":"il_round","amount":0,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"1","price_details":{"price":"price_round"}},"parent":{"subscription_item_details":{"subscription":%q}}},
 {"id":"il_base","amount":25000,"currency":"usd","quantity":1,"period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"25000","price_details":{"price":"price_pro"}},"parent":{"subscription_item_details":{"subscription":%q,"subscription_item":"si_base"}}}]}}`, invoice, customer, gross+25000, net+25000, net+25000, net+25000, f.start.Unix(), f.end.Unix(), sub, applied, gross, f.start.Unix(), f.end.Unix(), sub, applied, f.start.Unix(), f.end.Unix(), sub, f.end.Unix(), f.end.AddDate(0, 1, 0).Unix(), sub)
	if err = json.Unmarshal([]byte(raw), &f.invoice); err != nil {
		t.Fatal(err)
	}

	var memorySnapshot []byte
	if err = h.Pool.QueryRow(t.Context(), `SELECT billing_meter_accounting_snapshot($1,$2,$3,'memory')`, team, f.start, f.end).Scan(&memorySnapshot); err != nil {
		t.Fatal(err)
	}
	plan.Resources = append(plan.Resources, billing.InvoiceCloseResource{Resource: "memory", PriceID: "price_memory", UnitUSD: "0", Snapshot: memorySnapshot})
	var memoryLine StripeInvoiceAmountLine
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"id":"il_memory","amount":0,"currency":"usd","period":{"start":%d,"end":%d},"pricing":{"unit_amount_decimal":"0","price_details":{"price":"price_memory"}},"parent":{"subscription_item_details":{"subscription":%q}}}`, f.start.Unix(), f.end.Unix(), sub)), &memoryLine)
	f.invoice.Lines.Data = append(f.invoice.Lines.Data, memoryLine)
	if credit == 0 {
		f.invoice.PretaxCredits = nil
		for i := range f.invoice.Lines.Data {
			f.invoice.Lines.Data[i].PretaxCredits = nil
		}
	}
	for _, mutate := range mutations {
		mutate(&plan, &f.invoice)
	}
	exec(`INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,to_timestamp($6),to_timestamp($7),extract(epoch FROM $3::timestamptz)::bigint)`, team, f.start, f.end, customer, sub, plan.InvoiceStart, plan.InvoiceEnd)
	finalInvoiceRaw, _ := json.Marshal(f.invoice)
	planRaw, _ := json.Marshal(plan)
	finalRaw, _ := json.Marshal(billing.InvoiceCloseSettlement{CreditAppliedCents: applied, CreditRemainingCents: remainingCredit, NetCents: net, Invoice: finalInvoiceRaw})
	persistClose := func() {
		exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'verified',clock_timestamp(),$5,$6)`, team, f.start, f.end, invoice, planRaw, finalRaw)
		exec(`UPDATE team_billing_period SET status='finalized',finalized_at=clock_timestamp(),gross_charges_usd=$4::numeric/100,credits_applied_usd=$5::numeric/100,net_invoice_amount_usd=$6::numeric/100 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team, f.start, f.end, gross, applied, net)

	}
	if !producer {
		persistClose()
	}
	providerMetadata := map[string]string{"pro_upgrade_id": upgrade.String()}
	if params.FirstPaidProCycle {
		providerMetadata["first_paid_pro_cycle"] = "true"
	}
	var providerSub invoiceSubscription
	price := func(id, usage, amount, meter string) map[string]any {
		return map[string]any{"id": id, "active": true, "product": "prod_" + id, "currency": "usd", "unit_amount_decimal": amount, "billing_scheme": "per_unit", "recurring": map[string]any{"usage_type": usage, "interval": "month", "interval_count": 1, "meter": meter}}
	}
	subRaw, _ := json.Marshal(map[string]any{"id": sub, "customer": customer, "status": "active", "collection_method": "charge_automatically", "default_payment_method": "pm_diag", "billing_mode": map[string]string{"type": "flexible"}, "pause_collection": map[string]string{"behavior": "keep_as_draft"}, "metadata": providerMetadata, "start_date": f.start.Unix(), "billing_cycle_anchor": f.end.Unix(), "billing_cycle_anchor_config": map[string]int{"day_of_month": f.start.Day(), "hour": f.start.Hour(), "minute": f.start.Minute(), "second": f.start.Second()}, "items": map[string]any{"data": []any{
		map[string]any{"id": "si_base", "quantity": 1, "price": price("price_pro", "licensed", "25000", "")},
		map[string]any{"id": "si_cpu", "current_period_start": f.end.Unix(), "current_period_end": f.end.AddDate(0, 1, 0).Unix(), "price": price("price_cpu", "metered", "3600", "meter_cpu")},
		map[string]any{"id": "si_memory", "current_period_start": f.end.Unix(), "current_period_end": f.end.AddDate(0, 1, 0).Unix(), "price": price("price_memory", "metered", "0", "meter_memory")},
		map[string]any{"id": "si_round", "current_period_start": f.end.Unix(), "current_period_end": f.end.AddDate(0, 1, 0).Unix(), "price": price("price_round", "metered", "1", "meter_round")}}}})
	_ = json.Unmarshal(subRaw, &providerSub)
	var grantCreates atomic.Int64
	var nextGrant *entitlementGrant
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/invoices/"+invoice:
			json.NewEncoder(w).Encode(f.invoice)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/invoice_payments":
			if f.invoice.Status != "paid" {
				fmt.Fprint(w, `{"data":[]}`)
			} else {
				fmt.Fprintf(w, `{"data":[{"id":"inpay_diag","invoice":%q,"status":"paid","currency":"usd","amount_paid":%d,"payment":{"type":"payment_intent","payment_intent":"pi_diag"}}]}`, invoice, f.invoice.AmountDue)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/payment_intents/pi_diag":
			fmt.Fprintf(w, `{"id":"pi_diag","status":"succeeded","customer":%q,"currency":"usd","amount_received":%d,"latest_charge":"ch_diag"}`, customer, f.invoice.AmountDue)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/charges/ch_diag":
			fmt.Fprintf(w, `{"id":"ch_diag","customer":%q,"payment_intent":"pi_diag","currency":"usd","paid":true,"captured":true,"amount_captured":%d}`, customer, f.invoice.AmountDue)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions/"+sub:
			json.NewEncoder(w).Encode(providerSub)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{providerSub}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/prices/price_cpu":
			json.NewEncoder(w).Encode(price("price_cpu", "metered", "3600", "meter_cpu"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/prices/price_memory":
			json.NewEncoder(w).Encode(price("price_memory", "metered", "0", "meter_memory"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/prices/price_round":
			json.NewEncoder(w).Encode(price("price_round", "metered", "1", "meter_round"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/billing/meters":
			meters := []any{}
			for _, name := range []string{"cpu", "memory", "round"} {
				meters = append(meters, map[string]any{"id": "meter_" + name, "event_name": name, "default_aggregation": map[string]string{"formula": "sum"}, "customer_mapping": map[string]string{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]string{"event_payload_key": "value"}})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": meters})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/invoices":
			fmt.Fprint(w, `{"data":[]}`)
		case r.URL.Path == "/v1/billing/credit_grants":
			if r.Method == http.MethodGet {
				data := []any{}
				if credit > 0 {
					data = append(data, grant)
				}
				if nextGrant != nil {
					data = append(data, nextGrant)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": data})
				break
			}
			grantCreates.Add(1)
			_ = r.ParseForm()
			g := testEntitlementGrant()
			g.ID = "credgr_next_" + team.String()
			g.Customer = customer
			g.Amount.Monetary.Value, _ = strconv.ParseInt(r.Form.Get("amount[monetary][value]"), 10, 64)
			g.ExpiresAt, _ = strconv.ParseInt(r.Form.Get("expires_at"), 10, 64)
			g.Created = time.Now().Unix()
			g.EffectiveAt = g.Created
			g.Metadata = map[string]string{"entitlement_id": r.Form.Get("metadata[entitlement_id]")}
			g.Applicability.Scope.Prices = g.Applicability.Scope.Prices[:3]
			for i := range g.Applicability.Scope.Prices {
				g.Applicability.Scope.Prices[i].ID = r.Form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i))
			}
			nextGrant = &g
			json.NewEncoder(w).Encode(g)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/invoices/"+invoice+"/pay":
			f.pays.Add(1)
			f.invoice.Status = "paid"
			f.invoice.StatusTransitions.PaidAt = time.Now().Unix()
			amountPaid := f.invoice.AmountDue
			f.invoice.AmountPaid = &amountPaid
			zero := int64(0)
			f.invoice.AmountRemaining = &zero
			fmt.Fprint(w, `{}`)

		case r.Method == http.MethodGet && r.URL.Path == "/v1/billing/credit_grants/"+grant.ID:
			json.NewEncoder(w).Encode(grant)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/billing/credit_balance_transactions":
			fmt.Fprint(w, `{"data":[]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/billing/credit_balance_summary":
			fmt.Fprintf(w, `{"balances":[{"ledger_balance":{"monetary":{"currency":"usd","value":%d}}}]}`, credit)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/event_summaries"):
			quantity := "0"
			if !strings.Contains(r.URL.Path, "meter_round/") {
				quantity = new(big.Rat).SetFrac(big.NewInt(gross), big.NewInt(3600)).FloatString(12)
			}
			fmt.Fprintf(w, `{"data":[{"aggregated_value":%s}],"has_more":false}`, quantity)
		default:
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	f.client = &stripeHTTPClient{baseURL: server.URL, httpClient: server.Client(), apiVersion: "2026-07-29.dahlia"}
	h.Stripe = f.client

	if producer {
		rateKey := "renewal-proof-" + team.String()
		exec(`INSERT INTO pricing_plan(key,name) VALUES($1,'renewal producer fixture')`, rateKey)
		exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.01,$2),($1,'memory_gib','second',0,$2)`, rateKey, f.start)
		exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, rateKey, f.start)
		exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, team)
		exec(`INSERT INTO billing_incremental_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, f.start, f.end)
		period := billing.ExportPeriod{TeamID: team, Start: f.start, End: f.end}
		store := billing.ExportStore{Pool: h.Pool}
		quantity := new(big.Rat).SetFrac(big.NewInt(gross), big.NewInt(3600)).FloatString(12)
		for _, resource := range []string{"cpu", "memory"} {
			if _, e := store.Reserve(t.Context(), period, resource, quantity, f.end, billing.ExportPayload{EventName: resource, CustomerID: customer, Timestamp: f.end.Add(-time.Minute).Unix()}); e != nil {
				t.Fatal(e)
			}
			event, e := store.Claim(t.Context(), period)
			if e != nil || event == nil {
				t.Fatalf("claim resource export: %v", e)
			}
			if e = store.Acknowledge(t.Context(), *event, nil); e != nil {
				t.Fatal(e)
			}
		}
		exec(`UPDATE team_billing_period SET status='exporting' WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team, f.start, f.end)
		account, ok, e := h.invoiceAccount(t.Context(), team)
		if e != nil || !ok {
			t.Fatal(e)
		}
		draft := f.invoice
		draft.Status = "draft"
		draft.Total = draft.Subtotal
		draft.AmountDue = draft.Subtotal
		draft.PretaxCredits = nil
		prepared, e := h.prepareInvoicePlan(t.Context(), period, account, draft, f.client)
		if e != nil {
			t.Fatalf("ordinary close producer: %v", e)
		}
		if prepared.BaseCents != 25000 || prepared.BasePeriodStart != f.end.Unix() || prepared.ExpectedCents != gross || prepared.CreditVersion != 1 || prepared.CreditBeforeCents != credit || len(prepared.Resources) != 2 {
			t.Fatalf("producer contract differs: %+v", prepared)
		}
		planRaw, _ = json.Marshal(prepared)
		persistClose()
	}
	return &proCashFixture{f, &grantCreates}, upgrade
}

func TestProFirstRenewalComponentCollection(t *testing.T) {
	for _, prior := range []string{planKindFree, planKindPrepaid} {
		for _, tc := range []struct {
			name                    string
			protected, paid, credit int64
			allowed                 bool
		}{
			{"fully credited", 2, 100, 25000, true},
			{"legitimate Pro overage", 2, 30000, 25000, true},
			{"small independent monthly credit", 2, 300, 2, true},
			{"protected cent unpaid", 2, 300, 1, false},
		} {
			t.Run(prior+"/"+tc.name, func(t *testing.T) {
				f, _ := newProCashFixture(t, prior, tc.protected, tc.paid, tc.credit)
				p := billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}
				if err := f.h.enqueueInvoiceCollection(t.Context(), p, f.invoice, true); err != nil {
					t.Fatal(err)
				}
				j := f.claim(t)
				state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
				want := int64(0)
				if tc.allowed {
					want = 1
				}
				if f.pays.Load() != want {
					t.Fatalf("state=%s reason=%s /pay=%d want=%d", state, reason, f.pays.Load(), want)
				}
				var policy string
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT policy FROM billing_invoice_cash_authority WHERE invoice_id=$1`, f.invoice.ID).Scan(&policy); err != nil {
					t.Fatal(err)
				}
				if policy == "residual_allowed" {
					t.Fatal("old historical usage decision was changed")
				}
				t.Logf("prior=%s protected_seconds=%d paid_seconds=%d credit=%d historical_policy=%s state=%s pay_calls=%d reason=%s", prior, tc.protected, tc.paid, tc.credit, policy, state, f.pays.Load(), reason)
			})
		}
	}
}

func TestProFirstRenewalRejectsUnprovedComponents(t *testing.T) {
	for _, which := range []string{"credit_version_zero", "partial_credit_scope", "missing_grant_evidence", "changed_fee", "extra_licensed_line", "wrong_fee_period", "wrong_usage_price", "wrong_currency", "wrong_customer", "wrong_subscription"} {
		t.Run(which, func(t *testing.T) {
			mutate := func(plan *billing.InvoiceClosePlan, inv *StripeInvoiceAmounts) {
				switch which {
				case "credit_version_zero":
					plan.CreditVersion = 0
				case "partial_credit_scope":
					var g entitlementGrant
					_ = json.Unmarshal(plan.CreditGrants[0].Evidence, &g)
					g.Applicability.Scope.PriceType = ""
					_ = json.Unmarshal([]byte(`[{"id":"price_cpu"}]`), &g.Applicability.Scope.Prices)
					plan.CreditGrants[0].Evidence, _ = json.Marshal(g)
				case "missing_grant_evidence":
					plan.CreditGrants[0].Evidence = json.RawMessage(`{}`)
				case "changed_fee":
					inv.Lines.Data[2].Amount--
				case "extra_licensed_line":
					inv.Lines.Data = append(inv.Lines.Data, inv.Lines.Data[2])
				case "wrong_fee_period":
					inv.Lines.Data[2].Period.Start++
				case "wrong_usage_price":
					inv.Lines.Data[0].Pricing.PriceDetails.Price = "price_other"
				case "wrong_currency":
					inv.Currency = "eur"
				case "wrong_customer":
					inv.Customer = "cus_other"
				case "wrong_subscription":
					inv.Parent.SubscriptionDetails.Subscription = "sub_other"
				}
			}
			f, _ := newProCashFixture(t, planKindFree, 2, 30000, 25000, mutate)
			if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
				t.Fatal(err)
			}
			j := f.claim(t)
			state, _ := f.h.collectInvoice(t.Context(), f.client, &j)
			if state != "review_required" || f.pays.Load() != 0 {
				t.Fatal("unproved components acquired cash", state, f.pays.Load())
			}
			var proofs int
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_invoice_cash_authority WHERE invoice_id=$1`, f.invoice.ID).Scan(&proofs); err != nil || proofs != 0 {
				t.Fatal("invalid authority persisted", proofs, err)
			}
		})
	}
}

func TestProFirstRenewalReplayAndSQLGuard(t *testing.T) {
	f, _ := newProCashFixture(t, planKindFree, 2, 30000, 25000)
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatal(state, reason, f.pays.Load())
	}
	state, reason = f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "paid" || f.pays.Load() != 1 {
		t.Fatal("paid replay duplicated payment", state, reason, f.pays.Load())
	}
	var proofs int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_invoice_cash_authority WHERE invoice_id=$1`, f.invoice.ID).Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal(proofs, err)
	}
	// The SQL barrier still refuses a mismatched immutable settlement even with a
	// valid component proof. Perform this on a second untouched fixture.
	blocked, _ := newProCashFixture(t, planKindPrepaid, 2, 300, 1)
	if err := blocked.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: blocked.team, Start: blocked.start, End: blocked.end}, blocked.invoice, true); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.h.Pool.Exec(t.Context(), `UPDATE billing_invoice_collection SET state='unknown',first_attempt_at=clock_timestamp() WHERE invoice_id=$1`, blocked.invoice.ID); err == nil {
		t.Fatal("old writer bypassed protected residual guard")
	}
}

func TestProFirstRenewalPaymentReleasesExactlyOneNextCredit(t *testing.T) {
	for _, prior := range []string{planKindFree, planKindPrepaid} {
		for _, producer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ordinary_close_producer_%v", prior, producer), func(t *testing.T) { testProRenewalNextCredit(t, prior, producer) })
		}
	}
}
func testProRenewalNextCredit(t *testing.T, prior string, producer bool) {
	f, upgrade := newProCashFixtureMode(t, prior, 2, 30000, 25000, producer)
	ctx := t.Context()
	var contract uuid.UUID
	if err := f.h.Pool.QueryRow(ctx, `SELECT contract_id FROM billing_pro_upgrade WHERE id=$1`, upgrade).Scan(&contract); err != nil {
		t.Fatal(err)
	}
	f.h.Config = &config.Config{BillingUsageEntitlementsEnabled: true}
	// The recurring contract remains pending before verified collection.
	if _, err := f.h.reconcileUsageEntitlement(ctx, contract); err != nil {
		t.Fatal(err)
	}
	if f.grantCreates.Load() != 0 {
		t.Fatal("renewal credit issued before payment")
	}
	if err := f.h.enqueueInvoiceCollection(ctx, billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(ctx, f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatal(state, reason, f.pays.Load())
	}
	// The provider stub changes to paid ONLY in response to the actual /pay
	// request. The next collector read must observe that transition.
	state, reason = f.h.collectInvoice(ctx, f.client, &j)
	if state != "paid" {
		t.Fatal(state, reason)
	}
	sub := f.invoice.Parent.SubscriptionDetails.Subscription
	receipt, found, err := f.h.verifyProContractInvoice(ctx, f.client, contract, f.invoice.ID, proOffer{Key: "pro_monthly", Price: "price_pro", Amount: 25000, Months: 1}, f.invoice.Customer, sub)
	if err != nil || !found {
		t.Fatalf("actual paid renewal receipt: found=%v err=%v", found, err)
	}
	_, err = f.h.DB.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: f.team, ContractID: contract, InvoiceID: f.invoice.ID, PaymentReference: receipt.Reference, CustomerID: f.invoice.Customer, SubscriptionID: &sub, BasePriceID: "price_pro", ServicePeriodStart: time.Unix(receipt.Start, 0), ServicePeriodEnd: time.Unix(receipt.End, 0), BaseAmountPaidCents: 25000, InvoiceAmountPaidCents: receipt.Invoice.AmountPaid, Currency: "usd", PaidAt: time.Unix(receipt.Invoice.StatusTransitions.PaidAt, 0), Evidence: receipt.Raw})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: f.team, ContractID: contract})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.DB.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: f.team, ContractID: contract, ExpectedRevision: c.Revision}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = f.h.reconcileUsageEntitlement(ctx, contract); err != nil {
			t.Fatalf("next credit after observed paid renewal: %v", err)
		}
	}
	var count int
	var cents int64
	var grantID string
	if err = f.h.Pool.QueryRow(ctx, `SELECT count(*),max(amount_cents),max(stripe_credit_grant_id) FROM billing_usage_entitlement WHERE contract_id=$1 AND period_start=$2 AND state='issued'`, contract, f.end).Scan(&count, &cents, &grantID); err != nil {
		t.Fatal(err)
	}
	if count != 1 || cents != 25000 || grantID == "" || f.grantCreates.Load() != 1 || f.pays.Load() != 1 {
		t.Fatalf("payment/grant uniqueness: rows=%d cents=%d grant=%s grantPOSTs=%d payPOSTs=%d", count, cents, grantID, f.grantCreates.Load(), f.pays.Load())
	}
}

func TestProFirstRenewalActualCloseProducerFeedsCollection(t *testing.T) {
	f, _ := newProCashFixtureMode(t, planKindFree, 2, 30000, 25000, true)
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatalf("actual close producer did not authorize legitimate renewal+Pro overage: state=%s reason=%s pays=%d", state, reason, f.pays.Load())
	}
	state, reason = f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "paid" || f.pays.Load() != 1 {
		t.Fatal(state, reason, f.pays.Load())
	}
}

func TestProFirstRenewalConcurrentAuthorityAndRevokedSource(t *testing.T) {
	f, upgrade := newProCashFixture(t, planKindFree, 2, 30000, 25000)
	var wg sync.WaitGroup
	results := make(chan error, 4)
	allowed := make(chan bool, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.h.invoiceCollectionCashAllowed(t.Context(), f.invoice)
			allowed <- ok
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	close(allowed)
	successes := 0
	for ok := range allowed {
		if ok {
			successes++
		}
	}
	for err := range results {
		if err != nil {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("unexpected authority race error: %v", err)
			}
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent authority request succeeded")
	}
	var proofs int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_pro_invoice_cash_authority WHERE invoice_id=$1`, f.invoice.ID).Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal(proofs, err)
	}
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	// A later payment review cannot be bypassed with a previously frozen proof.
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade SET payment_review_required=true WHERE id=$1`, upgrade); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, _ := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "review_required" || f.pays.Load() != 0 {
		t.Fatal("reviewed payment reused old cash permission", state, f.pays.Load())
	}
	if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_invoice_collection SET state='unknown',first_attempt_at=clock_timestamp() WHERE invoice_id=$1`, f.invoice.ID); err == nil {
		t.Fatal("old SQL writer reused reviewed source")
	}
}

func TestProFirstRenewalPreservesMappedStarterCalendar(t *testing.T) {
	f, _ := newProCashFixtureMode(t, planKindPrepaid, 2, 30000, 25000, true, func(plan *billing.InvoiceClosePlan, inv *StripeInvoiceAmounts) {
		plan.InvoiceStart += 3600
		inv.PeriodStart = plan.InvoiceStart
	})
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatal("historical provider/commercial calendar mapping lost", state, reason, f.pays.Load())
	}
}

func TestProFirstRenewalUnmarkedStarterCloseProducer(t *testing.T) {
	f, _ := newProCashFixtureMode(t, planKindPrepaid, 2, 30000, 25000, true)
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatalf("actual Starter close producer did not collect renewal: state=%s reason=%s pays=%d", state, reason, f.pays.Load())
	}
}

func TestProFirstRenewalZeroRoundedUnmarkedBridge(t *testing.T) {
	f, upgrade := newProCashFixtureMode(t, planKindPrepaid, 0, 1, 0, true)
	var monthly, bridge int64
	var grant *string
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT (request_payload#>>'{PlanTerms,Credit}')::bigint,bridge_credit_cents,grant_id FROM billing_pro_upgrade WHERE id=$1`, upgrade).Scan(&monthly, &bridge, &grant); err != nil {
		t.Fatal(err)
	}
	if monthly != 1 || bridge != 0 || grant != nil {
		t.Fatal("not the accepted positive-configured zero-rounded bridge", monthly, bridge, grant)
	}
	if rounded, err := proratedProAmount(monthly, f.start, f.end, f.end.Add(-time.Hour)); err != nil || rounded != 0 {
		t.Fatal("legitimate proration did not round to zero", rounded, err)
	}
	if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
		t.Fatal(err)
	}
	j := f.claim(t)
	state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
	if state != "unknown" || f.pays.Load() != 1 {
		t.Fatal("zero bridge with only authorized Pro usage held", state, reason, f.pays.Load())
	}

	account, ok, err := f.h.invoiceAccount(t.Context(), f.team)
	if err != nil || !ok {
		t.Fatal(err)
	}
	later := billing.ExportPeriod{TeamID: f.team, Start: f.end, End: f.end.AddDate(0, 1, 0)}
	handled, err := f.h.prepareFirstProCycleCredits(t.Context(), later, account, "in_next", &billing.InvoiceClosePlan{}, f.client)
	if err != nil || handled {
		t.Fatalf("later recurring allowance must bypass old bridge: handled=%v err=%v", handled, err)
	}
}

// insertProCashFundingPurchase records a purchase; a retained one is a credit
// purchase that kept the team's plan.
func insertProCashFundingPurchase(t *testing.T, h *Handlers, team uuid.UUID, customer, source, state string, at time.Time, retained ...bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var snapshot any
	if len(retained) > 0 && retained[0] {
		snapshot = `{"retain":true}`
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key,created_at,plan_snapshot)
 VALUES($1,$2,$3,$4,500,$5,'','',$6,$7)`, id, team, customer, source, uuid.New(), at, snapshot); err != nil {
		t.Fatal(err)
	}
	switch state {
	case "uncertain":
		if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_prepaid_purchase SET payment_state='uncertain',payment_first_attempt_at=clock_timestamp() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	case "succeeded":
		if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=jsonb_build_object('amount_cents',amount_cents,'customer',customer_id) WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	case "failed":
		if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_prepaid_purchase SET payment_state='failed',failure_reason='conclusively failed' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func TestProInvoiceCashUnresolvedFundingCannotUseComponentProof(t *testing.T) {
	for _, source := range []string{"checkout", "auto_recharge"} {
		for _, payment := range []string{"pending", "uncertain", "succeeded", "failed"} {
			t.Run(source+"/"+payment, func(t *testing.T) {
				// Mutations run before the real prepareInvoicePlan producer. The
				// purchase therefore exists before any cash policy/proof freezes.
				h, _ := newPlanAssignmentFixture(t)
				f, _ := newProCashFixtureMode(t, planKindPrepaid, 2, 30000, 25000, true, func(plan *billing.InvoiceClosePlan, inv *StripeInvoiceAmounts) {
					team := uuid.MustParse(strings.TrimPrefix(inv.Customer, "cus_"))
					insertProCashFundingPurchase(t, h, team, inv.Customer, source, payment, time.Unix(plan.InvoiceStart, 0).Add(-time.Hour))
				})
				f.quiescePrepaidPurchases(t)
				if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
					t.Fatal(err)
				}
				j := f.claim(t)
				state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
				wantState, wantPays, wantProofs := "review_required", int64(0), 0
				if payment == "failed" {
					wantState, wantPays, wantProofs = "unknown", 1, 1
				}
				var proofs int
				var firstAttempt bool
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_pro_invoice_cash_authority WHERE invoice_id=$1),first_attempt_at IS NOT NULL FROM billing_invoice_collection WHERE invoice_id=$1`, f.invoice.ID).Scan(&proofs, &firstAttempt); err != nil {
					t.Fatal(err)
				}
				if state != wantState || f.pays.Load() != wantPays || proofs != wantProofs || firstAttempt != (payment == "failed") {
					t.Fatalf("component funding fence: %s %s pays=%d proofs=%d intent=%v; want %s/%d/%d", state, reason, f.pays.Load(), proofs, firstAttempt, wantState, wantPays, wantProofs)
				}
				if payment != "failed" {
					if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_invoice_collection SET state='unknown',first_attempt_at=clock_timestamp() WHERE invoice_id=$1`, f.invoice.ID); err == nil {
						t.Fatal("old writer bypassed unresolved funding through Pro component proof")
					}
				}
			})
		}
	}
}

func TestProInvoiceCashRetainedProofCannotBypassUnresolvedFunding(t *testing.T) {
	for _, source := range []string{"checkout", "auto_recharge"} {
		for _, payment := range []string{"pending", "uncertain", "succeeded", "failed"} {
			t.Run(source+"/"+payment, func(t *testing.T) {
				f, _ := newProCashFixtureMode(t, planKindPrepaid, 2, 30000, 25000, true)
				f.quiescePrepaidPurchases(t)
				allowed, err := f.h.freezeProInvoiceCash(t.Context(), f.invoice)
				if err != nil || !allowed {
					t.Fatal("legitimate initial component proof unavailable", allowed, err)
				}
				var before string
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(p)::text FROM billing_pro_invoice_cash_authority p WHERE invoice_id=$1`, f.invoice.ID).Scan(&before); err != nil {
					t.Fatal(err)
				}
				// Represent a retained proof from an older writer that omitted
				// this historical purchase. Never edit or replace that proof.
				insertProCashFundingPurchase(t, f.h, f.team, f.invoice.Customer, source, payment, f.start.Add(-time.Hour))
				var valid bool
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT pro_invoice_cash_source_valid($1,$2)`, f.invoice.ID, invoiceSettlementHash(f.invoice)).Scan(&valid); err != nil || valid != (payment == "failed") {
					t.Fatal("retained proof funding validity", valid, err)
				}
				if err := f.h.enqueueInvoiceCollection(t.Context(), billing.ExportPeriod{TeamID: f.team, Start: f.start, End: f.end}, f.invoice, true); err != nil {
					t.Fatal(err)
				}
				j := f.claim(t)
				state, reason := f.h.collectInvoice(t.Context(), f.client, &j)
				if payment != "failed" {
					if state != "review_required" || f.pays.Load() != 0 {
						t.Fatal("retained proof bypassed funding hold", state, reason, f.pays.Load())
					}
					if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_invoice_collection SET state='unknown',first_attempt_at=clock_timestamp() WHERE invoice_id=$1`, f.invoice.ID); err == nil {
						t.Fatal("old SQL writer reused a proof with unresolved funding")
					}
				} else {
					if state != "unknown" || f.pays.Load() != 1 {
						t.Fatal("terminal failure blocked legitimate retained proof", state, reason, f.pays.Load())
					}
					// A payment already observed as paid must still reconcile once,
					// even if additional old funding evidence arrives afterward.
					var intentBefore string
					if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_array(idempotency_key,settlement_hash,payment_authorized,first_attempt_at)::text FROM billing_invoice_collection WHERE invoice_id=$1`, f.invoice.ID).Scan(&intentBefore); err != nil {
						t.Fatal(err)
					}
					insertProCashFundingPurchase(t, f.h, f.team, f.invoice.Customer, source, "pending", f.start.Add(-time.Hour))
					state, reason = f.h.collectInvoice(t.Context(), f.client, &j)
					var intentAfter string
					if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_array(idempotency_key,settlement_hash,payment_authorized,first_attempt_at)::text FROM billing_invoice_collection WHERE invoice_id=$1`, f.invoice.ID).Scan(&intentAfter); err != nil {
						t.Fatal(err)
					}
					if state != "paid" || f.pays.Load() != 1 || intentAfter != intentBefore {
						t.Fatal("paid replay lost accepted intent or duplicated cash", state, reason, f.pays.Load())
					}
				}
				var after string
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(p)::text FROM billing_pro_invoice_cash_authority p WHERE invoice_id=$1`, f.invoice.ID).Scan(&after); err != nil || after != before {
					t.Fatal("retained proof history rewritten", err)
				}
			})
		}
	}
}
