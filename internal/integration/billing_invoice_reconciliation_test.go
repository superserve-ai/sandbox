//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_InvoiceCentRecoveryAndCredits(t *testing.T) {
	for _, offset := range []time.Duration{0, 4 * 24 * time.Hour} {
		t.Run("calendar_offset_"+offset.String(), func(t *testing.T) { testInvoiceCentRecoveryAndCredits(t, offset) })
	}
}

func testInvoiceCentRecoveryAndCredits(t *testing.T, offset time.Duration) {
	for _, tc := range []struct {
		name                     string
		target, provider, credit int64
		loseResponse             bool
		fault                    string
	}{
		{"up full", 106, 105, 1000, true, ""}, {"down full", 105, 106, 1000, true, ""},
		{"up partial", 106, 105, 100, false, ""}, {"down partial", 105, 106, 100, false, ""},
		{"canceled frozen recovery", 106, 105, 1000, true, "canceled"},
		{"replacement frozen recovery", 106, 105, 1000, true, "replacement"},
		{"offsetting resource errors", 106, 105, 1000, false, "offset"}, {"wrong remaining credits", 106, 105, 1000, false, "credit"}, {"late adjustment ignored", 106, 105, 1000, false, "late"}, {"no credit", 106, 105, 0, false, ""}, {"no adjustment", 105, 105, 1000, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			invoiceStart, invoiceEnd := p.Start.Add(offset), p.End.Add(offset)
			customer, subscription := "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String()
			seconds, quantity := "105499.999999", "29.305555555278"
			if tc.target == 106 {
				seconds, quantity = "105500.000001", "29.305555555833"
			}
			providerQuantity := "29.3055555555"
			if tc.provider == 106 {
				providerQuantity = "29.3055555556"
			}
			correctionExec(t, `UPDATE team_billing_usage SET vcpu_seconds=$2::numeric,memory_mib_seconds=0,storage_mib_seconds=0 WHERE team_id=$1`, p.TeamID, seconds)
			if _, err := store.Reserve(t.Context(), p, "cpu", quantity, p.End, billing.ExportPayload{EventName: "example_cpu_hours", CustomerID: customer, Timestamp: p.End.Add(-time.Second).Unix()}); err != nil {
				t.Fatal(err)
			}
			if tc.fault != "canceled" {
				acceptIncrement(t, store, p)
			}
			correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, p.TeamID)
			correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, customer, subscription, p.Start)
			subscriptionStatus := "active"
			if tc.fault == "canceled" || tc.fault == "replacement" {
				subscriptionStatus = "canceled"
				correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='canceled' WHERE team_id=$1`, p.TeamID)
			}
			replacement := "sub_replacement_" + p.TeamID.String()
			replacementHeld := true
			if tc.fault == "replacement" {
				correctionExec(t, `UPDATE billing_invoice_enrollment SET completed_at=now()`)
				correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='active',stripe_subscription_id=$2,commercial_billing_anchor=now() WHERE team_id=$1`, p.TeamID, replacement)
			}
			key := "invoice-test-" + p.TeamID.String()
			insertPricingPlanForTest(t, t.Context(), key, true)
			correctionExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.00001,$2),($1,'storage_gib','second',0.00000003,$2)`, key, p.Start)
			correctionExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, p.TeamID, key, p.Start)
			correctionExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at) VALUES($1,10,10,'independent shadow grant',$2)`, p.TeamID, p.Start)
			if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported' WHERE team_id=$1`, p.TeamID); err == nil {
				t.Fatal("legacy writer bypassed invoice gate")
			}
			invoiceID := "in_" + p.TeamID.String()
			status, auto, coupon := "draft", false, false
			balance, adjustment := tc.credit, int64(0)
			events, finalizations, releases, usageEvents := 0, 0, 0, 0
			price := func(id, meter, amount string) map[string]any {
				return map[string]any{"id": id, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": amount, "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": meter}}
			}
			line := func(id, pr, amount string, value int64) map[string]any {
				if tc.fault == "offset" && status != "draft" {
					if pr == "price_cpu" {
						value--
					}
					if pr == "price_storage" {
						value++
					}
				}
				return map[string]any{"id": id, "amount": value, "currency": "usd", "period": map[string]any{"start": invoiceStart.Unix(), "end": invoiceEnd.Unix()}, "pricing": map[string]any{"unit_amount_decimal": amount, "price_details": map[string]any{"price": pr}}, "parent": map[string]any{"subscription_item_details": map[string]any{"subscription": subscription, "subscription_item": "si_" + pr, "proration": false}}}
			}
			invoice := func() map[string]any {
				subtotal := tc.provider + adjustment
				if tc.fault == "late" && status != "draft" {
					subtotal = tc.provider
				}
				applied, net := int64(0), subtotal
				discount := int64(0)
				if coupon {
					discount = 1
					net--
				}
				if status != "draft" {
					a, _ := billing.AllocateInvoiceCredits(net, tc.credit)
					applied, net = a.AppliedCents, a.PayableCents
				}
				credits := []any{}
				if applied > 0 {
					credits = append(credits, map[string]any{"type": "credit_balance_transaction", "amount": applied, "credit_balance_transaction": "cbtxn_example"})
				}
				discounts := []any{}
				discountAmounts := []any{}
				if coupon {
					discounts = append(discounts, map[string]any{"id": "di_example", "source": map[string]any{"coupon": map[string]any{"id": "rounding_" + invoiceID}}})
					discountAmounts = append(discountAmounts, map[string]any{"amount": discount})
				}
				due, ending := net, int64(0)
				if net > 0 && net < 50 {
					due, ending = 0, net
				}
				return map[string]any{"id": invoiceID, "customer": customer, "currency": "usd", "billing_reason": "subscription_cycle", "period_start": invoiceStart.Unix(), "period_end": invoiceEnd.Unix(), "status": status, "auto_advance": auto, "subtotal": subtotal, "total": net, "amount_due": due, "starting_balance": 0, "ending_balance": ending, "discounts": discounts, "total_discount_amounts": discountAmounts, "total_pretax_credit_amounts": credits, "parent": map[string]any{"subscription_details": map[string]any{"subscription": subscription}}, "lines": map[string]any{"data": []any{line("il_cpu", "price_cpu", "3.6", tc.provider), line("il_round", "price_round", "1", adjustment), line("il_storage", "price_storage", "0.0108", 0)}, "has_more": false}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				var out any
				switch r.URL.Path {
				case "/v1/prices/price_storage":
					out = price("price_storage", "mtr_storage", "0.0108")
				case "/v1/prices/price_cpu":
					out = price("price_cpu", "mtr_cpu", "3.6")
				case "/v1/invoices":
					out = map[string]any{"data": []any{invoice()}, "has_more": false}
				case "/v1/prices/price_round":
					out = price("price_round", "mtr_round", "1.00")
				case "/v1/subscriptions":
					data := []any{map[string]any{"id": subscription, "status": subscriptionStatus}}
					if tc.fault == "replacement" {
						data = append(data, map[string]any{"id": replacement, "status": "active"})
					}
					out = map[string]any{"data": data, "has_more": false}
				case "/v1/subscriptions/" + replacement:
					out = map[string]any{"id": replacement, "customer": customer, "billing_cycle_anchor": invoiceStart.Unix(), "status": "active", "items": map[string]any{"data": []any{map[string]any{"id": "si_cpu_new", "current_period_start": invoiceStart.Unix(), "current_period_end": invoiceEnd.Unix(), "price": price("price_cpu", "mtr_cpu", "3.6")}, map[string]any{"id": "si_round_new", "price": price("price_round", "mtr_round", "1")}, map[string]any{"id": "si_storage_new", "current_period_start": invoiceStart.Unix(), "current_period_end": invoiceEnd.Unix(), "price": price("price_storage", "mtr_storage", "0.0108")}}}}
					if replacementHeld {
						out.(map[string]any)["pause_collection"] = map[string]any{"behavior": "keep_as_draft"}
					}
				case "/v1/subscriptions/" + subscription:
					out = map[string]any{"id": subscription, "customer": customer, "billing_cycle_anchor": invoiceStart.Unix(), "status": subscriptionStatus, "pause_collection": map[string]any{"behavior": "keep_as_draft"}, "items": map[string]any{"data": []any{map[string]any{"id": "si_cpu", "current_period_start": invoiceStart.Unix(), "current_period_end": invoiceEnd.Unix(), "price": price("price_cpu", "mtr_cpu", "3.6")}, map[string]any{"id": "si_round", "price": price("price_round", "mtr_round", "1")}, map[string]any{"id": "si_storage", "current_period_start": invoiceStart.Unix(), "current_period_end": invoiceEnd.Unix(), "price": price("price_storage", "mtr_storage", "0.0108")}}}}
				case "/v1/billing/meters":
					data := []any{}
					for _, m := range []struct{ id, event string }{{"mtr_cpu", "example_cpu_hours"}, {"mtr_round", "round"}, {"mtr_storage", "storage_gib_hours"}} {
						data = append(data, map[string]any{"id": m.id, "event_name": m.event, "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}})
					}
					out = map[string]any{"data": data, "has_more": false}
				case "/v1/billing/meters/mtr_storage/event_summaries":
					out = map[string]any{"data": []any{}, "has_more": false}
				case "/v1/billing/meters/mtr_cpu/event_summaries":
					if offset > 0 && tc.fault == "" && (r.URL.Query().Get("start_time") != strconv.FormatInt(invoiceStart.Unix(), 10) || r.URL.Query().Get("end_time") != strconv.FormatInt(invoiceEnd.Unix(), 10)) {
						t.Errorf("provider usage queried outside mapped invoice: %s", r.URL)
					}
					if tc.fault == "canceled" && usageEvents == 0 {
						out = map[string]any{"data": []any{}, "has_more": false}
						break
					}
					out = map[string]any{"data": []any{map[string]any{"aggregated_value": json.Number(providerQuantity)}}, "has_more": false}
				case "/v1/billing/meters/mtr_round/event_summaries":
					out = map[string]any{"data": []any{map[string]any{"aggregated_value": adjustment}}, "has_more": false}
				case "/v1/billing/meter_events":
					if r.Form.Get("event_name") == "example_cpu_hours" {
						usageEvents++
						if tc.fault != "canceled" || r.Form.Get("payload[value]") != quantity {
							t.Errorf("unexpected resource delivery %v", r.Form)
						}
						out = map[string]any{"identifier": r.Form.Get("identifier")}
						break
					}
					events++
					if r.Form.Get("identifier") != "invoice-cent:"+invoiceID || r.Header.Get("Idempotency-Key") == "" {
						t.Error("correction lacks durable identity")
					}
					adjustment, _ = strconv.ParseInt(r.Form.Get("payload[value]"), 10, 64)
					out = map[string]any{"identifier": r.Form.Get("identifier")}
				case "/v1/billing/credit_grants":
					data := []any{}
					if tc.credit > 0 {
						data = append(data, map[string]any{"id": "credgr_example", "effective_at": p.Start.Unix(), "applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}}})
					}
					out = map[string]any{"data": data, "has_more": false}
				case "/v1/billing/credit_balance_summary":
					out = map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": balance}}}}}
				case "/v1/coupons/rounding_" + invoiceID:
					http.Error(w, `{"error":{"message":"missing"}}`, 404)
					return
				case "/v1/coupons":
					out = map[string]any{"id": "rounding_" + invoiceID, "amount_off": 1, "currency": "usd"}
				case "/v1/invoices/" + invoiceID:
					if r.Method == http.MethodPost {
						if r.Form.Get("auto_advance") == "true" {
							auto = true
							releases++
							if tc.loseResponse && releases == 1 {
								http.Error(w, `{"error":{"message":"release response lost"}}`, 500)
								return
							}
						} else if r.Form.Get("discounts[0][coupon]") == "rounding_"+invoiceID {
							coupon = true
						} else {
							t.Errorf("unexpected invoice write %v", r.Form)
						}
					}
					out = invoice()
				case "/v1/invoices/" + invoiceID + "/finalize":
					if r.Form.Get("auto_advance") != "false" {
						t.Error("collection enabled during finalization")
					}
					finalizations++
					status = "open"
					allocation, _ := billing.AllocateInvoiceCredits(tc.target, tc.credit)
					balance = allocation.RemainingCents
					if tc.fault == "credit" {
						balance++
					}
					if tc.loseResponse && finalizations == 1 {
						http.Error(w, `{"error":{"message":"response lost"}}`, 500)
						return
					}
					out = invoice()
				default:
					t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
					http.Error(w, "unsupported", 400)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			cfg := &config.Config{StripeSecretKey: "sk_test_example", StripeAPIBaseURL: server.URL, StripeAPIVersion: "2026-05-27.dahlia", BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_cpu", StripeEventName: "example_cpu_hours", Billable: true, CheckoutEnabled: true}, {ResourceKey: "storage_gib", StripePriceID: "price_storage", StripeEventName: "storage_gib_hours", Billable: false, CheckoutEnabled: true}}}
			newHandler := func() *api.Handlers {
				h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
				h.Pool = testPool
				h.Stripe = api.NewStripeBillingClient(cfg)
				return h
			}
			if tc.fault == "replacement" {
				replacementHeld = false
				if err := newHandler().VerifyInvoiceExportHoldForTest(t.Context(), p); err == nil {
					t.Fatal("unheld replacement accepted")
				}
				if err := newHandler().ReconcileInvoiceForTest(t.Context(), p); err == nil {
					t.Fatal("unheld replacement reconciled")
				}
				if events != 0 || finalizations != 0 {
					t.Fatal("unheld replacement caused financial side effects")
				}
				replacementHeld = true
			}
			if err := newHandler().VerifyInvoiceExportHoldForTest(t.Context(), p); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 4; i++ {
				var err error
				if tc.fault == "canceled" {
					correctionExec(t, `UPDATE billing_export_work SET next_run_at=now()+interval '10 years',next_reconcile_at=now()+interval '10 years'`)
					correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start)
					correctionExec(t, `INSERT INTO billing_export_work(team_id,next_run_at) VALUES($1,now()-interval '1 hour') ON CONFLICT(team_id) DO UPDATE SET next_run_at=EXCLUDED.next_run_at,lease_until=NULL`, p.TeamID)
					var worked bool
					var measured int
					worked, measured, err = newHandler().IncrementalBillingTickForTest(t.Context())
					if measured != 0 {
						t.Fatal("canceled recovery measured new usage")
					}
					if i == 0 && !worked {
						t.Fatal("frozen canceled period not claimed")
					}
				} else {
					err = newHandler().ReconcileInvoiceForTest(t.Context(), p)
				}
				if err != nil && (tc.fault == "" || tc.fault == "canceled" || tc.fault == "replacement") && !strings.Contains(err.Error(), "aggregation") && !strings.Contains(err.Error(), "500") {
					t.Fatal(err)
				}
			}
			if tc.fault != "" && tc.fault != "canceled" && tc.fault != "replacement" {
				if auto || releases != 0 {
					t.Fatal("invalid settlement released collection")
				}
				if finalizations != 1 {
					t.Fatalf("finalized %d times", finalizations)
				}
				if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported' WHERE team_id=$1`, p.TeamID); err == nil {
					t.Fatal("invalid invoice bypassed close gate")
				}
				return
			}
			var savedState string
			if err := testPool.QueryRow(t.Context(), `SELECT state FROM billing_invoice_close WHERE team_id=$1`, p.TeamID).Scan(&savedState); err != nil || savedState != "verified" {
				t.Fatalf("state=%s err=%v", savedState, err)
			}
			var saved []byte
			if err := testPool.QueryRow(t.Context(), `SELECT plan FROM billing_invoice_close WHERE team_id=$1`, p.TeamID).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			var planned billing.InvoiceClosePlan
			if err := json.Unmarshal(saved, &planned); err != nil {
				t.Fatal(err)
			}
			if planned.ExpectedCents != tc.target || planned.AdjustmentCents != tc.target-tc.provider {
				t.Fatalf("boundary plan=%+v", planned)
			}
			if _, err := testPool.Exec(t.Context(), `UPDATE billing_invoice_close SET plan=jsonb_set(plan,'{expected_cents}','999') WHERE team_id=$1`, p.TeamID); err == nil {
				t.Fatal("verified plan was mutable")
			}
			if auto || releases != 0 {
				t.Fatal("collection released before local accounting")
			}
			if tc.fault == "replacement" {
				if err := newHandler().ExportInvoicePeriodForTest(t.Context(), p); err != nil {
					t.Fatalf("historical export used replacement scope or anchor: %v", err)
				}
			}
			if tc.fault == "canceled" {
				var exported bool
				if err := testPool.QueryRow(t.Context(), `SELECT status='exported' FROM team_billing_period WHERE team_id=$1`, p.TeamID).Scan(&exported); err != nil || !exported || usageEvents != 1 {
					t.Fatalf("canceled worker progression: exported=%v usage events=%d err=%v", exported, usageEvents, err)
				}
			} else {
				correctionExec(t, `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, p.TeamID)
			}
			result, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End)
			if err != nil {
				t.Fatal(err)
			}
			if got := numericFloat64(t, result.Period.GrossChargesUsd); got != float64(tc.target)/100 {
				t.Fatalf("gross=%v", got)
			}
			var untouched bool
			if err = testPool.QueryRow(t.Context(), `SELECT remaining_usd=10 FROM team_credit_grant WHERE team_id=$1`, p.TeamID).Scan(&untouched); err != nil || !untouched {
				t.Fatal("shadow credits debited", err)
			}
			release := func() error {
				if tc.fault == "canceled" {
					correctionExec(t, `UPDATE billing_invoice_account SET last_attempt_at=now()+interval '10 years' WHERE team_id<>$1`, p.TeamID)
					worked, err := newHandler().InvoiceReconciliationTickForTest(t.Context())
					if !worked {
						t.Fatal("canceled invoice release not scheduled")
					}
					return err
				}
				return newHandler().ReconcileInvoiceForTest(t.Context(), p)
			}
			if err = release(); err != nil && !(tc.loseResponse && strings.Contains(err.Error(), "500")) {
				t.Fatal(err)
			}
			if err = release(); err != nil {
				t.Fatal(err)
			}
			wantEvents := 0
			if tc.target > tc.provider {
				wantEvents = 1
			}
			if events != wantEvents || finalizations != 1 || releases != 1 {
				t.Fatalf("duplicate provider writes: events=%d finalize=%d release=%d", events, finalizations, releases)
			}
			if offset > 0 && tc.name == "up full" {
				next := billing.ExportPeriod{TeamID: p.TeamID, Start: p.End, End: p.End.AddDate(0, 1, 0)}
				correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, next.TeamID, next.Start, next.End)
				h := newHandler()
				h.Now = func() time.Time { return next.Start.Add(time.Hour) }
				if err := h.VerifyInvoiceExportHoldForTest(t.Context(), next); err == nil || !strings.Contains(err.Error(), "waiting for mapped invoice cycle") {
					t.Fatalf("next-period export was not deferred: %v", err)
				}
				h.Now = func() time.Time { return invoiceEnd.Add(time.Hour) }
				if err := h.VerifyInvoiceExportHoldForTest(t.Context(), next); err != nil {
					t.Fatalf("next-period export did not resume: %v", err)
				}
				var nextStart, nextEnd time.Time
				if err := testPool.QueryRow(t.Context(), `SELECT invoice_start,invoice_end FROM billing_invoice_calendar WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, next.TeamID, next.Start, next.End).Scan(&nextStart, &nextEnd); err != nil || !nextStart.Equal(invoiceEnd) || !nextEnd.Equal(invoiceEnd.AddDate(0, 1, 0)) {
					t.Fatalf("next mapping=%v %v err=%v", nextStart, nextEnd, err)
				}
			}
			if tc.fault == "replacement" {
				if worked, err := newHandler().InvoiceEnrollmentTickForTest(t.Context()); !worked || err != nil {
					t.Fatalf("replacement did not resume after historical release: %v %v", worked, err)
				}
				var ready bool
				if err := testPool.QueryRow(t.Context(), `SELECT a.subscription_id=$2 AND w.completed_at IS NOT NULL FROM billing_invoice_account a JOIN billing_invoice_enrollment w USING(team_id) WHERE team_id=$1`, p.TeamID, replacement).Scan(&ready); err != nil || !ready {
					t.Fatalf("replacement association not completed: %v %v", ready, err)
				}
			}
		})
	}
}

func TestIntegration_InvoiceEnrollmentConflictDoesNotMutateProvider(t *testing.T) {
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	_, p := seedIncrementalPeriod(t)
	customer, sub := "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String()
	correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, customer, sub, p.Start)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "unexpected", 500) }))
	defer server.Close()
	client := api.NewStripeBillingClient(&config.Config{StripeSecretKey: "sk_test_example", StripeAPIVersion: "2026-05-27.dahlia", StripeAPIBaseURL: server.URL})
	router := newBillingRouterWithPool(t, client, testPool)
	actor := seedPlatformAdminProfile(t)
	response := doBillingOperator(router, "/internal/teams/"+p.TeamID.String()+"/billing/invoice-reconciliation", operatorRBACToken, actor.String(), `{"adjustment_price_id":"price_different","adjustment_event_name":"different"}`)
	if response.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body)
	}
}

func TestIntegration_InvoiceAssociationFailureYieldsQueue(t *testing.T) {
	_, bad := seedIncrementalPeriod(t)
	_, good := seedIncrementalPeriod(t)
	correctionExec(t, `UPDATE billing_invoice_account SET last_attempt_at=now()+interval '10 years'`)
	for _, p := range []billing.ExportPeriod{bad, good} {
		correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, p.TeamID)
		correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String(), p.Start)
	}
	correctionExec(t, `UPDATE billing_invoice_account SET last_attempt_at=now()-interval '1 hour' WHERE team_id=$1`, good.TeamID)
	correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, bad.TeamID, "sub_replacement_"+bad.TeamID.String())
	correctionExec(t, `UPDATE billing_invoice_enrollment SET requested_at=$2 WHERE team_id=$1`, bad.TeamID, bad.Start.Add(15*24*time.Hour))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "fixture provider unavailable", 400)
	}))
	defer server.Close()
	cfg := &config.Config{StripeSecretKey: "sk_test_fixture", StripeAPIBaseURL: server.URL, StripeAPIVersion: "2026-05-27.dahlia"}
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
	h.Pool, h.Stripe = testPool, api.NewStripeBillingClient(cfg)
	if worked, err := h.InvoiceReconciliationTickForTest(t.Context()); !worked || err == nil || !strings.Contains(err.Error(), "association changed") {
		t.Fatalf("expected association failure: %v %v", worked, err)
	}
	var attempted bool
	var lastError *string
	if err := testPool.QueryRow(t.Context(), `SELECT last_attempt_at IS NOT NULL,last_error FROM billing_invoice_account WHERE team_id=$1`, bad.TeamID).Scan(&attempted, &lastError); err != nil || !attempted || lastError == nil || calls != 0 {
		t.Fatalf("failure not recorded or unsafe provider access: %v %v calls=%d err=%v", attempted, lastError, calls, err)
	}
	if worked, err := h.InvoiceReconciliationTickForTest(t.Context()); !worked || err == nil || strings.Contains(err.Error(), "association changed") || calls == 0 {
		t.Fatalf("next team starved: %v %v calls=%d", worked, err, calls)
	}
}

func TestIntegration_InvoiceCanceledRecoveryEligibility(t *testing.T) {
	correctionExec(t, `WITH fixtures AS (
        INSERT INTO team(name) SELECT 'invoice-discovery-'||gen_random_uuid()::text FROM generate_series(1,101) RETURNING id
    ) INSERT INTO team_billing_account(team_id) SELECT id FROM fixtures`)
	for _, tc := range []struct {
		name, status, period string
		enrolled, discover   bool
	}{
		{"frozen canceled", "canceled", "exporting", true, true},
		{"open canceled", "canceled", "open", true, false},
		{"approved canceled", "canceled", "approved", true, false},
		{"unenrolled canceled", "canceled", "exporting", false, false},
		{"inactive frozen", "unpaid", "exporting", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p := seedIncrementalPeriod(t)
			correctionExec(t, `UPDATE billing_export_work SET next_run_at=now()+interval '10 years',next_reconcile_at=now()+interval '10 years'`)
			correctionExec(t, `UPDATE team_billing_period SET status=$2 WHERE team_id=$1`, p.TeamID, tc.period)
			correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status=$2,commercial_billing_anchor=$3 WHERE team_id=$1`, p.TeamID, tc.status, p.Start)
			if tc.enrolled {
				correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, p.TeamID, "cus_"+p.TeamID.String(), "sub_"+p.TeamID.String(), p.Start)
			}
			h := api.NewHandlers(&stubVMD{}, db.New(testPool), &config.Config{})
			h.Pool = testPool
			correctionExec(t, `DELETE FROM billing_export_work WHERE team_id=$1`, p.TeamID)
			correctionExec(t, `UPDATE billing_export_discovery SET after_team=NULL,next_run_at=now()`)
			var accounts int
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_billing_account`).Scan(&accounts); err != nil {
				t.Fatal(err)
			}
			complete := false
			pages := 0
			for ; pages <= accounts/100 && !complete; pages++ {
				correctionExec(t, `UPDATE billing_export_discovery SET next_run_at=now()`)
				if err := h.DiscoverIncrementalBillingWorkForTest(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := testPool.QueryRow(t.Context(), `SELECT after_team IS NULL FROM billing_export_discovery`).Scan(&complete); err != nil {
					t.Fatal(err)
				}
			}
			if !complete || pages < 2 {
				t.Fatalf("discovery did not finish multiple batches: pages=%d complete=%v", pages, complete)
			}
			var discovered bool
			if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_export_work WHERE team_id=$1)`, p.TeamID).Scan(&discovered); err != nil || discovered != tc.discover {
				t.Fatalf("discovery=%v err=%v", discovered, err)
			}
			correctionExec(t, `UPDATE billing_export_work SET next_run_at=now()+interval '10 years',next_reconcile_at=now()+interval '10 years'`)
			correctionExec(t, `INSERT INTO billing_export_work(team_id,next_run_at) VALUES($1,now()-interval '1 hour') ON CONFLICT(team_id) DO UPDATE SET next_run_at=EXCLUDED.next_run_at,lease_until=NULL`, p.TeamID)
			if tc.discover {
				correctionExec(t, `UPDATE billing_export_work SET next_reconcile_at=now()-interval '1 day' WHERE team_id=$1`, p.TeamID)
			}
			worked, measured, err := h.IncrementalBillingTickForTest(t.Context())
			if worked != tc.discover || measured != 0 {
				t.Fatalf("claimed=%v measured=%d err=%v", worked, measured, err)
			}
			if tc.discover {
				if err == nil {
					t.Fatal("missing provider should fail recovery")
				}
				if worked, _, err := h.IncrementalBillingTickForTest(t.Context()); worked || err != nil {
					t.Fatalf("canceled retry ignored backoff: %v %v", worked, err)
				}
				_, other := seedIncrementalPeriod(t)
				correctionExec(t, `INSERT INTO billing_export_work(team_id,next_run_at) VALUES($1,now()-interval '1 hour') ON CONFLICT(team_id) DO UPDATE SET next_run_at=EXCLUDED.next_run_at,lease_until=NULL`, other.TeamID)
				if worked, _, err := h.IncrementalBillingTickForTest(t.Context()); !worked {
					t.Fatalf("other due team starved: %v", err)
				}
			}
		})
	}
}

func TestIntegration_InvoiceLegacyShadowHandoff(t *testing.T) {
	team, _, start, end := seedBillingPeriodForStripe(t, true, true)
	p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
	correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, p.TeamID)
	sent := false
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		var out any
		switch r.URL.Path {
		case "/v1/billing/meters":
			out = map[string]any{"data": []any{map[string]any{"id": "mtr_cpu", "event_name": "example_cpu_hours", "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}}}, "has_more": false}
		case "/v1/billing/meters/mtr_cpu/event_summaries":
			quantity := 0
			if sent {
				quantity = 2
			}
			out = map[string]any{"data": []any{map[string]any{"aggregated_value": quantity}}, "has_more": false}
		case "/v1/billing/meter_events":
			if r.Form.Get("payload[value]") != "2.000000000000" {
				t.Errorf("unexpected usage: %v", r.Form)
			}
			sent = true
			writes++
			out = map[string]any{"identifier": r.Form.Get("identifier")}
		default:
			t.Errorf("unexpected enrollment or provider call %s", r.URL)
			http.Error(w, "unexpected", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	cfg := &config.Config{StripeSecretKey: "sk_test_fixture", StripeAPIVersion: "2026-05-27.dahlia", StripeAPIBaseURL: server.URL, BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_cpu", StripeEventName: "example_cpu_hours", Billable: true, CheckoutEnabled: true}}}
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
	h.Pool, h.Stripe = testPool, api.NewStripeBillingClient(cfg)
	if err := h.VerifyInvoiceExportHoldForTest(t.Context(), p); err == nil {
		t.Fatal("unanchored account without legacy handoff accepted")
	}
	correctionExec(t, `INSERT INTO billing_usage_export(team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status) VALUES($1,$2,$3,'cpu',$4,'example_cpu_hours',2,'skipped_shadow')`, p.TeamID, p.Start, p.End, "legacy_"+p.TeamID.String())
	if err := h.ExportInvoicePeriodForTest(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	var closed, enrolled bool
	if err := testPool.QueryRow(t.Context(), `SELECT status='exported',EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1) FROM team_billing_period WHERE team_id=$1`, p.TeamID).Scan(&closed, &enrolled); err != nil || !closed || enrolled || writes != 1 {
		t.Fatalf("closed=%v enrolled=%v writes=%d err=%v", closed, enrolled, writes, err)
	}
}
