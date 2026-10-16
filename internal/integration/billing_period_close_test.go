//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_AutomaticBillingClose(t *testing.T) {
	for _, mode := range []string{"clean", "anomaly", "future", "response_loss", "pre_enrollment", "provider_future", "nonzero", "missing_enrollment", "earlier_held", "unicode_error", "disabled_exporting", "disabled_exported", "disabled_finalized", "disabled_open"} {
		t.Run(mode, func(t *testing.T) {
			disabledFrozen := strings.HasPrefix(mode, "disabled_") && mode != "disabled_open"
			nonzero := mode == "nonzero" || mode == "earlier_held" || disabledFrozen
			team, _, start, end := seedBillingPeriodForStripe(t, false, true)
			correctionExec(t, `UPDATE team_billing_period SET status='open' WHERE team_id=$1`, team)
			if !nonzero {
				correctionExec(t, `DELETE FROM sandbox_compute_billing_interval WHERE team_id=$1`, team)
			}
			correctionExec(t, `DELETE FROM sandbox_storage_interval WHERE team_id=$1`, team)
			correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, team, start)
			customer, sub, invoiceID := "cus_"+team.String(), "sub_"+team.String(), "in_"+team.String()
			enrolled := start
			if mode == "earlier_held" {
				enrolled = start.AddDate(0, -1, 0)
			}
			if mode == "pre_enrollment" {
				enrolled = end.Add(time.Hour)
			}
			correctionExec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','invoice_rounding_cents_v1','mtr_round',$4)`, team, customer, sub, enrolled)
			if mode == "missing_enrollment" {
				correctionExec(t, `DELETE FROM billing_invoice_account WHERE team_id=$1`, team)
				correctionExec(t, `UPDATE billing_invoice_enrollment SET started_at=$2 WHERE team_id=$1`, team, start)
			}
			if mode == "anomaly" {
				correctionExec(t, `INSERT INTO billing_period_anomaly(team_id,period_start,period_end,severity,kind) VALUES($1,$2,$3,'error','test_incomplete')`, team, start, end)
			}
			status, auto := "draft", false
			charge := int64(0)
			if nonzero {
				charge = 7
			}
			usageEvents := 0
			invoiceStart, invoiceEnd := start, end
			if mode == "provider_future" {
				invoiceStart, invoiceEnd = start.Add(4*24*time.Hour), end.Add(4*24*time.Hour)
			}

			finalizations, releases := 0, 0
			price := func(id, meter, amount string) map[string]any {
				return map[string]any{"id": id, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": amount, "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": meter}}
			}
			line := func(pr, amount string) map[string]any {
				return map[string]any{"id": "il_" + pr, "amount": func() int64 {
					if pr == "price_cpu" {
						return charge
					}
					return 0
				}(), "currency": "usd", "period": map[string]any{"start": invoiceStart.Unix(), "end": invoiceEnd.Unix()}, "pricing": map[string]any{"unit_amount_decimal": amount, "price_details": map[string]any{"price": pr}}, "parent": map[string]any{"subscription_item_details": map[string]any{"subscription": sub, "subscription_item": "si_" + pr, "proration": false}}}
			}
			invoice := func() map[string]any {
				return map[string]any{"id": invoiceID, "customer": customer, "currency": "usd", "billing_reason": "subscription_cycle", "period_start": invoiceStart.Unix(), "period_end": invoiceEnd.Unix(), "status": status, "auto_advance": auto, "subtotal": charge, "total": charge, "amount_due": 0, "starting_balance": 0, "ending_balance": charge, "parent": map[string]any{"subscription_details": map[string]any{"subscription": sub}}, "lines": map[string]any{"data": []any{line("price_cpu", "3.6"), line("price_round", "1")}, "has_more": false}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				var out any
				switch r.URL.Path {
				case "/v1/prices":
					out = map[string]any{"data": []any{price("price_round", "mtr_round", "1")}, "has_more": false}
				case "/v1/prices/price_cpu":
					out = price("price_cpu", "mtr_cpu", "3.6")
				case "/v1/prices/price_round":
					out = price("price_round", "mtr_round", "1")
				case "/v1/subscriptions":
					out = map[string]any{"data": []any{map[string]any{"id": sub, "status": "active"}}, "has_more": false}
				case "/v1/subscriptions/" + sub:
					if mode == "unicode_error" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": strings.Repeat("\u2603", 800)}})
						return
					}
					out = map[string]any{"id": sub, "customer": customer, "status": "active", "billing_cycle_anchor": invoiceStart.Unix(), "pause_collection": map[string]any{"behavior": "keep_as_draft"}, "items": map[string]any{"data": []any{map[string]any{"id": "si_price_cpu", "current_period_start": invoiceStart.Unix(), "current_period_end": invoiceEnd.Unix(), "price": price("price_cpu", "mtr_cpu", "3.6")}, map[string]any{"id": "si_price_round", "price": price("price_round", "mtr_round", "1")}}}}
				case "/v1/billing/meters":
					out = map[string]any{"data": []any{map[string]any{"id": "mtr_cpu", "event_name": "example_cpu_hours", "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}}, map[string]any{"id": "mtr_round", "event_name": "invoice_rounding_cents_v1", "default_aggregation": map[string]any{"formula": "sum"}, "customer_mapping": map[string]any{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]any{"event_payload_key": "value"}}}, "has_more": false}
				case "/v1/billing/meter_events":
					if r.Form.Get("event_name") != "example_cpu_hours" || r.Form.Get("payload[value]") != "2.000000000000" {
						t.Errorf("unexpected usage %v", r.Form)
					}
					usageEvents++
					out = map[string]any{"identifier": r.Form.Get("identifier")}
				case "/v1/billing/meters/mtr_cpu/event_summaries":
					if nonzero && usageEvents > 0 {
						out = map[string]any{"data": []any{map[string]any{"aggregated_value": 2}}, "has_more": false}
					} else {
						out = map[string]any{"data": []any{}, "has_more": false}
					}
				case "/v1/billing/meters/mtr_round/event_summaries":
					out = map[string]any{"data": []any{}, "has_more": false}
				case "/v1/billing/credit_grants":
					out = map[string]any{"data": []any{}, "has_more": false}
				case "/v1/billing/credit_balance_summary":
					out = map[string]any{"balances": []any{map[string]any{"available_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": 0}}}}}
				case "/v1/invoices":
					out = map[string]any{"data": []any{invoice()}, "has_more": false}
				case "/v1/invoices/" + invoiceID:
					if r.Method == http.MethodPost {
						if r.Form.Get("auto_advance") != "true" {
							t.Errorf("unexpected write %v", r.Form)
						}
						auto = true
						releases++
						if mode == "response_loss" && releases == 1 {
							http.Error(w, "lost release", 500)
							return
						}
					}
					out = invoice()
				case "/v1/invoices/" + invoiceID + "/finalize":
					if r.Form.Get("auto_advance") != "false" {
						t.Error("early collection")
					}
					status = "open"
					finalizations++
					out = invoice()
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.Error(w, "unexpected", 400)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			cfg := &config.Config{StripeSecretKey: "sk_test_example", StripeAPIBaseURL: server.URL, StripeAPIVersion: "2026-05-27.dahlia", BillingResources: []config.BillingResourceConfig{{ResourceKey: "vcpu", StripePriceID: "price_cpu", StripeEventName: "example_cpu_hours", Billable: true, CheckoutEnabled: true}}}
			newHandler := func() *api.Handlers {
				h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
				h.Pool = testPool
				h.Stripe = api.NewStripeBillingClient(cfg)
				if mode == "provider_future" {
					h.Now = func() time.Time { return end.Add(time.Hour) }
				}
				if mode == "future" {
					h.Now = func() time.Time { return end.Add(-time.Second) }
				}
				return h
			}
			key := "auto-close-" + team.String()
			insertPricingPlanForTest(t, t.Context(), key, true)
			correctionExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0.00001,$2)`, key, start)
			correctionExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, key, start)
			if mode == "earlier_held" || disabledFrozen {
				// Start recovery after provider verification but before local close.
				correctionExec(t, `UPDATE team_billing_period SET status='approved' WHERE team_id=$1`, team)
				if disabledFrozen {
					correctionExec(t, `UPDATE team_billing_period SET approved_at=now(),approved_by=$2,approval_source='human' WHERE team_id=$1`, team, seedPlatformAdminProfile(t))
				}
				for i := 0; i < 3; i++ {
					_ = newHandler().ExportInvoicePeriodForTest(t.Context(), billing.ExportPeriod{TeamID: team, Start: start, End: end})
				}
				var verified bool
				if err := testPool.QueryRow(t.Context(), `SELECT state='verified' FROM billing_invoice_close WHERE team_id=$1`, team).Scan(&verified); err != nil || !verified {
					t.Fatalf("setup did not verify later invoice: %v %v", verified, err)
				}
				if mode == "earlier_held" {
					correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, enrolled, start)
					correctionExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,99,99,'audit-only local fixture')`, team)
				}
				if mode == "disabled_exporting" {
					// Model a crash after provider verification, before marking exported.
					correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, team)
				}
				if mode == "disabled_finalized" {
					if _, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, team, start, end, newHandler().ResolveActiveBillingMeter); err != nil {
						t.Fatal(err)
					}
				}
			}
			if disabledFrozen || mode == "disabled_open" {
				correctionExec(t, `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, team)
			}
			// Drive discovery rather than inserting a close record or approving manually.
			correctionExec(t, `UPDATE billing_period_close_discovery SET after_team='00000000-0000-0000-0000-000000000000',after_start='-infinity',after_end='-infinity',next_run_at=now()`)
			for page := 0; ; page++ {
				if page == 100 {
					t.Fatal("discovery did not complete its bounded sweep")
				}
				if err := newHandler().DiscoverBillingPeriodCloseForTest(t.Context()); err != nil {
					t.Fatal(err)
				}
				var after uuid.UUID
				if err := testPool.QueryRow(t.Context(), `SELECT after_team FROM billing_period_close_discovery`).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if after == uuid.Nil {
					break
				}
				correctionExec(t, `UPDATE billing_period_close_discovery SET next_run_at=now()`)
			}
			correctionExec(t, `UPDATE billing_period_close_work SET next_attempt_at=now()+interval '10 years' WHERE team_id<>$1`, team)
			if mode == "earlier_held" {
				correctionExec(t, `UPDATE billing_period_close_work SET next_attempt_at=now()+interval '10 years' WHERE team_id=$1 AND period_start<$2`, team, start)
				worked, err := newHandler().BillingPeriodCloseTickForTest(t.Context())
				if !worked || err == nil {
					t.Fatalf("later period was not held: %v %v", worked, err)
				}
				var held bool
				if err := testPool.QueryRow(t.Context(), `SELECT p.finalized_at IS NULL AND w.stage='earlier_period' AND w.next_attempt_at>now()
 AND (SELECT sum(remaining_usd) FROM team_credit_grant WHERE team_id=$1)=99
 AND NOT EXISTS(SELECT 1 FROM team_credit_ledger WHERE team_id=$1)
 FROM team_billing_period p JOIN billing_period_close_work w USING(team_id,period_start,period_end)
 WHERE p.team_id=$1 AND p.period_start=$2`, team, start).Scan(&held); err != nil || !held || releases != 0 {
					t.Fatalf("later period progressed past older hold: held=%v releases=%d err=%v", held, releases, err)
				}
				return
			}
			if mode == "pre_enrollment" || mode == "disabled_open" {
				var n int
				err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_period_close_work WHERE team_id=$1`, team).Scan(&n)
				if err != nil || n != 0 {
					t.Fatalf("ineligible history scheduled: %d %v", n, err)
				}
				return
			}
			for i := 0; i < 5; i++ {
				worked, err := newHandler().BillingPeriodCloseTickForTest(t.Context())
				if !worked {
					t.Fatalf("no attempt: %v", err)
				}
				if mode == "anomaly" || mode == "future" || mode == "provider_future" || mode == "unicode_error" {
					if finalizations != 0 || releases != 0 {
						t.Fatal("blocked period billed")
					}
					var next bool
					var stage string
					if e := testPool.QueryRow(t.Context(), `SELECT next_attempt_at>now(),stage FROM billing_period_close_work WHERE team_id=$1`, team).Scan(&next, &stage); e != nil || !next {
						t.Fatalf("retry not paced: %s %v", stage, e)
					}
					if mode == "provider_future" && stage != "waiting_provider" {
						t.Fatalf("wrong provider wait: %s %v", stage, err)
					}
					if mode == "unicode_error" {
						var recorded bool
						if e := testPool.QueryRow(t.Context(), `SELECT lease_token IS NULL AND octet_length(last_error) BETWEEN 2000 AND 2048 FROM billing_period_close_work WHERE team_id=$1`, team).Scan(&recorded); e != nil || !recorded {
							t.Fatalf("long unicode error prevented acknowledgement: %v %v", recorded, e)
						}
						return
					}
					if mode == "future" || mode == "provider_future" {
						return
					}
					correctionExec(t, `UPDATE billing_period_anomaly SET resolved_at=now(),resolved_by=(SELECT user_id FROM team_memberships WHERE team_id=$1 LIMIT 1) WHERE team_id=$1`, team)
					mode = "clean"
				}
				var done bool
				if e := testPool.QueryRow(t.Context(), `SELECT completed_at IS NOT NULL FROM billing_period_close_work WHERE team_id=$1`, team).Scan(&done); e != nil {
					t.Fatal(e)
				}
				if done {
					break
				}
				if i == 4 {
					t.Fatalf("did not finish: %v", err)
				}
				correctionExec(t, `UPDATE billing_period_close_work SET next_attempt_at=now() WHERE team_id=$1`, team)
			}
			var approved, final bool
			if err := testPool.QueryRow(t.Context(), `SELECT (approval_source='system' AND approved_by IS NULL) OR ($2 AND approval_source='human'),finalized_at IS NOT NULL FROM team_billing_period WHERE team_id=$1`, team, disabledFrozen).Scan(&approved, &final); err != nil || !approved || !final {
				t.Fatalf("approval=%v final=%v err=%v", approved, final, err)
			}
			if nonzero && usageEvents != 1 {
				t.Fatalf("usage delivered %d times", usageEvents)
			}
			if finalizations != 1 || releases != 1 {
				t.Fatalf("provider writes finalize=%d release=%d", finalizations, releases)
			}
			if worked, err := newHandler().BillingPeriodCloseTickForTest(t.Context()); worked || err != nil {
				t.Fatalf("completed work retried: %v %v", worked, err)
			}
		})
	}
}

func TestIntegration_BillingCloseClaimCapacityAndRecovery(t *testing.T) {
	correctionExec(t, `UPDATE billing_period_close_work SET completed_at=now(),lease_token=NULL,lease_until=NULL`)
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), &config.Config{})
	h.Pool = testPool
	for i := 0; i < 12; i++ {
		team, _, start, end := seedBillingPeriodForStripe(t, false, true)
		correctionExec(t, `INSERT INTO billing_period_close_work(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, start, end)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := map[uuid.UUID]bool{}
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := h.ClaimBillingPeriodCloseForTest(t.Context())
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if claimed[p.TeamID] {
				t.Error("duplicate claim")
			}
			claimed[p.TeamID] = true
		}()
	}
	wg.Wait()
	// SKIP LOCKED contenders may return immediately; fill remaining free slots.
	for len(claimed) < 4 {
		p, err := h.ClaimBillingPeriodCloseForTest(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		claimed[p.TeamID] = true
	}
	if p, err := h.ClaimBillingPeriodCloseForTest(t.Context()); err == nil {
		t.Fatalf("exceeded fleet cap: %v", p)
	}
	correctionExec(t, `UPDATE billing_period_close_work SET lease_until=now()-interval '1 second' WHERE lease_token IS NOT NULL`)
	correctionExec(t, `UPDATE billing_export_work SET lease_until=now()-interval '1 second' WHERE lease_token IS NOT NULL`)
	if _, err := h.ClaimBillingPeriodCloseForTest(t.Context()); err != nil {
		t.Fatal("expired work stranded", err)
	}
}

func TestIntegration_BillingCloseThousandPeriodQueue(t *testing.T) {
	correctionExec(t, `UPDATE billing_period_close_work SET completed_at=now(),lease_token=NULL,lease_until=NULL`)
	correctionExec(t, `WITH teams AS (INSERT INTO team(name) SELECT 'close-scale-'||n FROM generate_series(1,1000) n RETURNING id),
 periods AS (INSERT INTO team_billing_period(team_id,period_start,period_end) SELECT id,'2026-06-01','2026-07-01' FROM teams RETURNING team_id,period_start,period_end)
 INSERT INTO billing_period_close_work(team_id,period_start,period_end) SELECT team_id,period_start,period_end FROM periods`)
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), &config.Config{})
	h.Pool = testPool
	seen := map[uuid.UUID]bool{}
	began := time.Now()
	for i := 0; i < 1000; i++ {
		p, err := h.ClaimBillingPeriodCloseForTest(t.Context())
		if err != nil {
			t.Fatalf("queue stopped at %d: %v", i, err)
		}
		if seen[p.TeamID] {
			t.Fatal("duplicate period claim")
		}
		seen[p.TeamID] = true
		// Simulate the durable ack only; provider throughput is measured separately.
		correctionExec(t, `UPDATE billing_period_close_work SET completed_at=now(),lease_token=NULL,lease_until=NULL WHERE team_id=$1`, p.TeamID)
		correctionExec(t, `UPDATE billing_export_work SET lease_token=NULL,lease_until=NULL WHERE team_id=$1`, p.TeamID)
	}
	if _, err := h.ClaimBillingPeriodCloseForTest(t.Context()); err == nil {
		t.Fatal("completed queue remained due")
	}
	t.Logf("claimed and acknowledged %d distinct periods in %s", len(seen), time.Since(began))
}

func TestIntegration_BillingCloseSharesExportLease(t *testing.T) {
	correctionExec(t, `UPDATE billing_period_close_work SET completed_at=now(),lease_token=NULL,lease_until=NULL`)
	correctionExec(t, `UPDATE billing_export_work SET next_run_at=now()+interval '10 years',next_reconcile_at=now()+interval '10 years'`)
	team, _, start, end := seedBillingPeriodForStripe(t, false, true)
	correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, team)
	correctionExec(t, `INSERT INTO billing_period_close_work(team_id,period_start,period_end) VALUES($1,$2,$3)`, team, start, end)
	exportToken := uuid.New()
	correctionExec(t, `INSERT INTO billing_export_work(team_id,lease_token,lease_until) VALUES($1,$2,now()+interval '2 minutes')`, team, exportToken)
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), &config.Config{})
	h.Pool = testPool
	if _, err := h.ClaimBillingPeriodCloseForTest(t.Context()); err == nil {
		t.Fatal("close claimed a team owned by the exporter")
	}
	correctionExec(t, `UPDATE billing_export_work SET lease_until=now()-interval '1 second' WHERE team_id=$1`, team)
	if p, err := h.ClaimBillingPeriodCloseForTest(t.Context()); err != nil || p.TeamID != team {
		t.Fatalf("expired exporter lease prevented close: %v %v", p, err)
	}
	if worked, _, err := h.IncrementalBillingTickForTest(t.Context()); worked || err != nil {
		t.Fatalf("exporter claimed a team owned by close: worked=%v err=%v", worked, err)
	}
	// An old exporter acknowledgement must not clear the new close ownership.
	correctionExec(t, `UPDATE billing_export_work SET lease_token=NULL,lease_until=NULL WHERE team_id=$1 AND lease_token=$2`, team, exportToken)
	var shared bool
	if err := testPool.QueryRow(t.Context(), `SELECT e.lease_token=w.lease_token AND e.lease_until>now()
 FROM billing_export_work e JOIN billing_period_close_work w USING(team_id) WHERE team_id=$1`, team).Scan(&shared); err != nil || !shared {
		t.Fatalf("shared ownership lost: %v %v", shared, err)
	}
}

func TestIntegration_BillingCloseManualApprovalWithoutAccount(t *testing.T) {
	team, periodID, start, end := seedBillingPeriodForStripe(t, false, false)
	admin := seedPlatformAdminProfile(t)
	r := newBillingRouter(t, &fakeStripeClient{})
	response := doInternal(r, "POST", "/internal/teams/"+team.String()+"/billing/periods/"+periodID+"/approve", admin.String(), "")
	if response.Code != http.StatusOK {
		t.Fatalf("manual approval without account: %d %s", response.Code, response.Body.String())
	}
	var human bool
	if err := testPool.QueryRow(t.Context(), `SELECT status='approved' AND approval_source='human' AND approved_by=$4
 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, team, start, end, admin).Scan(&human); err != nil || !human {
		t.Fatalf("human provenance missing: %v %v", human, err)
	}
}
