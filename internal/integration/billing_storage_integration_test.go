//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func seedStorageActivation(t *testing.T, team uuid.UUID, at time.Time) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff) VALUES($1,$2,$2) ON CONFLICT DO NOTHING`, team, at); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_BillingProspectiveStorageConsumers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		activated bool
		offset    time.Duration
		want      float64
	}{
		{"missing activation", false, 0, 0}, {"later period", true, -35 * 24 * time.Hour, 5529600},
		{"at start", true, 0, 5529600}, {"partial changing quantities", true, 15 * time.Minute, 4608000},
		{"at quantity change", true, 30 * time.Minute, 3686400}, {"second quantity", true, 45 * time.Minute, 1843200},
		{"at end", true, time.Hour, 0}, {"after end", true, 2 * time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			teamID, viewerKey, _ := seedTeamAndKeyWithRole(t, "viewer")
			team := struct{ ID uuid.UUID }{teamID}
			start := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
			end := start.Add(time.Hour)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := testPool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			sandbox := uuid.New()
			exec(`INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,created_at) VALUES($1,$2,'example-paused','paused',1,1024,'default',$3)`, sandbox, team.ID, start)
			exec(`INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason) VALUES($1,$2,1024,$3,$4,'deleted'),($1,$2,2048,$4,$5,'deleted')`, sandbox, team.ID, start, start.Add(30*time.Minute), end)
			exec(`INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason) VALUES($1,$2,1,1024,$3,$4,'paused')`, sandbox, team.ID, start, end)
			exec(`INSERT INTO team_billing_account(team_id) VALUES($1)`, team.ID)
			plan := "example-storage-" + uuid.NewString()
			exec(`INSERT INTO pricing_plan(key,name,currency,active) VALUES($1,'Example storage','USD',true)`, plan)
			exec(`INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0,$2),($1,'memory_gib','second',0,$2),($1,'storage_gib','second',1,$2)`, plan, start.Add(-time.Hour))
			exec(`INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team.ID, plan, start.Add(-time.Hour))
			exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at) VALUES($1,10000,10000,'signup trial credit',$2)`, team.ID, start)
			// A flag alone never imports tracked history into payable usage.
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_storage_billing_enabled',true)`, team.ID)
			if tc.activated {
				seedStorageActivation(t, team.ID, start.Add(tc.offset))
			}
			exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team.ID, start, end)
			router := newBillingRouter(t, &fakeStripeClient{})
			admin := seedPlatformAdminProfile(t)
			check := func() {
				t.Helper()
				usage, err := testQueries.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{TeamID: team.ID, PeriodStart: start, PeriodEnd: end})
				if err != nil {
					t.Fatal(err)
				}
				if numericFloat64(t, usage.StorageGibSeconds) != 5400 || numericFloat64(t, usage.BillableStorageGibSeconds) != tc.want/1024 || numericFloat64(t, usage.VcpuSeconds) != 3600 || numericFloat64(t, usage.MemoryGibSeconds) != 3600 {
					t.Fatalf("tracked/payable/compute mismatch: %+v", usage)
				}
				var cpu, mem, storage pgtype.Numeric
				if err = testPool.QueryRow(ctx, billing.ExportRemeasurementSQL, team.ID, start, end).Scan(&cpu, &mem, &storage); err != nil {
					t.Fatal(err)
				}
				if numericFloat64(t, storage) != tc.want || numericFloat64(t, cpu) != 3600 || numericFloat64(t, mem) != 3686400 {
					t.Fatal("export remeasurement differs")
				}
				if tc.want == 3686400 {
					quantity, err := billing.MeterUsageQuantity(storage, "storage_gib")
					if err != nil || quantity != "1.000000000000" {
						t.Fatalf("GiB-hour conversion: %s %v", quantity, err)
					}
				}

				rollup, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{TeamID: team.ID, PeriodStart: pgtype.Timestamptz{Time: start, Valid: true}, PeriodEnd: pgtype.Timestamptz{Time: end, Valid: true}})
				if err != nil {
					t.Fatal(err)
				}
				if numericFloat64(t, rollup.StorageMibSeconds) != tc.want {
					t.Fatal("payable period rollup differs")
				}
				series, err := testQueries.GetTeamBillingUsageSeries(ctx, db.GetTeamBillingUsageSeriesParams{TeamID: team.ID, PeriodStarts: []time.Time{start, start.Add(30 * time.Minute)}, PeriodEnds: []time.Time{start.Add(30 * time.Minute), end}})
				if err != nil {
					t.Fatal(err)
				}
				if len(series) != 2 || numericFloat64(t, series[0].BillableStorageGibSeconds)+numericFloat64(t, series[1].BillableStorageGibSeconds) != tc.want/1024 {
					t.Fatal("usage series differs")
				}
				trial, err := testQueries.GetTeamTrialBalance(ctx, team.ID)
				if err != nil {
					t.Fatal(err)
				}
				if numericFloat64(t, trial.ConsumedUsd) != tc.want/1024 || numericFloat64(t, trial.RemainingUsd) != 10000-tc.want/1024 {
					t.Fatalf("trial differs: %+v", trial)
				}
				assertStorageHTTPConsumers(t, router, team.ID, viewerKey, admin, start, end, tc.want/1024, 5400)
				var balance float64
				if err = testPool.QueryRow(ctx, `SELECT remaining_usd FROM team_credit_grant WHERE team_id=$1`, team.ID).Scan(&balance); err != nil || balance != 10000 {
					t.Fatalf("read double-deducted grant: %v %v", balance, err)
				}
			}
			check()
			exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID)
			check()
			if tc.name == "partial changing quantities" {
				exec(`UPDATE team_credit_grant SET amount_usd=4500,remaining_usd=4500 WHERE team_id=$1`, team.ID)
				for _, amount := range []float64{4500, 5000} {
					if amount == 5000 {
						// A new grant makes an exhausted trial eligible for refresh.
						exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,500,500,'signup trial credit')`, team.ID)
					}
					balance, err := testQueries.GetTeamTrialBalance(ctx, team.ID)
					if err != nil || numericFloat64(t, balance.ConsumedUsd) != 4500 || numericFloat64(t, balance.RemainingUsd) != amount-4500 {
						t.Fatalf("trial exhaustion balance: %+v %v", balance, err)
					}
					// Paused storage must be discovered by the same background sweep
					// that publishes eligibility for create/resume cache misses.
					h := &api.Handlers{DB: db.New(warningDispatchScope{Pool: testPool, team: team.ID})}
					api.RefreshActiveTrialEligibilityForTest(h, ctx)
					h.WaitAsyncBookkeeping()
					eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, team.ID)
					if err != nil || eligible != (amount > 4500) {
						t.Fatalf("trial exhaustion eligibility: %v %v", eligible, err)
					}
				}
				exec(`UPDATE team_credit_grant SET expires_at=$2 WHERE team_id=$1`, team.ID, end)
				eligible, err := testQueries.IsTeamSandboxBillingEligible(ctx, team.ID)
				if err != nil || eligible {
					t.Fatalf("expired trial remains eligible: %v %v", eligible, err)
				}
			}

			if tc.activated {
				if _, err := testPool.Exec(ctx, `UPDATE team_storage_billing_activation SET effective_at=effective_at+interval '1 hour' WHERE team_id=$1`, team.ID); err == nil {
					t.Fatal("activation changed")
				}
				if _, err := testPool.Exec(ctx, `DELETE FROM team_storage_billing_activation WHERE team_id=$1`, team.ID); err == nil {
					t.Fatal("activation deleted")
				}
			}
		})
	}
}

type storageReadyStripe struct {
	*fakeStripeClient
	mu             sync.Mutex
	ready          map[string]bool
	creates        int
	inspected      []string
	expectedAmount string
	providerAmount string
}

func (s *storageReadyStripe) EnsureStorageSubscription(_ context.Context, p api.StripeStorageSubscriptionParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspected = append(s.inspected, p.SubscriptionID)
	if s.expectedAmount != "" && p.UnitAmountDecimal != s.expectedAmount {
		return fmt.Errorf("canonical conversion: got %s want %s", p.UnitAmountDecimal, s.expectedAmount)
	}
	if s.providerAmount != "" && p.UnitAmountDecimal != s.providerAmount {
		return fmt.Errorf("storage price does not match canonical rate")
	}
	if p.SubscriptionID == "" {
		return nil
	}
	if !s.ready[p.SubscriptionID] && p.Reconcile {
		s.ready[p.SubscriptionID] = true
		s.creates++
	}
	if !s.ready[p.SubscriptionID] {
		return fmt.Errorf("current subscription is missing storage item")
	}
	return nil
}

func TestIntegration_BillingStorageActivationReadinessAndConcurrency(t *testing.T) {
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	team, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	admin := seedPlatformAdminProfile(t)
	stripe := &storageReadyStripe{fakeStripeClient: &fakeStripeClient{}, ready: map[string]bool{}}
	r := newBillingRouter(t, stripe)
	path := "/internal/teams/" + team.String() + "/billing/storage"
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_storage_billing_enabled',true)`, team); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(-time.Minute)
	body := fmt.Sprintf(`{"mode":"activate","approved_cutoff":%q}`, cutoff.Format(time.RFC3339Nano))
	if w := doBillingOperator(r, path, operatorRBACToken, admin.String(), body); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "missing storage") {
		t.Fatalf("activation bypassed readiness: %d %s", w.Code, w.Body.String())
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doBillingOperator(r, path, operatorRBACToken, admin.String(), `{"mode":"reconcile"}`)
			if w.Code != 200 {
				t.Errorf("reconcile: %d %s", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	if stripe.creates != 1 {
		t.Fatalf("created %d items", stripe.creates)
	}
	// Activation uses the database clock, which may differ from the test host.
	var before time.Time
	if err := testPool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doBillingOperator(r, path, operatorRBACToken, admin.String(), body)
			if w.Code != 200 {
				t.Errorf("activate: %d %s", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	var first time.Time
	if err := testPool.QueryRow(t.Context(), `SELECT effective_at FROM team_storage_billing_activation WHERE team_id=$1`, team).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first.Before(before) || first.Before(cutoff) {
		t.Fatalf("activation backdated: effective_at=%s before=%s cutoff=%s", first, before, cutoff)
	}
	// A replacement (including an old Checkout completing late) must be checked
	// against the current association, while the original cutoff remains fixed.
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id='sub_replacement' WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if w := doBillingOperator(r, path, operatorRBACToken, admin.String(), body); w.Code != 409 {
		t.Fatalf("replacement bypassed readiness: %d", w.Code)
	}
	if w := doBillingOperator(r, path, operatorRBACToken, admin.String(), `{"mode":"reconcile"}`); w.Code != 200 {
		t.Fatalf("replacement reconcile: %s", w.Body.String())
	}
	w := doBillingOperator(r, path, operatorRBACToken, admin.String(), body)
	var response struct {
		EffectiveAt time.Time `json:"effective_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || !response.EffectiveAt.Equal(first) {
		t.Fatalf("activation changed: %s", w.Body.String())
	}
}

func TestIntegration_BillingStorageTrialActivationDoesNotCreateSubscription(t *testing.T) {
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	team, err := testQueries.CreateTeam(t.Context(), "example-trial-storage-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	admin := seedPlatformAdminProfile(t)
	stripe := &storageReadyStripe{fakeStripeClient: &fakeStripeClient{}, ready: map[string]bool{}}
	router := newBillingRouter(t, stripe)
	if _, err = testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_storage_billing_enabled',true)`, team.ID); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	body := fmt.Sprintf(`{"mode":"activate","approved_cutoff":%q}`, cutoff.Format(time.RFC3339Nano))
	path := "/internal/teams/" + team.ID.String() + "/billing/storage"
	storageExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,5,'signup trial credit')`, team.ID)
	for i := 0; i < 2; i++ {
		storageExec(t, `INSERT INTO team_trial_eligibility_cache(team_id,eligible) VALUES($1,false) ON CONFLICT(team_id) DO UPDATE SET eligible=false`, team.ID)
		w := doBillingOperator(router, path, operatorRBACToken, admin.String(), body)
		var response struct {
			EffectiveAt time.Time `json:"effective_at"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || !response.EffectiveAt.Equal(cutoff) {
			t.Fatalf("trial activation: %d %s", w.Code, w.Body.String())
		}
		var eligible bool
		if err := testPool.QueryRow(t.Context(), `SELECT eligible FROM team_trial_eligibility_cache WHERE team_id=$1`, team.ID).Scan(&eligible); err != nil || !eligible {
			t.Fatalf("activation did not refresh trial eligibility: %v %v", eligible, err)
		}
	}
	storageExec(t, `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID)
	if active, err := testQueries.IsStorageBillingActivated(t.Context(), team.ID); err != nil || active {
		t.Fatalf("future cutoff is active now: %v %v", active, err)
	}
	for _, tc := range []struct {
		name   string
		end    time.Time
		active bool
	}{
		{"before cutoff", cutoff.Add(-time.Microsecond), false},
		{"at cutoff", cutoff, false},
		{"after cutoff", cutoff.Add(time.Microsecond), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active, err := testQueries.IsStorageBillingActivatedForWindow(t.Context(), db.IsStorageBillingActivatedForWindowParams{TeamID: team.ID, PeriodEnd: tc.end})
			if err != nil || active != tc.active {
				t.Fatalf("explicit window activation: got %v want %v: %v", active, tc.active, err)
			}
		})
	}
	var untouched bool
	if err := testPool.QueryRow(t.Context(), `SELECT stripe_customer_id IS NULL AND stripe_subscription_id IS NULL AND trial_ended_at IS NULL FROM team_billing_account WHERE team_id=$1`, team.ID).Scan(&untouched); err != nil || !untouched || stripe.creates != 0 || len(stripe.customerCalls) != 0 || len(stripe.checkoutCalls) != 0 {
		t.Fatalf("trial subscription mutated: %v %v", untouched, err)
	}
}

func TestIntegration_BillingStorageDoesNotCorrectPreActivationFrozenUsage(t *testing.T) {
	for _, status := range []string{"exported", "finalized"} {
		t.Run(status, func(t *testing.T) {
			store, period := seedIncrementalPeriod(t)
			storageExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, period.TeamID, period.Start)
			storageExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end) VALUES($1,$2,$3,'cpu',0,0,0,0,$2,$3)`, period.TeamID, period.Start, period.End)
			storageExec(t, `UPDATE team_billing_usage SET exported_at=now(),finalized_at=CASE WHEN $2='finalized' THEN now() ELSE NULL END WHERE team_id=$1`, period.TeamID, status)
			storageExec(t, `UPDATE team_billing_period SET status=$2,exported_at=now(),finalized_at=CASE WHEN $2='finalized' THEN now() ELSE NULL END,gross_charges_usd=CASE WHEN $2='finalized' THEN 7 ELSE NULL END,credits_applied_usd=CASE WHEN $2='finalized' THEN 2 ELSE NULL END,net_invoice_amount_usd=CASE WHEN $2='finalized' THEN 5 ELSE NULL END WHERE team_id=$1`, period.TeamID, status)
			snapshot := func() string {
				t.Helper()
				var result string
				if err := testPool.QueryRow(t.Context(), `SELECT jsonb_build_object('period',to_jsonb(p),'usage',to_jsonb(u))::text FROM team_billing_period p JOIN team_billing_usage u USING(team_id,period_start,period_end) WHERE p.team_id=$1`, period.TeamID).Scan(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := snapshot()
			var quantity float64
			if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds FROM team_billing_usage WHERE team_id=$1`, period.TeamID).Scan(&quantity); err != nil || quantity != 3686400 {
				t.Fatalf("nonzero settled fixture: %v %v", quantity, err)
			}
			seedStorageActivation(t, period.TeamID, time.Now().UTC())
			correction, err := store.MeasureCorrection(t.Context(), period, "storage")
			if err != nil {
				t.Fatal(err)
			}
			if correction.Measured != "0.000000000000" || correction.Baseline != "0.000000000000" || correction.Target != "0.000000000000" {
				t.Fatalf("historical storage became payable: %+v", correction)
			}
			observations := 0
			stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}, countedUsage: func(string, string, time.Time, time.Time) (string, error) { observations++; return "0", nil }}
			router := newBillingRouter(t, stripe)
			admin := seedPlatformAdminProfile(t)
			path := "/internal/teams/" + period.TeamID.String() + "/billing/periods/" + apiPeriodID(period.Start, period.End) + "/export"
			// Other historical resources can require reconciliation; neither an
			// attempted re-export nor a correction may rewrite settled storage.
			for i := 0; i < 2; i++ {
				w := doInternal(router, "POST", path, admin.String(), "")
				if w.Code != 200 && w.Code != 409 {
					t.Fatalf("historical re-export: %d %s", w.Code, w.Body.String())
				}
			}
			if observations == 0 {
				t.Fatal("historical re-export did not reach reconciliation")
			}
			if after := snapshot(); after != before {
				t.Fatalf("settled snapshot changed: before=%s after=%s", before, after)
			}
			var count int
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_export_allocation WHERE team_id=$1 AND resource_type='storage'`, period.TeamID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("historical storage re-exported: %d %v", count, err)
			}
			for _, call := range stripe.reportCalls {
				if call.EventName == "storage_gib_hours" {
					t.Fatalf("historical storage submitted: %+v", call)
				}
			}
		})
	}
}

func storageExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func assertStorageHTTPConsumers(t *testing.T, router *gin.Engine, team uuid.UUID, key string, admin uuid.UUID, start, end time.Time, cost, raw float64) {
	t.Helper()
	decode := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var body map[string]any
		if w.Code != 200 {
			t.Fatalf("billing HTTP: %d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	body := decode(do(router, "GET", "/billing/summary", key, ""))
	if body["current_charges_usd"] != cost || body["cost_breakdown_usd"].(map[string]any)["storage"] != cost {
		t.Fatalf("summary cost: %v, want %v", body, cost)
	}
	resource := body["resources_by_key"].(map[string]any)["storage_gib"].(map[string]any)
	if resource["usage"] != raw || resource["tracked"] != true {
		t.Fatalf("summary raw tracking: %v", resource)
	}
	body = decode(do(router, "GET", "/billing/usage-series?start="+start.Format(time.RFC3339)+"&end="+end.Format(time.RFC3339)+"&granularity=hour&timezone=UTC", key, ""))
	var gotCost, gotRaw float64
	for _, b := range body["buckets"].([]any) {
		bucket := b.(map[string]any)
		storage := bucket["storage"].(map[string]any)
		gotCost += storage["cost_usd"].(float64)
		gotRaw += storage["usage"].(float64)
	}
	if gotCost != cost || gotRaw != raw {
		t.Fatalf("series cost/raw: %v/%v want %v/%v", gotCost, gotRaw, cost, raw)
	}
	for _, sort := range []string{"team_name", "current_charges_usd"} {
		body = decode(doInternal(router, "GET", "/internal/billing?search="+team.String()+"&sort="+sort, admin.String(), ""))
		totals := body["totals"].(map[string]any)
		if totals["teams"] != float64(1) || totals["current_charges_usd"] != cost {
			t.Fatalf("platform totals: %v want %v", totals, cost)
		}
	}
}

func TestIntegration_BillingStorageCanonicalPriceEndpoints(t *testing.T) {
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	team, _, start, _ := seedBillingPeriodForStripe(t, true, true)
	plan := "example-rate-" + team.String()
	insertPricingPlanForTest(t, t.Context(), plan, true)
	storageExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'storage_gib','second',0.000000037123,$2)`, plan, start)
	storageExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, plan, start)
	storageExec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_storage_billing_enabled',true)`, team)
	// USD/GiB-second * 3600 seconds/hour * 100 cents/USD, exactly.
	stripe := &storageReadyStripe{fakeStripeClient: &fakeStripeClient{}, ready: map[string]bool{"sub_" + team.String(): true}, expectedAmount: "0.013364280000", providerAmount: "0.013364280001"}
	router := newBillingRouter(t, stripe)
	admin := seedPlatformAdminProfile(t)
	path := "/internal/teams/" + team.String() + "/billing/storage"
	activate := fmt.Sprintf(`{"mode":"activate","approved_cutoff":%q}`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	for _, body := range []string{`{"mode":"reconcile"}`, activate} {
		w := doBillingOperator(router, path, operatorRBACToken, admin.String(), body)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "canonical rate") {
			t.Fatalf("wrong price accepted: %d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_storage_billing_activation WHERE team_id=$1`, team).Scan(&count); err != nil || count != 0 {
		t.Fatalf("activated wrong price: %d %v", count, err)
	}
	stripe.providerAmount = stripe.expectedAmount
	for _, body := range []string{`{"mode":"reconcile"}`, activate} {
		w := doBillingOperator(router, path, operatorRBACToken, admin.String(), body)
		if w.Code != 200 {
			t.Fatalf("canonical price rejected: %d %s", w.Code, w.Body.String())
		}
	}
}

func reserveStorage(t *testing.T, store billing.ExportStore, p billing.ExportPeriod, total string) *billing.ExportEvent {
	t.Helper()
	event, err := store.Reserve(t.Context(), p, "storage", total, p.End, billing.ExportPayload{EventName: "storage_gib_hours", CustomerID: "cus_" + p.TeamID.String(), Timestamp: p.End.Truncate(time.Minute).Add(-time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestIntegration_BillingStorageReadinessPreservesSubmissionHistory(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous-send-%v", sent), func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			seedStorageActivation(t, p.TeamID, p.Start)
			original := &billing.ExportEvent{ID: uuid.New(), AllocationID: uuid.New(), ExportPayload: billing.ExportPayload{EventName: "storage_gib_hours", CustomerID: "cus_" + p.TeamID.String(), Quantity: "1.000000000000", Timestamp: p.End.Add(-time.Second).Unix()}}
			original.Identifier = "usage-" + original.ID.String()
			original.IdempotencyKey = original.Identifier
			storageExec(t, `INSERT INTO billing_export_allocation(id,team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through) VALUES($1,$2,$3,$4,'storage',0,1,$4)`, original.AllocationID, p.TeamID, p.Start, p.End)
			storageExec(t, `INSERT INTO billing_export_event(id,allocation_id,identifier,idempotency_key,event_name,customer_id,quantity,quantity_payload,event_timestamp,source,status,created_at) VALUES($1,$2,$3,$3,$4,$5,1.000000000000,$6,$7,'export','pending',now()-interval '25 hours')`, original.ID, original.AllocationID, original.Identifier, original.EventName, original.CustomerID, original.Quantity, original.Timestamp)
			claim := func() *billing.ExportEvent {
				t.Helper()
				e, err := store.Claim(t.Context(), p)
				if err != nil || e == nil || e.ID != original.ID || e.AllocationID != original.AllocationID || e.ExportPayload != original.ExportPayload {
					t.Fatalf("claim changed reservation: %+v %v", e, err)
				}
				return e
			}
			if sent {
				e := claim()
				// The provider accepted the event but its response was lost.
				if err := store.Acknowledge(t.Context(), *e, errors.New("provider response lost")); err != nil {
					t.Fatal(err)
				}
				storageExec(t, `UPDATE billing_export_event SET first_attempt_at=now()-interval '22 hours',next_attempt_at=now() WHERE id=$1`, original.ID)
			}
			var before pgtype.Timestamptz
			if err := testPool.QueryRow(t.Context(), `SELECT first_attempt_at FROM billing_export_event WHERE id=$1`, original.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				e := claim()
				if err := store.Defer(t.Context(), *e, errors.New("replacement subscription missing storage item")); err != nil {
					t.Fatal(err)
				}
				var after pgtype.Timestamptz
				var status string
				var attempts int
				if err := testPool.QueryRow(t.Context(), `SELECT first_attempt_at,status,attempt_count FROM billing_export_event WHERE id=$1`, original.ID).Scan(&after, &status, &attempts); err != nil {
					t.Fatal(err)
				}
				if sent {
					if status != "uncertain" || attempts != 1 || !after.Valid || !after.Time.Equal(before.Time) {
						t.Fatalf("lost uncertainty: %s %d %v -> %v", status, attempts, before, after)
					}
				} else if status != "pending" || attempts != 0 || after.Valid {
					t.Fatalf("preflight started retry window: %s %d %v", status, attempts, after)
				}
				storageExec(t, `UPDATE billing_export_event SET next_attempt_at=now() WHERE id=$1`, original.ID)
			}
			if sent {
				storageExec(t, `UPDATE billing_export_event SET first_attempt_at=now()-interval '24 hours' WHERE id=$1`, original.ID)
				if e, err := store.Claim(t.Context(), p); err != nil || e != nil {
					t.Fatalf("expired uncertain event retried: %+v %v", e, err)
				}
				var status string
				if err := testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, original.ID).Scan(&status); err != nil || status != "recovery_required" {
					t.Fatalf("expiry: %s %v", status, err)
				}
			} else {
				// A queued hold older than provider retention still has no send deadline.
				e := claim()
				if err := store.Acknowledge(t.Context(), *e, nil); err != nil {
					t.Fatal(err)
				}
				delta := reserveStorage(t, store, p, "3")
				if delta == nil || delta.Quantity != "2.000000000000" || delta.Identifier == original.Identifier {
					t.Fatalf("catchup replayed reserved usage: %+v", delta)
				}
			}
			totals, err := store.Totals(t.Context(), p, "storage")
			want := "1.000000000000"
			if !sent {
				want = "3.000000000000"
			}
			if err != nil || totals.Reserved != want {
				t.Fatalf("reservation changed: %+v %v", totals, err)
			}
		})
	}
}

func TestIntegration_BillingStorageQueuedPreactivationReplacement(t *testing.T) {
	store, p := seedIncrementalPeriod(t)
	cutoff := p.Start.Add(30 * time.Minute)
	allocation, event := uuid.New(), uuid.New()
	// Seed a legacy allocation whose measurement predates activation, while its
	// provider attribution lies later. Replacement creation cannot change that provenance.
	storageExec(t, `INSERT INTO billing_export_allocation(id,team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through,created_at)
	VALUES($1,$2,$3,$4,'storage',0,1,$4,$5)`, allocation, p.TeamID, p.Start, p.End, cutoff.Add(-time.Minute))
	storageExec(t, `INSERT INTO billing_export_event(id,allocation_id,identifier,idempotency_key,event_name,customer_id,quantity,quantity_payload,event_timestamp,source,status)
	VALUES($1,$2,$3,$3,'storage_gib_hours',$4,1.000000000000,'1.000000000000',$5,'export','pending')`, event, allocation, "example-"+event.String(), "cus_"+p.TeamID.String(), p.End.Add(-time.Second).Unix())
	seedStorageActivation(t, p.TeamID, cutoff)
	for _, replacement := range []bool{false, true} {
		if replacement {
			if ok, err := store.Reject(t.Context(), "example-"+event.String(), "", "", "", "definitive provider rejection"); err != nil || !ok {
				t.Fatalf("reject: %v %v", ok, err)
			}
			if err := store.RecoverRejected(t.Context(), event, "reviewed provider rejection"); err != nil {
				t.Fatal(err)
			}
		}
		if e, err := store.Claim(t.Context(), p); err != nil || e != nil {
			t.Fatalf("preactivation replayed: %+v %v", e, err)
		}
		totals, err := store.Totals(t.Context(), p, "storage")
		if err != nil || totals.Reserved != "1.000000000000" {
			t.Fatalf("lost legacy reservation: %+v %v", totals, err)
		}
	}
	reserveIncrement(t, store, p, "2")
	e, err := store.Claim(t.Context(), p)
	if err != nil || e == nil || e.ResourceType != "cpu" {
		t.Fatalf("storage hold blocked compute: %+v %v", e, err)
	}
	if err := store.Acknowledge(t.Context(), *e, nil); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_BillingStoragePartialMinuteExport(t *testing.T) {
	team, _, _, end := seedBillingPeriodForStripe(t, true, true)
	p := billing.ExportPeriod{TeamID: team, Start: end.Add(30*time.Minute + 45*time.Second)}
	p.End = p.Start.AddDate(0, 1, 0)
	storageExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, team, p.Start)
	storageExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, team, p.Start, p.End)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
	SELECT id,$1,1024,$2,$3,'deleted' FROM sandbox WHERE team_id=$1 LIMIT 1`, team, p.End.Add(-45*time.Second), p.End)
	seedStorageActivation(t, team, p.End.Add(-35*time.Second))
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(event, customer string, from, to time.Time) (string, error) {
		var total float64
		for _, call := range stripe.reportCalls {
			if call.EventName == event {
				var n float64
				if _, err := fmt.Sscan(call.Value, &n); err != nil {
					t.Fatal(err)
				}
				total += n
			}
		}
		return fmt.Sprintf("%.12f", total), nil
	}
	router := newBillingRouter(t, stripe)
	admin := seedPlatformAdminProfile(t)
	path := "/internal/teams/" + team.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	w := doInternal(router, "POST", path, admin.String(), "")
	if w.Code != 200 {
		t.Fatalf("partial minute export: %d %s", w.Code, w.Body.String())
	}
	if len(stripe.reportCalls) == 0 {
		t.Fatal("eligible partial-minute storage never reached provider")
	}
	var total float64
	for _, call := range stripe.reportCalls {
		if call.EventName != "storage_gib_hours" {
			t.Fatalf("unexpected event: %+v", call)
		}
		if call.Timestamp != p.End.Truncate(time.Minute).Add(-time.Second).Unix() {
			t.Fatalf("attribution changed: %+v", call)
		}
		var n float64
		if _, err := fmt.Sscan(call.Value, &n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	assertFloatNear(t, total, 0.009722222222)
}

func TestIntegration_BillingStorageCacheCoverage(t *testing.T) {
	for _, cutoff := range []time.Duration{15 * time.Minute, 75 * time.Minute} {
		t.Run(cutoff.String(), func(t *testing.T) { testStorageCacheCoverage(t, cutoff) })
	}
}

func testStorageCacheCoverage(t *testing.T, cutoff time.Duration) {
	team, _, _, _ := seedBillingPeriodForStripe(t, true, true)
	hour := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
	start, end := hour.Add(30*time.Minute), hour.Add(24*time.Hour)
	storageExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, start, end)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason) SELECT id,$1,1024,$2,$3,'deleted' FROM sandbox WHERE team_id=$1 LIMIT 1`, team, hour, hour.Add(3*time.Hour))
	seedStorageActivation(t, team, hour.Add(cutoff))
	// Match the worker's single-statement contribution + accumulator upsert,
	// including the INSERT and UPDATE triggers exercised by ON CONFLICT.
	consume := func(at time.Time) {
		storageExec(t, `WITH old AS MATERIALIZED (
		 SELECT storage_mib_seconds FROM billing_export_measurement WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND hour_start=$4
		), contribution AS (
		 INSERT INTO billing_export_measurement(team_id,period_start,period_end,hour_start,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
		 VALUES($1,$2,$3,$4,1800,1843200,3686400) ON CONFLICT(team_id,period_start,period_end,hour_start) DO UPDATE SET storage_mib_seconds=EXCLUDED.storage_mib_seconds RETURNING *
		) INSERT INTO billing_export_usage(team_id,period_start,period_end,storage_mib_seconds)
		 SELECT $1,$2,$3,c.storage_mib_seconds-COALESCE(o.storage_mib_seconds,0) FROM contribution c LEFT JOIN old o ON true
		 ON CONFLICT(team_id,period_start,period_end) DO UPDATE SET storage_mib_seconds=billing_export_usage.storage_mib_seconds+EXCLUDED.storage_mib_seconds`, team, start, end, at)
	}
	check := func(want float64) {
		t.Helper()
		var got float64
		if err := testPool.QueryRow(t.Context(), `SELECT storage_mib_seconds FROM billing_export_usage WHERE team_id=$1 AND period_start=$2`, team, start).Scan(&got); err != nil || got != want {
			t.Fatalf("coverage=%v want %v: %v", got, want, err)
		}
	}
	first := float64(1843200)
	second := float64(5529600)
	if cutoff == 75*time.Minute {
		first = 0
		second = 2764800
	}
	consume(hour)
	check(first)
	consume(hour)
	check(first)
	storageExec(t, `UPDATE billing_export_usage SET storage_mib_seconds=999999999 WHERE team_id=$1 AND period_start=$2`, team, start)
	check(first)
	if first == 0 {
		store := billing.ExportStore{Pool: testPool}
		p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
		if err := store.Enroll(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		through := hour.Add(time.Hour)
		payload := billing.ExportPayload{EventName: "storage_gib_hours", CustomerID: "cus_" + team.String(), Timestamp: through.Add(-time.Second).Unix()}
		if event, err := store.Reserve(t.Context(), p, "storage", "0", through, payload); err != nil || event != nil {
			t.Fatalf("zero pre-cutoff reservation: %+v %v", event, err)
		}
		payload.EventName = "cpu_vcpu_hours"
		if _, err := store.Reserve(t.Context(), p, "cpu", "0.5", through, payload); err != nil {
			t.Fatal(err)
		}
		event, err := store.Claim(t.Context(), p)
		if err != nil || event == nil || event.ResourceType != "cpu" {
			t.Fatalf("pre-cutoff storage blocked compute: %+v %v", event, err)
		}
		if err := store.Acknowledge(t.Context(), *event, nil); err != nil {
			t.Fatal(err)
		}
	}
	consume(hour.Add(time.Hour))
	check(second)
	// The following unconsumed hour is deliberately absent from the accumulator.
}

func TestIntegration_BillingStorageFractionalArtifactSettlement(t *testing.T) {
	for _, offset := range []time.Duration{0, 15 * time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			ctx := t.Context()
			cutoff := p.Start.Add(offset)
			retentionEnd := cutoff.Add(time.Hour)
			seedStorageActivation(t, p.TeamID, cutoff)
			storageExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start)
			storageExec(t, `INSERT INTO template(team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path)
                VALUES($1,'example-fractional','ready','{}',1,1024,1024,'/templates/'||$1::uuid::text||'/base.ext4')`, p.TeamID)
			storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
                SELECT id,'base.ext4',rootfs_path,1073745920,1073745920,repeat('0',64) FROM template WHERE team_id=$1`, p.TeamID)
			storageExec(t, `UPDATE sandbox SET template_id=(SELECT id FROM template WHERE team_id=$1),created_at=$2,destroyed_at=NULL WHERE team_id=$1`, p.TeamID, p.Start)
			storageExec(t, `UPDATE sandbox_storage_interval SET ended_at=NULL,end_reason=NULL WHERE team_id=$1`, p.TeamID)
			payload := billing.ExportPayload{EventName: "storage_gib_hours", CustomerID: "cus_" + p.TeamID.String()}
			accepted := new(big.Rat)
			wantQuantity := "2.000003814697"
			const wantMiBSeconds = 7372814.0625 // One GiB overlay plus one GiB + 4096-byte artifact, for one hour.
			consume := func(hour time.Time) {
				t.Helper()
				storageExec(t, `INSERT INTO billing_export_measurement(team_id,period_start,period_end,hour_start,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
                    VALUES($1,$2,$3,$4,0,0,0)`, p.TeamID, p.Start, p.End, hour)
				storageExec(t, `INSERT INTO billing_export_usage(team_id,period_start,period_end,storage_mib_seconds)
                    VALUES($1,$2,$3,0) ON CONFLICT(team_id,period_start,period_end) DO UPDATE SET storage_mib_seconds=0`, p.TeamID, p.Start, p.End)
				var measured pgtype.Numeric
				if err := testPool.QueryRow(ctx, `SELECT storage_mib_seconds FROM billing_export_usage WHERE team_id=$1 AND period_start=$2`, p.TeamID, p.Start).Scan(&measured); err != nil {
					t.Fatal(err)
				}
				quantity, err := billing.MeterUsageQuantity(measured, "storage_gib")
				if err != nil {
					t.Fatal(err)
				}
				through := hour.Add(time.Hour)
				payload.Timestamp = through.Add(-time.Second).Unix()
				event, err := store.Reserve(ctx, p, "storage", quantity, through, payload)
				if err != nil || event == nil {
					t.Fatalf("incremental reservation: %+v %v", event, err)
				}
				event = acceptIncrement(t, store, p)
				value, ok := new(big.Rat).SetString(event.Quantity)
				if !ok {
					t.Fatal(event.Quantity)
				}
				accepted.Add(accepted, value)
			}
			consume(p.Start)
			// Retention ends after the first increment was accepted, well before close.
			storageExec(t, `UPDATE sandbox SET destroyed_at=$2 WHERE team_id=$1`, p.TeamID, retentionEnd)
			storageExec(t, `UPDATE sandbox_storage_interval SET ended_at=$2,end_reason='deleted' WHERE team_id=$1`, p.TeamID, retentionEnd)
			if offset != 0 {
				consume(p.Start.Add(time.Hour))
			}
			if accepted.FloatString(12) != wantQuantity {
				t.Fatalf("incremental cumulative quantity=%s want %s", accepted.FloatString(12), wantQuantity)
			}
			usage, err := testQueries.UpsertTeamBillingUsage(ctx, db.UpsertTeamBillingUsageParams{TeamID: p.TeamID, PeriodStart: pgtype.Timestamptz{Time: p.Start, Valid: true}, PeriodEnd: pgtype.Timestamptz{Time: p.End, Valid: true}})
			if err != nil || numericFloat64(t, usage.StorageMibSeconds) != wantMiBSeconds {
				t.Fatalf("closing snapshot lost fractional usage: %+v %v", usage, err)
			}
			var cpu, memory, storage pgtype.Numeric
			if err := testPool.QueryRow(ctx, billing.ExportRemeasurementSQL, p.TeamID, p.Start, p.End).Scan(&cpu, &memory, &storage); err != nil || numericFloat64(t, storage) != wantMiBSeconds {
				t.Fatalf("correction remeasurement lost fractional usage: %+v %v", storage, err)
			}
			series, err := testQueries.GetTeamBillingUsageSeries(ctx, db.GetTeamBillingUsageSeriesParams{TeamID: p.TeamID, PeriodStarts: []time.Time{p.Start, p.Start.Add(time.Hour)}, PeriodEnds: []time.Time{p.Start.Add(time.Hour), p.End}})
			if err != nil || len(series) != 2 {
				t.Fatalf("usage series: %+v %v", series, err)
			}
			if got := numericFloat64(t, series[0].BillableStorageGibSeconds) + numericFloat64(t, series[1].BillableStorageGibSeconds); got != wantMiBSeconds/1024 {
				t.Fatalf("partitioned usage=%v want %v", got, wantMiBSeconds/1024)
			}
			stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
			stripe.countedUsage = func(event, customer string, start, end time.Time) (string, error) {
				total := new(big.Rat)
				if event == payload.EventName {
					total.Set(accepted)
				}
				for _, call := range stripe.reportCalls {
					if call.EventName == event {
						value, ok := new(big.Rat).SetString(call.Value)
						if !ok {
							t.Fatal(call.Value)
						}
						total.Add(total, value)
					}
				}
				return total.FloatString(12), nil
			}
			admin := seedPlatformAdminProfile(t)
			router := newBillingRouter(t, stripe)
			path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
			for i := 0; i < 2; i++ {
				w := doInternal(router, "POST", path, admin.String(), "")
				if w.Code != http.StatusOK {
					t.Fatalf("closing export: %d %s", w.Code, w.Body.String())
				}
			}
			for _, call := range stripe.reportCalls {
				if call.EventName == payload.EventName {
					t.Fatalf("closing export duplicated storage: %+v", call)
				}
			}
			for i := 0; i < 2; i++ {
				correction, err := store.MeasureCorrection(ctx, p, "storage")
				if err != nil || !correction.Frozen || correction.Measured != wantQuantity || correction.Baseline != wantQuantity || correction.Target != wantQuantity {
					t.Fatalf("closing/finalized correction: %+v %v", correction, err)
				}
				if err := store.ApplyCorrection(ctx, correction.ID, admin, "accept_usage", "unchanged fractional storage", payload); err != nil {
					t.Fatal(err)
				}
				result, err := billing.FinalizeTeamBillingPeriodWithCredits(ctx, testPool, p.TeamID, p.Start, p.End)
				if err != nil || !result.Period.FinalizedAt.Valid || numericFloat64(t, result.Usage.StorageMibSeconds) != wantMiBSeconds {
					t.Fatalf("fractional storage finalization: %+v %v", result, err)
				}
			}
			var allocations int
			wantAllocations := 1
			if offset != 0 {
				wantAllocations = 2
			}
			if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_export_allocation WHERE team_id=$1 AND resource_type='storage'`, p.TeamID).Scan(&allocations); err != nil || allocations != wantAllocations {
				t.Fatalf("duplicate storage reservations: %d want %d: %v", allocations, wantAllocations, err)
			}
		})
	}
}

func TestIntegration_BillingStorageCreditParity(t *testing.T) {
	team, _, start, end := seedBillingPeriodForStripe(t, true, true)
	key := seedKeyForExistingTeamWithRole(t, team, "viewer")
	plan := "example-credit-" + team.String()
	insertPricingPlanForTest(t, t.Context(), plan, true)
	storageExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from) VALUES($1,'vcpu','second',0,$2),($1,'memory_gib','second',0,$2),($1,'storage_gib','second',0.001,$2)`, plan, start)
	storageExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, plan, start)
	storageExec(t, `UPDATE sandbox_storage_interval SET ended_at=started_at+interval '30 minutes' WHERE team_id=$1`, team)
	storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason) SELECT id,$1,2048,$2,$3,'deleted' FROM sandbox WHERE team_id=$1 LIMIT 1`, team, start.Add(30*time.Minute), start.Add(time.Hour))
	// Startup and promotional grants use the existing common grant ordering.
	for _, g := range []struct {
		reason string
		amount float64
		expiry any
	}{
		{"expired startup credit", 9, end.Add(-time.Second)},
		{"startup credit", 2, end},
		{"stripe promotional credit", 5, nil},
	} {
		storageExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at,expires_at) VALUES($1,$2,$2,$3,$4,$5)`, team, g.amount, g.reason, start, g.expiry)
	}
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{creditBalance: api.StripeCreditBalance{AvailableUSD: 3, ObservedAt: time.Now().UTC()}}}
	stripe.countedUsage = func(event, customer string, from, to time.Time) (string, error) {
		var total float64
		for _, call := range stripe.reportCalls {
			if call.EventName == event {
				var n float64
				if _, err := fmt.Sscan(call.Value, &n); err != nil {
					t.Fatal(err)
				}
				total += n
			}
		}
		return fmt.Sprintf("%.12f", total), nil
	}
	router := newBillingRouter(t, stripe)
	readSummary := func(cost, applied, remaining float64) {
		t.Helper()
		for i := 0; i < 2; i++ {
			w := do(router, "GET", "/billing/summary", key, "")
			if w.Code != 200 {
				t.Fatalf("summary: %d %s", w.Code, w.Body.String())
			}
			b := mustJSON(t, w)
			if b["current_charges_usd"] != cost || b["stripe_credits_applied_usd"] != applied || b["stripe_remaining_credit_usd"] != remaining {
				t.Fatalf("Stripe credit parity: %v", b)
			}
		}
	}
	readSummary(0, 0, 3)
	seedStorageActivation(t, team, start.Add(15*time.Minute))
	readSummary(4.5, 3, 0)
	stripe.creditBalance = api.StripeCreditBalance{AvailableUSD: 2, ObservedAt: time.Now().UTC(), IncludesCurrentPeriodUsage: true}
	readSummary(4.5, 0, 2)
	var balance float64
	if err := testPool.QueryRow(t.Context(), `SELECT sum(remaining_usd) FROM team_credit_grant WHERE team_id=$1`, team).Scan(&balance); err != nil || balance != 16 {
		t.Fatalf("summary deducted local credit: %v %v", balance, err)
	}
	storageExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, team, start)
	admin := seedPlatformAdminProfile(t)
	w := doInternal(router, "POST", "/internal/teams/"+team.String()+"/billing/periods/"+apiPeriodID(start, end)+"/export", admin.String(), "")
	if w.Code != 200 {
		t.Fatalf("credit export: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < 2; i++ {
		result, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, team, start, end)
		if err != nil {
			t.Fatal(err)
		}
		if numericFloat64(t, result.Period.GrossChargesUsd) != 4.5 || numericFloat64(t, result.Period.CreditsAppliedUsd) != 4.5 || numericFloat64(t, result.Period.NetInvoiceAmountUsd) != 0 {
			t.Fatalf("finalized credit parity: %+v", result.Period)
		}
		for reason, want := range map[string]float64{"expired startup credit": 9, "startup credit": 0, "stripe promotional credit": 2.5} {
			if err := testPool.QueryRow(t.Context(), `SELECT remaining_usd FROM team_credit_grant WHERE team_id=$1 AND reason=$2`, team, reason).Scan(&balance); err != nil || balance != want {
				t.Fatalf("grant %s=%v want %v: %v", reason, balance, want, err)
			}
		}
		var count int
		if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_credit_ledger WHERE team_id=$1`, team).Scan(&count); err != nil || count != 2 {
			t.Fatalf("duplicate credit deduction: %d %v", count, err)
		}
	}
}

type storageRecoveryStripe struct {
	*storageReadyStripe
	accepted                       map[string]api.StripeReportMeterEventParams
	failStorage, acceptBeforeError bool
}

func (s *storageRecoveryStripe) ReportMeterEvent(_ context.Context, p api.StripeReportMeterEventParams) error {
	s.reportCalls = append(s.reportCalls, p)
	if p.EventName == "storage_gib_hours" && s.failStorage {
		if s.acceptBeforeError {
			s.accepted[p.Identifier] = p
		}
		return errors.New("storage provider response unavailable")
	}
	s.accepted[p.Identifier] = p
	return nil
}
func (s *storageRecoveryStripe) CountedMeterUsage(_ context.Context, event, customer string, start, end time.Time) (string, error) {
	total := new(big.Rat)
	for _, p := range s.accepted {
		if p.EventName == event {
			n, ok := new(big.Rat).SetString(p.Value)
			if !ok {
				return "", fmt.Errorf("invalid fixture quantity")
			}
			total.Add(total, n)
		}
	}
	return total.FloatString(12), nil
}

func TestIntegration_BillingStorageProviderRecovery(t *testing.T) {
	for _, mode := range []string{"readiness hold", "provider failure", "ambiguous acceptance"} {
		t.Run(mode, func(t *testing.T) {
			store, p := seedIncrementalPeriod(t)
			storageExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start)
			seedStorageActivation(t, p.TeamID, p.Start.Add(15*time.Minute))
			stripe := &storageRecoveryStripe{storageReadyStripe: &storageReadyStripe{fakeStripeClient: &fakeStripeClient{}, ready: map[string]bool{"sub_" + p.TeamID.String(): mode != "readiness hold"}}, accepted: map[string]api.StripeReportMeterEventParams{}, failStorage: mode != "readiness hold", acceptBeforeError: mode == "ambiguous acceptance"}
			router := newBillingRouter(t, stripe)
			admin := seedPlatformAdminProfile(t)
			path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
			attempt := func() {
				w := doInternal(router, "POST", path, admin.String(), "")
				if w.Code != 200 && w.Code != 409 {
					t.Fatalf("export recovery: %d %s", w.Code, w.Body.String())
				}
			}
			attempt()
			var originalID, allocation uuid.UUID
			var identifier, status string
			var first pgtype.Timestamptz
			if err := testPool.QueryRow(t.Context(), `SELECT e.id,e.allocation_id,e.identifier,e.status,e.first_attempt_at FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1 AND a.resource_type='storage' AND e.active`, p.TeamID).Scan(&originalID, &allocation, &identifier, &status, &first); err != nil {
				t.Fatal(err)
			}
			if mode == "readiness hold" {
				if status != "pending" || first.Valid {
					t.Fatalf("readiness consumed retry window: %s %v", status, first)
				}
			} else if status != "uncertain" || !first.Valid {
				t.Fatalf("provider uncertainty lost: %s %v", status, first)
			}
			for _, resource := range []string{"cpu", "memory"} {
				totals, err := store.Totals(t.Context(), p, resource)
				if err != nil || totals.Submitted != "2.000000000000" {
					t.Fatalf("storage failure blocked %s: %+v %v", resource, totals, err)
				}
			}
			stripe.ready["sub_"+p.TeamID.String()] = false
			storageExec(t, `UPDATE billing_export_event SET next_attempt_at=now() WHERE id=$1`, originalID)
			attempt()
			var held pgtype.Timestamptz
			if err := testPool.QueryRow(t.Context(), `SELECT first_attempt_at FROM billing_export_event WHERE id=$1`, originalID).Scan(&held); err != nil || held.Valid != first.Valid || held.Valid && !held.Time.Equal(first.Time) {
				t.Fatalf("readiness reset submission deadline: %v -> %v: %v", first, held, err)
			}
			stripe.ready["sub_"+p.TeamID.String()] = true
			stripe.failStorage = false
			storageExec(t, `UPDATE billing_export_event SET next_attempt_at=now() WHERE id=$1`, originalID)
			attempt()
			attempt()
			totals, err := store.Totals(t.Context(), p, "storage")
			if err != nil || totals.Submitted != "0.750000000000" || totals.Reserved != totals.Submitted {
				t.Fatalf("storage recovery: %+v %v", totals, err)
			}
			var count int
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1 AND a.resource_type='storage'`, p.TeamID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("recovery replaced event: %d %v", count, err)
			}
			for _, call := range stripe.reportCalls {
				if call.EventName == "storage_gib_hours" && (call.Identifier != identifier || call.Value != "0.750000000000") {
					t.Fatalf("recovery payload changed: %+v", call)
				}
			}
			if len(stripe.accepted) != 3 {
				t.Fatalf("provider charged duplicate events: %+v", stripe.accepted)
			}
		})
	}
}
