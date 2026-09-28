//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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
			team, err := testQueries.CreateTeam(ctx, "example-prospective-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
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
				var balance float64
				if err = testPool.QueryRow(ctx, `SELECT remaining_usd FROM team_credit_grant WHERE team_id=$1`, team.ID).Scan(&balance); err != nil || balance != 10000 {
					t.Fatalf("read double-deducted grant: %v %v", balance, err)
				}
			}
			check()
			exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID)
			check()
			if tc.activated {
				if _, err = testPool.Exec(ctx, `UPDATE team_storage_billing_activation SET effective_at=effective_at+interval '1 hour' WHERE team_id=$1`, team.ID); err == nil {
					t.Fatal("activation changed")
				}
				if _, err = testPool.Exec(ctx, `DELETE FROM team_storage_billing_activation WHERE team_id=$1`, team.ID); err == nil {
					t.Fatal("activation deleted")
				}
			}
		})
	}
}

type storageReadyStripe struct {
	*fakeStripeClient
	mu        sync.Mutex
	ready     map[string]bool
	creates   int
	inspected []string
}

func (s *storageReadyStripe) EnsureStorageSubscription(_ context.Context, p api.StripeStorageSubscriptionParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspected = append(s.inspected, p.SubscriptionID)
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
	before := time.Now().UTC()
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
		t.Fatal("activation backdated")
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
	for i := 0; i < 2; i++ {
		w := doBillingOperator(router, path, operatorRBACToken, admin.String(), body)
		var response struct {
			EffectiveAt time.Time `json:"effective_at"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || !response.EffectiveAt.Equal(cutoff) {
			t.Fatalf("trial activation: %d %s", w.Code, w.Body.String())
		}
		if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_storage_billing_enabled'`, team.ID); err != nil {
			t.Fatal(err)
		}
	}
	var untouched bool
	if err := testPool.QueryRow(t.Context(), `SELECT stripe_customer_id IS NULL AND stripe_subscription_id IS NULL AND trial_ended_at IS NULL FROM team_billing_account WHERE team_id=$1`, team.ID).Scan(&untouched); err != nil || !untouched || stripe.creates != 0 || len(stripe.customerCalls) != 0 || len(stripe.checkoutCalls) != 0 {
		t.Fatalf("trial subscription mutated: %v %v", untouched, err)
	}
}

func TestIntegration_BillingStorageDoesNotCorrectPreActivationFrozenUsage(t *testing.T) {
	store, period := seedIncrementalPeriod(t)
	seedStorageActivation(t, period.TeamID, time.Now().UTC())
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, period.TeamID); err != nil {
		t.Fatal(err)
	}
	correction, err := store.MeasureCorrection(t.Context(), period, "storage")
	if err != nil {
		t.Fatal(err)
	}
	if correction.Measured != "0.000000000000" || correction.Baseline != "0.000000000000" || correction.Target != "0.000000000000" {
		t.Fatalf("frozen tracked storage became payable: %+v", correction)
	}
	enabled, err := testQueries.IsStorageBillingActivatedForWindow(t.Context(), db.IsStorageBillingActivatedForWindowParams{TeamID: period.TeamID, PeriodEnd: period.End})
	if err != nil || enabled {
		t.Fatalf("historical window enabled: %v %v", enabled, err)
	}
}
