//go:build integration

package integration

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_BillingMissingLegacyStorage(t *testing.T) {
	for _, tc := range []struct {
		name         string
		subscribed   bool
		activation   time.Duration
		measuredZero bool
		wantStatus   int
	}{
		{"tracking only", false, -1, false, http.StatusOK},
		{"subscribed without storage activation", true, -1, false, http.StatusOK},
		{"missing history before activation", true, 2 * time.Hour, false, http.StatusOK},
		{"missing billable measurements", true, 0, false, http.StatusServiceUnavailable},
		{"measured zero", false, -1, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			team, key, _ := seedTeamAndKeyWithRole(t, "viewer")
			start := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
			end := start.Add(3 * time.Hour)
			plan := "legacy-storage-" + uuid.NewString()
			insertPricingPlanForTest(t, t.Context(), plan, true)
			storageExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from)
				VALUES($1,'vcpu','second',0.000011,$2),($1,'memory_gib','second',0.0000045,$2),($1,'storage_gib','second',0.00000003,$2)`, plan, start.Add(-time.Hour))
			storageExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, team, plan, start.Add(-time.Hour))
			storageExec(t, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team)
			storageExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, start, end)
			if tc.subscribed {
				storageExec(t, `UPDATE team_billing_account SET stripe_customer_id=$2,stripe_subscription_id=$3,stripe_subscription_status='active' WHERE team_id=$1`, team, "cus_"+team.String(), "sub_"+team.String())
			}
			if tc.activation >= 0 {
				seedStorageActivation(t, team, start.Add(tc.activation))
			}
			template, sandbox := uuid.New(), uuid.New()
			storageExec(t, `INSERT INTO template(id,team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path)
				VALUES($1,$2,'legacy-template','ready','{}',1,1024,1024,'/templates/'||$1::uuid::text||'/base.ext4')`, template, team)
			// An old sandbox still references a build with no manifest. Its
			// retention ends before the later-activation case starts billing.
			storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,template_id,base_path,created_at,destroyed_at)
				SELECT $1,$2,'legacy-sandbox','deleted',1,1024,'default',id,rootfs_path,$4,$5 FROM template WHERE id=$3`, sandbox, team, template, start, start.Add(time.Hour))
			storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason)
				VALUES($1,$2,'default',0,$3,$4,'deleted')`, sandbox, team, start, start.Add(time.Hour))
			storageExec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
				VALUES($1,$2,1,1024,$3,$4,'paused')`, sandbox, team, start, start.Add(time.Hour))
			if tc.measuredZero {
				storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
					SELECT id,'base.ext4',rootfs_path,0,0,repeat('0',64) FROM template WHERE id=$1`, template)
			}
			storageCharge := 0.0
			if tc.activation > 0 {
				// Complete post-activation usage must still be charged even when
				// unrelated older artifacts make the tracked total unknown.
				currentSandbox := uuid.New()
				storageExec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id,created_at,destroyed_at)
					VALUES($1,$2,'measured-sandbox','deleted',1,1024,'default',$3,$4)`, currentSandbox, team, start.Add(tc.activation), end)
				storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,host_id,disk_mib,started_at,ended_at,end_reason)
					VALUES($1,$2,'default',1024,$3,$4,'deleted')`, currentSandbox, team, start.Add(tc.activation), end)
				storageCharge = 0.000108
			}
			usage, err := testQueries.GetTeamBillingUsage(t.Context(), db.GetTeamBillingUsageParams{TeamID: team, PeriodStart: start, PeriodEnd: end})
			if err != nil || usage.StorageGibSeconds.Valid != tc.measuredZero {
				t.Fatalf("fixture must distinguish missing and measured-zero usage: %+v, %v", usage, err)
			}
			router := newBillingRouter(t, &fakeStripeClient{creditBalance: api.StripeCreditBalance{AvailableUSD: 10, ObservedAt: time.Now().UTC()}})
			for _, path := range []string{
				"/billing/summary",
				"/billing/usage-series?start=" + start.Format(time.RFC3339) + "&end=" + end.Format(time.RFC3339) + "&granularity=day&timezone=UTC",
			} {
				w := do(router, http.MethodGet, path, key, "")
				if w.Code != tc.wantStatus {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
				}
				if tc.wantStatus == http.StatusServiceUnavailable {
					if !strings.Contains(w.Body.String(), "storage_unavailable") {
						t.Fatalf("missing billable usage must fail closed: %s", w.Body.String())
					}
					continue
				}
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				var storage map[string]any
				var cost float64
				if path == "/billing/summary" {
					resources := body["resources_by_key"].(map[string]any)
					storage = resources["storage_gib"].(map[string]any)
					for _, entry := range body["resources"].([]any) {
						r := entry.(map[string]any)
						if r["resource_key"] == "storage_gib" && r["usage"] != storage["usage"] {
							t.Fatal("resource list and keyed resource disagree")
						}
					}
					cost = body["current_charges_usd"].(float64)
					if resources["vcpu"].(map[string]any)["usage"] != float64(3600) || math.Abs(body["cost_breakdown_usd"].(map[string]any)["storage"].(float64)-storageCharge) > 1e-12 {
						t.Fatalf("compute usage/storage charges changed: %s", w.Body.String())
					}
				} else {
					buckets := body["buckets"].([]any)
					storage = buckets[0].(map[string]any)["storage"].(map[string]any)
					for _, entry := range buckets {
						cost += entry.(map[string]any)["billed_total_usd"].(float64)
					}
				}
				wantUsage := any(nil)
				if tc.measuredZero {
					wantUsage = float64(0)
				}
				if value, present := storage["usage"]; !present || value != wantUsage {
					t.Fatalf("storage usage = %v (present %v), want %v", value, present, wantUsage)
				}
				if math.Abs(cost-(0.0558+storageCharge)) > 1e-9 {
					t.Fatalf("complete charges = %v, want %v", cost, 0.0558+storageCharge)
				}
			}
		})
	}
}
