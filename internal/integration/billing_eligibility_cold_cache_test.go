//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/api"
)

func TestIntegration_BillingEligibilityColdCacheDoesNotReadUsageHistory(t *testing.T) {
	for _, fleet := range []int{1, 1000} {
		t.Run(fmt.Sprintf("sandboxes=%d", fleet), func(t *testing.T) {
			team, err := testQueries.CreateTeam(t.Context(), "example-cold-eligibility-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, table := range []string{"sandbox_compute_billing_interval", "sandbox_storage_interval", "sandbox", "template", "team_credit_grant", "team_billing_account"} {
					if _, err := testPool.Exec(context.Background(), "DELETE FROM "+table+" WHERE team_id=$1", team.ID); err != nil {
						t.Errorf("clean up cold eligibility fixture %s: %v", table, err)
					}
				}
				if _, err := testPool.Exec(context.Background(), `DELETE FROM team WHERE id=$1`, team.ID); err != nil {
					t.Errorf("clean up cold eligibility team: %v", err)
				}
			})
			seedHistoricalTeam(t, team.ID)
			start := time.Now().UTC().Add(-24 * time.Hour)
			storageExec(t, `INSERT INTO team_billing_account(team_id) VALUES($1)`, team.ID)
			storageExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at)
				VALUES($1,1000000,1000000,'signup trial credit',$2)`, team.ID, start)
			storageExec(t, `INSERT INTO template(team_id,name,status,build_spec,vcpu,memory_mib,disk_mib,rootfs_path)
				SELECT $1::uuid,'example-cold-'||n,'ready','{}',1,1024,1024,'/templates/'||$1::uuid::text||'/'||n||'/base.ext4'
				FROM generate_series(1,$2::int) n`, team.ID, fleet)
			storageExec(t, `INSERT INTO artifact_manifest(template_id,file_name,path,size_bytes,allocated_bytes,sha256)
				SELECT id,'base.ext4',rootfs_path,1073741824,1073741824,repeat('0',64) FROM template WHERE team_id=$1`, team.ID)
			storageExec(t, `INSERT INTO sandbox(team_id,name,status,vcpu_count,memory_mib,host_id,template_id,created_at)
				SELECT $1,name,'paused',1,1024,'default',id,$2 FROM template WHERE team_id=$1`, team.ID, start)
			storageExec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
				SELECT s.id,$1,1,1024,$2::timestamptz+n*interval '1 minute',$2::timestamptz+(n+1)*interval '1 minute','paused'
				FROM sandbox s CROSS JOIN generate_series(0,9) n WHERE s.team_id=$1`, team.ID, start)
			storageExec(t, `INSERT INTO sandbox_storage_interval(sandbox_id,team_id,disk_mib,started_at,ended_at,end_reason)
				SELECT s.id,$1,1024,$2::timestamptz+n*interval '1 minute',$2::timestamptz+(n+1)*interval '1 minute','deleted'
				FROM sandbox s CROSS JOIN generate_series(0,9) n WHERE s.team_id=$1`, team.ID, start)
			seedStorageActivation(t, team.ID, start.Add(5*time.Minute))
			if err := testQueries.RefreshTeamTrialEligibility(t.Context(), team.ID); err != nil {
				t.Fatal(err)
			}
			for _, eligible := range []bool{true, false} {
				t.Run(fmt.Sprintf("persisted_eligible=%t", eligible), func(t *testing.T) {
					storageExec(t, `UPDATE team_trial_eligibility_cache SET eligible=$2 WHERE team_id=$1`, team.ID, eligible)
					lock, err := testPool.Begin(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer lock.Rollback(context.Background())
					// Even a fast accidental aggregate must block here. This proves
					// bounded history access independently of machine/cache timing.
					if _, err := lock.Exec(t.Context(), `LOCK TABLE sandbox_compute_billing_interval, sandbox_storage_interval, artifact_manifest, sandbox IN ACCESS EXCLUSIVE MODE`); err != nil {
						t.Fatal(err)
					}
					for attempt := 0; attempt < 3; attempt++ {
						h := &api.Handlers{Pool: testPool, DB: testQueries}
						ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
						w := httptest.NewRecorder()
						c, _ := gin.CreateTestContext(w)
						c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil).WithContext(ctx)
						began := time.Now()
						got := api.RequireBillingEligibleForTest(h, c, team.ID)
						elapsed := time.Since(began)
						cancel()
						if got != eligible || (!eligible && w.Code != http.StatusPaymentRequired) {
							t.Fatalf("cold gate read locked history or lost persisted verdict: got=%t status=%d body=%s", got, w.Code, w.Body.String())
						}
						t.Logf("cold gate: fleet=%d intervals=%d artifacts=%d eligible=%t elapsed=%s", fleet, fleet*20, fleet, eligible, elapsed)
					}
				})
			}
		})
	}
}
