//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Run explicitly with -run '^$' -bench BenchmarkQMManagedBilling -benchtime=1s.
// Each fixture rolls back, including immutable bindings. Timings include a local
// database round trip and warm PostgreSQL pages, without the application cache.
func BenchmarkQMManagedBilling(b *testing.B) {
	for _, bindings := range []int{1, 1000, 100000} {
		b.Run(fmt.Sprintf("bindings=%d", bindings), func(b *testing.B) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				b.Fatal(err)
			}
			defer tx.Rollback(ctx)
			exec := func(sql string, args ...any) {
				b.Helper()
				if _, err := tx.Exec(ctx, sql, args...); err != nil {
					b.Fatal(err)
				}
			}
			namespace := "qm-bench-" + uuid.NewString()[:8]
			authority := uuid.New()
			exec(`INSERT INTO qm_team_service_authority VALUES($1,$2,'use')`, namespace, authority)
			exec(`INSERT INTO qm_organization_teams(namespace,qm_org_id,idempotency_key,authority_id,team_id,home_region)
 SELECT $1, md5($1||n)::uuid, 'qm-org:v1:'||md5($1||n)::uuid::text, $2, md5($1||':team:'||n)::uuid, 'use'
 FROM generate_series(1,$3::int) n`, namespace, authority, bindings)
			exec(`ANALYZE qm_organization_teams`)
			exec(`ANALYZE qm_team_service_authority`)
			var baseline string
			if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef('team_sandbox_billing_eligible(uuid)'::regprocedure)`).Scan(&baseline); err != nil {
				b.Fatal(err)
			}
			baseline = strings.Replace(baseline, "public.team_sandbox_billing_eligible", "pg_temp.qm_baseline_eligibility", 1)
			branch := "    WHEN public.qm_team_managed_billing(p_team_id) THEN true\n"
			if !strings.Contains(baseline, branch) {
				b.Fatal("managed branch missing from baseline comparison")
			}
			exec(strings.Replace(baseline, branch, "", 1))
			var managed uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT team_id FROM qm_organization_teams WHERE namespace=$1 LIMIT 1`, namespace).Scan(&managed); err != nil {
				b.Fatal(err)
			}
			ordinary := uuid.New()
			for _, tc := range []struct {
				name string
				id   uuid.UUID
			}{{"managed", managed}, {"ordinary", ordinary}} {
				for _, fn := range []string{"pg_temp.qm_baseline_eligibility", "team_sandbox_billing_eligible"} {
					b.Run(tc.name+"/"+fn, func(b *testing.B) {
						for i := 0; i < b.N; i++ {
							var eligible bool
							if err := tx.QueryRow(ctx, "SELECT "+fn+"($1)", tc.id).Scan(&eligible); err != nil || !eligible {
								b.Fatalf("eligibility=%t err=%v", eligible, err)
							}
						}
					})
				}
			}
			// Inspect the inner predicate as well: SECURITY DEFINER functions do
			// not expose their nested plan in the outer eligibility EXPLAIN.
			plan, err := tx.Query(ctx, `EXPLAIN (ANALYZE, BUFFERS) SELECT EXISTS(SELECT 1 FROM qm_organization_teams b JOIN qm_team_service_authority a USING(namespace,authority_id,home_region) WHERE b.team_id=$1 AND b.deleted_at IS NULL)`, managed)
			if err != nil {
				b.Fatal(err)
			}
			for plan.Next() {
				var line string
				if err := plan.Scan(&line); err != nil {
					b.Fatal(err)
				}
				b.Log(line)
			}
			if err := plan.Err(); err != nil {
				b.Fatal(err)
			}
			plan.Close()
			// Exercise the production sweep with up to 1,000 distinct teams,
			// half managed, and four active sandboxes each. Missing mappings are the
			// ordinary-team path; larger binding fixtures stress index depth.
			exec(`INSERT INTO team(id,name) SELECT md5($1||':ordinary:'||n)::uuid, $1||'-ordinary-'||n FROM generate_series(1,500) n`, namespace)
			exec(`INSERT INTO team(id,name,home_region) SELECT team_id,$1||'-managed-'||qm_org_id,'use' FROM qm_organization_teams WHERE namespace=$1 LIMIT 500`, namespace)
			exec(`INSERT INTO sandbox(team_id,name,status,host_id) SELECT t.id,'bench-'||n,'active',$2 FROM team t CROSS JOIN generate_series(1,4) n WHERE t.name LIKE $1||'-%'`, namespace, testDefaultHostID)
			exec(`ANALYZE sandbox`)
			source, err := os.ReadFile("../../db/queries/billing.sql")
			if err != nil {
				b.Fatal(err)
			}
			query := strings.Split(strings.Split(string(source), "-- name: ListTeamsWithActiveIneligibleSandboxes :many\n")[1], "-- name: ActivateTeamBilling")[0]
			query = strings.ReplaceAll(query, "sqlc.narg(after_team_id)", "NULL")
			query = strings.ReplaceAll(query, "sqlc.arg(batch_limit)", "1000")
			for _, fn := range []string{"pg_temp.qm_baseline_eligibility", "team_sandbox_billing_eligible"} {
				q := strings.ReplaceAll(query, "team_sandbox_billing_eligible(", fn+"(")
				b.Run("sweep/"+fn, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						rows, err := tx.Query(ctx, q)
						if err != nil {
							b.Fatal(err)
						}
						for rows.Next() {
						}
						if err := rows.Err(); err != nil {
							b.Fatal(err)
						}
						rows.Close()
					}
				})
				rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+q)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
					var line string
					if err := rows.Scan(&line); err != nil {
						b.Fatal(err)
					}
					b.Log(fn, line)
				}
				if err := rows.Err(); err != nil {
					b.Fatal(err)
				}
				rows.Close()
			}
		})
	}
}
