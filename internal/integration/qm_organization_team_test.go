//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/api"
)

func TestQMOrganizationTeam(t *testing.T) {
	pool := teamCreationDatabase(t, func(pool *pgxpool.Pool) {
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO service_role`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO service_role`)
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO service_role`)
	})
	service := teamCreationServiceRolePool(t, pool)
	token := strings.Repeat("q", 48)
	authority := uuid.NewString()
	t.Setenv("QM_TEAM_SERVICE_TOKEN", token)
	t.Setenv("QM_TEAM_NAMESPACE", "qm-test")
	t.Setenv("QM_TEAM_AUTHORITY_ID", authority)
	t.Setenv("QM_TEAM_REGION", "use")
	h := &api.Handlers{Pool: service}
	r := gin.New()
	r.POST("/internal/qm/organizations/:qm_org_id/team", h.QMOrganizationTeamHandler())
	r.GET("/internal/qm/organizations/:qm_org_id/team", h.QMOrganizationTeamHandler())
	call := func(method, org, key, credential string) *httptest.ResponseRecorder {
		path := "/internal/qm/organizations/" + org + "/team"
		body := ""
		if method == http.MethodGet {
			path += "?idempotency_key=" + key
		} else {
			b, _ := json.Marshal(map[string]string{"idempotency_key": key})
			body = string(b)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-QM-Team-Service-Token", credential)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	org := uuid.NewString()
	key := "qm-org:v1:" + org
	t.Run("unconfigured database is not absence", func(t *testing.T) {
		for _, method := range []string{"GET", "POST"} {
			if w := call(method, org, key, token); w.Code != 409 {
				t.Fatalf("wrong database accepted: %d", w.Code)
			}
		}
	})
	rolloutExec(t, pool, `INSERT INTO qm_team_service_authority(namespace,authority_id,home_region) VALUES('qm-test',$1,'use')`, authority)
	if w := call("POST", org, key, "customer-key"); w.Code != 401 {
		t.Fatalf("customer authorized: %d", w.Code)
	}
	if w := call("POST", org, "wrong", token); w.Code != 400 {
		t.Fatalf("wrong key accepted: %d", w.Code)
	}
	if w := call("GET", org, key, token); w.Code != 404 {
		t.Fatalf("lookup absence: %d %s", w.Code, w.Body)
	}
	const n = 8
	results := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = call("POST", org, key, token) }(i)
	}
	wg.Wait()
	for _, w := range results {
		if w.Code != 200 || w.Body.String() != results[0].Body.String() {
			t.Fatalf("concurrent ensure diverged: %d %s", w.Code, w.Body)
		}
	}
	var result map[string]string
	if err := json.Unmarshal(results[0].Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["qm_org_id"] != org || result["authority_id"] != authority || result["namespace"] != "qm-test" {
		t.Fatal("incorrect provenance")
	}
	id := result["ss_team_id"]
	// Discarding the create response and looking up must recover the same identity.
	if w := call("GET", org, key, token); w.Code != 200 || w.Body.String() != results[0].Body.String() {
		t.Fatal("lost-response recovery changed result")
	}
	for _, table := range []string{"team_member", "team_memberships", "user_role_assignments"} {
		if n := teamCreationCount(t, pool, "SELECT count(*) FROM "+table+" WHERE team_id=$1", id); n != 0 {
			t.Fatalf("synthetic membership in %s", table)
		}
	}
	if n := teamCreationCount(t, pool, `SELECT count(*) FROM qm_organization_teams WHERE qm_org_id=$1`, org); n != 1 {
		t.Fatal("duplicate binding")
	}
	t.Run("independent organizations and managed billing", func(t *testing.T) {
		other := uuid.NewString()
		w := call("POST", other, "qm-org:v1:"+other, token)
		var second map[string]string
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || second["ss_team_id"] == id {
			t.Fatal("independent organizations share a team", w.Code)
		}
		for _, team := range []string{id, second["ss_team_id"]} {
			if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_signup_trial_provenance WHERE team_id=$1`, team); n != 0 {
				t.Fatal("managed team entered human signup")
			}
			if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1`, team); n != 0 {
				t.Fatal("managed team received signup credits")
			}
			if n := teamCreationCount(t, pool, `SELECT count(*) WHERE team_sandbox_billing_eligible($1) AND feature_enabled('billing_metrics_write',$1) AND feature_enabled('billing_hourly_rollups',$1)`, team); n != 1 {
				t.Fatal("managed team requires payment or lost metering")
			}
			// These guard older writers as well as the HTTP checkout route.
			for _, statement := range []string{
				`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,5,'signup trial credit')`,
				`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_example')`,
				`INSERT INTO team_signup_trial_provenance(team_id) VALUES($1)`,
			} {
				tx, err := pool.Begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				localIdentityError(t, tx, "23514", statement, team)
				tx.Rollback(context.Background())
			}
		}
		// Normal human-created teams retain their existing signup gate.
		ordinary := uuid.NewString()
		rolloutExec(t, pool, `INSERT INTO team(id,name,home_region) VALUES($1,$2,'use')`, ordinary, "ordinary-"+ordinary)
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team_signup_trial_provenance WHERE team_id=$1`, ordinary); n != 1 {
			t.Fatal("ordinary signup behavior changed")
		}
	})
	t.Run("rollback leaves no team", func(t *testing.T) {
		badOrg := uuid.NewString()
		rolloutExec(t, pool, `CREATE FUNCTION reject_qm_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$`)
		rolloutExec(t, pool, `CREATE TRIGGER reject_qm_binding BEFORE INSERT ON qm_organization_teams FOR EACH ROW EXECUTE FUNCTION reject_qm_binding()`)
		w := call("POST", badOrg, "qm-org:v1:"+badOrg, token)
		rolloutExec(t, pool, `DROP TRIGGER reject_qm_binding ON qm_organization_teams`)
		if w.Code != 503 {
			t.Fatalf("expected rollback: %d", w.Code)
		}
		if n := teamCreationCount(t, pool, `SELECT count(*) FROM team WHERE name=$1`, "qm-qm-test-"+badOrg); n != 0 {
			t.Fatal("orphan team after rollback")
		}
		if w := call("POST", badOrg, "qm-org:v1:"+badOrg, token); w.Code != 200 {
			t.Fatalf("retry failed: %d %s", w.Code, w.Body)
		}
	})
	t.Run("immutable and restricted", func(t *testing.T) {
		for _, role := range []string{"anon", "authenticated", "service_role"} {
			tx, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(context.Background(), "SET LOCAL ROLE "+role); err != nil {
				t.Fatal(err)
			}
			localIdentityError(t, tx, "42501", `DELETE FROM qm_organization_teams WHERE qm_org_id=$1`, org)
			tx.Rollback(context.Background())
		}
	})
	t.Run("deletion cannot recreate or resurrect", func(t *testing.T) {
		rolloutExec(t, pool, `DELETE FROM team_feature_flag WHERE team_id=$1`, id)
		rolloutExec(t, pool, `DELETE FROM team WHERE id=$1`, id)
		for _, method := range []string{"GET", "POST"} {
			if w := call(method, org, key, token); w.Code != 410 {
				t.Fatalf("deleted binding reused: %d %s", w.Code, w.Body)
			}
		}
		rolloutExec(t, pool, `INSERT INTO team(id,name,home_region) VALUES($1,'replacement-fixture','use')`, id)
		if w := call("POST", org, key, token); w.Code != 410 {
			t.Fatal("reused team id resurrected binding")
		}
	})
}
