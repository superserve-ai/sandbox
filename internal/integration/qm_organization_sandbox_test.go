//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Real credential resolution and SQL ownership are used; only the VM is synthetic.
func TestQMOrganizationSandboxIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	teamToken, operator := strings.Repeat("q", 48), strings.Repeat("o", 48)
	t.Setenv("QM_TEAM_SERVICE_TOKEN", teamToken)
	t.Setenv("QM_TEAM_NAMESPACE", "qm-isolation")
	t.Setenv("QM_TEAM_REGION", "use")
	t.Setenv("OPERATOR_API_TOKEN", operator)
	authorityID := uuid.NewString()
	t.Setenv("QM_TEAM_AUTHORITY_ID", authorityID)
	rolloutExec(t, testPool, `INSERT INTO qm_team_service_authority(namespace,authority_id,home_region) VALUES('qm-isolation',$1,'use')`, authorityID)
	var template uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM template WHERE team_id=$1 AND name='superserve/base' AND deleted_at IS NULL`, testSystemTeamID).Scan(&template); err != nil {
		t.Fatal(err)
	}
	authority := api.NewDBMachineAuthority(testQueries)
	authority.SetEligibility(api.AuthorityEligibility{ContractRevision: "machine-identity-v1", Environment: "test", ConfiguredEnvironment: "test", SchemaReady: true, OwnershipReady: true, VerifierReady: true, OperatorReady: true})
	authority.Enable()
	seed := []byte("qm-organization-test-signing-key-0123456789")
	vmd := &createCacheVMD{stubVMD: &stubVMD{}}
	h := api.NewHandlers(vmd, testQueries, &config.Config{SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID, SandboxAccessTokenSeed: seed})
	h.Pool = testPool
	h.MachineCredentials = authority
	defer h.WaitAsyncBookkeeping()
	server := httptest.NewServer(api.SetupRouter(ctx, h, testPool))
	defer server.Close()
	call := func(method, path, header, credential string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(header, credential)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}
	type organization struct {
		team, principal, sandbox uuid.UUID
		material                 string
	}
	orgs := make([]organization, 2)
	for n := range orgs {
		org := uuid.NewString()
		status, result := call("POST", "/internal/qm/organizations/"+org+"/team", "X-QM-Team-Service-Token", teamToken, map[string]string{"idempotency_key": "qm-org:v1:" + org})
		if status != 200 {
			t.Fatalf("team create: %d %v", status, result)
		}
		team := uuid.MustParse(result["ss_team_id"].(string))
		tenant := uuid.New()
		status, result = call("POST", "/internal/machine-identity/principals", "Authorization", "Bearer "+operator, map[string]any{"team_id": team, "hosted_tenant_id": tenant, "approved_template_id": template})
		if status != 200 {
			t.Fatalf("principal create: %d %v", status, result)
		}
		principal := uuid.MustParse(result["principal_id"].(string))
		material := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(n + 1)}, 32))
		status, result = call("POST", "/internal/machine-identity/principals/"+principal.String()+"/credentials/issue", "Authorization", "Bearer "+operator, map[string]any{"operation_id": uuid.New(), "expected_generation": 1, "credential_material": material})
		if status != 200 {
			t.Fatalf("credential issue: %d %v", status, result)
		}
		caller, err := authority.ResolveMachineCredential(ctx, material)
		if err != nil || caller.TeamID != team || caller.PrincipalID != principal || caller.HostedTenantID != tenant {
			t.Fatal("credential wired to wrong team or principal", err)
		}
		status, result = call("POST", "/sandboxes", "X-QM-Machine-Credential", material, map[string]string{"name": "managed-fixture"})
		if status != 201 {
			t.Fatalf("sandbox create: %d %v", status, result)
		}
		sandbox := uuid.MustParse(result["id"].(string))
		child, err := auth.VerifyMachineCapability(result["access_token"].(string), seed, time.Now())
		if err != nil || child.TeamID != team || child.PrincipalID != principal || child.SandboxID != sandbox {
			t.Fatal("child authority differs", err)
		}
		if count := teamCreationCount(t, testPool, `SELECT count(*) FROM sandbox s JOIN sandbox_machine_owner o ON o.sandbox_id=s.id WHERE s.id=$1 AND s.team_id=$2 AND o.team_id=$2 AND o.owner_principal_id=$3`, sandbox, team, principal); count != 1 {
			t.Fatal("sandbox ownership differs")
		}
		orgs[n] = organization{team, principal, sandbox, material}
	}
	if orgs[0].team == orgs[1].team || orgs[0].principal == orgs[1].principal {
		t.Fatal("organizations share authority")
	}
	for n, o := range orgs {
		status, _ := call("GET", "/sandboxes/"+orgs[1-n].sandbox.String(), "X-QM-Machine-Credential", o.material, nil)
		if status != 404 && status != 403 {
			t.Fatalf("cross-team sandbox read accepted: %d", status)
		}
		status, _ = call("POST", "/internal/qm/organizations/"+uuid.NewString()+"/team", "X-QM-Team-Service-Token", o.material, nil)
		if status != 401 {
			t.Fatal("runtime credential granted team administration")
		}
		// Advance only the test usage clock and aggregate through the production query.
		hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
		rolloutExec(t, testPool, `UPDATE sandbox_compute_billing_interval SET started_at=$2,ended_at=$3,end_reason='paused' WHERE sandbox_id=$1`, o.sandbox, hour, hour.Add(time.Duration(n+1)*time.Minute))
		usage, err := testQueries.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{TeamID: o.team, HourStart: pgtype.Timestamptz{Time: hour, Valid: true}, HourEnd: pgtype.Timestamptz{Time: hour.Add(time.Hour), Valid: true}})
		if err != nil || usage.TeamID != o.team {
			t.Fatal("usage rollup failed", err)
		}
		if count := teamCreationCount(t, testPool, `SELECT count(*) FROM team_billing_usage_hourly WHERE team_id=$1 AND hour_start=$2 AND vcpu_seconds=60*$3*(SELECT vcpu_count FROM sandbox WHERE id=$4)`, o.team, hour, n+1, o.sandbox); count != 1 {
			t.Fatal("usage missing or attributed to another organization")
		}
	}
}
