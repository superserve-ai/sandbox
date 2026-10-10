//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type createCacheDB struct {
	db.DBTX
	ownerReads atomic.Int64
}

func (d *createCacheDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "owner_principal_id,team_id FROM sandbox_machine_owner WHERE") {
		d.ownerReads.Add(1)
		return createCacheErrorRow{}
	}
	return d.DBTX.QueryRow(ctx, sql, args...)
}

type createCacheErrorRow struct{}

func (createCacheErrorRow) Scan(...any) error {
	return errors.New("unexpected post-commit ownership read")
}

type createCacheResolver struct{ caller auth.CallerContext }

func (r createCacheResolver) ResolveMachineCredential(context.Context, string) (auth.CallerContext, error) {
	return r.caller, nil
}

type createCacheVMD struct {
	*stubVMD
	fail              bool
	observedCommitted atomic.Bool
}

func (v *createCacheVMD) PublishSandboxOwnership(ctx context.Context, id string, principal, team uuid.UUID) error {
	owner, err := testQueries.GetMachineSandboxOwner(ctx, uuid.MustParse(id), team)
	if err != nil {
		return err
	}
	if owner.OwnerPrincipalID != principal {
		return errors.New("committed owner mismatch")
	}
	v.observedCommitted.Store(true)
	if v.fail {
		return errors.New("ownership attestation failed")
	}
	return nil
}

func TestMachineCreateCachesOnlyCommittedAttestedOwnership(t *testing.T) {
	ctx := context.Background()
	var templateID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM template WHERE team_id=$1 AND name='superserve/base' AND deleted_at IS NULL`, testSystemTeamID).Scan(&templateID); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "owner_insert_failure", "attestation_failure"} {
		t.Run(scenario, func(t *testing.T) {
			teamID, _ := seedTeamAndKey(t)
			principal, err := testQueries.EnsureMachinePrincipal(ctx, teamID, uuid.New(), pgtype.UUID{Bytes: templateID, Valid: true})
			if err != nil {
				t.Fatal(err)
			}
			caller := auth.CallerContext{PrincipalID: principal.ID, TeamID: teamID, HostedTenantID: principal.HostedTenantID, CredentialID: uuid.New(), LineageID: uuid.New(), Audience: "sandbox-api", AllowedAudiences: []string{"sandbox-proxy"}, ExpiresAt: time.Now().Add(time.Hour), RevocationGeneration: uint64(principal.Generation), ApprovedTemplateID: &templateID, Permissions: []auth.MachineOperation{auth.MachineOperationCreate, auth.MachineOperationRead}, Policy: auth.NewMachinePolicy(auth.MachineOperationCreate, auth.MachineOperationRead)}
			if scenario == "owner_insert_failure" {
				caller.PrincipalID = uuid.New()
			}
			store := &createCacheDB{DBTX: testPool}
			vmd := &createCacheVMD{stubVMD: &stubVMD{}, fail: scenario == "attestation_failure"}
			seed := []byte("machine-create-cache-signing-key-0123456")
			h := api.NewHandlers(vmd, db.New(store), &config.Config{SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID, SandboxAccessTokenSeed: seed})
			h.Pool = testPool
			defer h.WaitAsyncBookkeeping()
			var cached atomic.Bool
			handlerDone := make(chan struct{})
			router := gin.New()
			router.Use(api.MachineCredentialAuth(createCacheResolver{caller: caller}), func(c *gin.Context) {
				c.Next()
				_, ok := c.Get("machine_resource_owner")
				cached.Store(ok)
				close(handlerDone)
			})
			router.POST("/sandboxes", h.CreateSandbox)
			server := httptest.NewServer(router)
			defer server.Close()
			request, err := http.NewRequest(http.MethodPost, server.URL+"/sandboxes", strings.NewReader(`{"name":"cache-fixture"}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-QM-Machine-Credential", "synthetic-runtime-fixture")
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var body map[string]any
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			<-handlerDone
			if store.ownerReads.Load() != 0 {
				t.Fatalf("create added %d ownership reads after transaction", store.ownerReads.Load())
			}
			if scenario == "success" {
				if response.StatusCode != http.StatusCreated || !cached.Load() || !vmd.observedCommitted.Load() {
					t.Fatalf("successful create not committed/cached: status=%d body=%v cached=%v committed=%v", response.StatusCode, body, cached.Load(), vmd.observedCommitted.Load())
				}
				token, _ := body["access_token"].(string)
				claim, err := auth.VerifyMachineCapability(token, seed, time.Now())
				if err != nil || claim.PrincipalID != principal.ID || claim.TeamID != teamID {
					t.Fatalf("committed ownership token incorrect: %+v %v", claim, err)
				}
			} else {
				if response.StatusCode != http.StatusInternalServerError || cached.Load() || body["access_token"] != nil {
					t.Fatalf("failed create published authority: status=%d cached=%v body=%v", response.StatusCode, cached.Load(), body)
				}
				if scenario == "owner_insert_failure" {
					var count int
					if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox WHERE team_id=$1`, teamID).Scan(&count); err != nil || count != 0 {
						t.Fatalf("ownership transaction did not roll back: count=%d err=%v", count, err)
					}
				}
			}
		})
	}
}
