package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type boundaryOwnerDB struct {
	*mockDBTX
	principal uuid.UUID
	failure   error
	reads     int
}

func (d *boundaryOwnerDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if strings.Contains(query, "FROM sandbox_machine_owner") {
		d.reads++
		return &mockRow{scanFn: func(dest ...any) error {
			if d.failure != nil {
				return d.failure
			}
			*dest[0].(*uuid.UUID) = args[0].(uuid.UUID)
			*dest[1].(*uuid.UUID) = d.principal
			*dest[2].(*uuid.UUID) = args[1].(uuid.UUID)
			return nil
		}}
	}
	return d.mockDBTX.QueryRow(ctx, query, args...)
}

func TestSharedResumePreservesMachineOwner(t *testing.T) {
	for _, scenario := range []string{"machine", "ordinary", "ordinary_actorless", "claim_failure"} {
		t.Run(scenario, func(t *testing.T) {
			sandbox, team, principal, snapID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			sb := pausedSandboxWithSnapshot(sandbox, team, snapID)
			snap := db.Snapshot{ID: snapID, SandboxID: sandbox, TeamID: team, Path: "/snapshots/example.snap", Trigger: "pause"}
			claims := 0
			m := &boundaryOwnerDB{principal: principal, mockDBTX: &mockDBTX{
				queryRowFn: func(_ context.Context, q string, _ ...any) pgx.Row {
					if strings.Contains(q, "'resuming'") {
						claims++
						if scenario == "claim_failure" {
							return &mockRow{scanFn: func(...any) error { return errors.New("claim unavailable") }}
						}
						row := claimResumeRow(sb, &snap, "", 0)
						return &mockRow{scanFn: func(dest ...any) error {
							if err := row.Scan(dest...); err != nil {
								return err
							}
							if scenario == "machine" {
								*dest[50].(*bool) = true
								*dest[51].(*pgtype.UUID) = pgtype.UUID{Bytes: principal, Valid: true}
								*dest[52].(*pgtype.UUID) = pgtype.UUID{Bytes: team, Valid: true}
							}
							return nil
						}}
					}
					if strings.Contains(q, "FROM sandbox") {
						return sandboxRow(sb)
					}
					return activityRow()
				}, execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}}
			m.failure = errors.New("unexpected separate ownership lookup")
			vmdCalls := 0
			vmd := &stubVMD{resumeFn: func(context.Context, string, string, string, []byte) (string, error) {
				vmdCalls++
				return "", status.Error(codes.NotFound, "missing")
			}}
			h := &Handlers{DB: db.New(m), VMD: vmd}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandbox.String()+"/activate", nil)
			actor := uuid.New()
			if scenario != "ordinary_actorless" {
				c.Set("actor_id", actor)
			}
			c.Set("team_id", team.String())
			_, ok := h.resumePausedSandbox(c, &sb, team, nil)
			if scenario == "claim_failure" {
				_, cached := c.Get("machine_resource_owner")
				if ok || claims != 1 || vmdCalls != 0 || cached {
					t.Fatal("failed claim published ownership or reached VMD")
				}
				return
			}
			wantOwner := actor.String()
			if scenario == "machine" {
				wantOwner = "machine:" + principal.String()
			} else if scenario == "ordinary_actorless" {
				wantOwner = "ordinary:attested"
			}
			if !ok || claims != 1 || vmd.restoreOwner != wantOwner {
				t.Fatalf("restore lost immutable owner: ok=%v owner=%q", ok, vmd.restoreOwner)
			}
			_, err := h.requestSandboxOwner(c, sandbox, team)
			if m.reads != 0 || (scenario == "machine" && err != nil) || (strings.HasPrefix(scenario, "ordinary") && !errors.Is(err, pgx.ErrNoRows)) {
				t.Fatalf("claim ownership not reused: reads=%d err=%v", m.reads, err)
			}
		})
	}
}

func TestAPIKeyResponseCapsParentExpiryAndFailsClosed(t *testing.T) {
	team, sandbox, parent, creator, principal := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	expiry := now.Add(20 * time.Second)
	for _, failure := range []error{nil, errors.New("authority unavailable"), pgx.ErrNoRows} {
		m := &boundaryOwnerDB{principal: principal, failure: failure, mockDBTX: &mockDBTX{}}
		h := &Handlers{DB: db.New(m), Config: &config.Config{SandboxAccessTokenSeed: []byte("machine-boundary-test-signing-key-000")}}
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandbox.String(), nil)
		setAPIKeyContext(c, apiKeyCacheEntry{id: parent.String(), teamID: team.String(), createdBy: pgtype.UUID{Bytes: creator, Valid: true}, expiresAt: pgtype.Timestamptz{Time: expiry, Valid: true}})
		resp := h.sandboxResponseForRequest(c, db.Sandbox{ID: sandbox, TeamID: team}, now)
		if failure != nil {
			if errors.Is(failure, pgx.ErrNoRows) {
				if !auth.VerifyAccessToken(h.Config.SandboxAccessTokenSeed, sandbox.String(), resp.AccessToken) {
					t.Fatal("ordinary compatibility lost")
				}
			} else if resp.AccessToken != "" {
				t.Fatal("lookup failure issued token")
			}
			continue
		}
		claim, err := auth.VerifyMachineCapability(resp.AccessToken, h.Config.SandboxAccessTokenSeed, now)
		if err != nil || claim.CallerKind != "api_key" || claim.ActorID != uuid.Nil || claim.ParentCredentialID != parent || !claim.ExpiresAt.Equal(expiry) {
			t.Fatalf("key provenance/expiry lost: %+v err=%v", claim, err)
		}
	}
}

func TestActorlessTeamKeyReceivesMachineSandboxCapability(t *testing.T) {
	team, sandbox, parent := uuid.New(), uuid.New(), uuid.New()
	m := &boundaryOwnerDB{principal: uuid.New(), mockDBTX: &mockDBTX{}}
	h := &Handlers{DB: db.New(m), Config: &config.Config{SandboxAccessTokenSeed: []byte("machine-boundary-test-signing-key-000")}}
	for _, keyName := range []string{"team-service", consoleImpersonationKeyName} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandbox.String(), nil)
		setAPIKeyContext(c, apiKeyCacheEntry{id: parent.String(), name: keyName, teamID: team.String()})
		if actorIDFromContext(c) != nil {
			t.Fatal("unexpected actor")
		}
		now := time.Now()
		response := h.sandboxResponseForRequest(c, db.Sandbox{ID: sandbox, TeamID: team}, now)
		capability, err := auth.VerifyMachineCapability(response.AccessToken, h.Config.SandboxAccessTokenSeed, now)
		if err != nil || capability.CallerKind != "api_key" || capability.ParentCredentialID != parent || capability.ActorID != uuid.Nil {
			t.Fatalf("actorless key capability: %+v %v", capability, err)
		}
		c.Set("api_key_id", "")
		if response := h.sandboxResponseForRequest(c, db.Sandbox{ID: sandbox, TeamID: team}, now); response.AccessToken != "" {
			t.Fatal("missing authenticated key received capability")
		}
	}
}
