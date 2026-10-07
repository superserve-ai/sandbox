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
	for _, lookupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "lookup_failure"}[lookupFails], func(t *testing.T) {
			sandbox, team, principal, snapID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			sb := pausedSandboxWithSnapshot(sandbox, team, snapID)
			snap := db.Snapshot{ID: snapID, SandboxID: sandbox, TeamID: team, Path: "/snapshots/example.snap", Trigger: "pause"}
			claims := 0
			m := &boundaryOwnerDB{principal: principal, mockDBTX: &mockDBTX{
				queryRowFn: func(_ context.Context, q string, _ ...any) pgx.Row {
					if strings.Contains(q, "'resuming'") {
						claims++
						return claimResumeRow(sb, &snap, "", 0)
					}
					if strings.Contains(q, "FROM sandbox") {
						return sandboxRow(sb)
					}
					return activityRow()
				}, execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}}
			if lookupFails {
				m.failure = errors.New("lookup unavailable")
			}
			vmd := &stubVMD{resumeFn: func(context.Context, string, string, string, []byte) (string, error) {
				return "", status.Error(codes.NotFound, "missing")
			}}
			h := &Handlers{DB: db.New(m), VMD: vmd}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandbox.String()+"/activate", nil)
			c.Set("actor_id", uuid.New())
			c.Set("team_id", team.String())
			_, ok := h.resumePausedSandbox(c, &sb, team, nil)
			if lookupFails {
				if ok || claims != 0 || vmd.restoreOwner != "" {
					t.Fatal("failed ownership lookup reached lifecycle work")
				}
				return
			}
			if !ok || vmd.restoreOwner != "machine:"+principal.String() {
				t.Fatalf("restore lost immutable owner: ok=%v owner=%q", ok, vmd.restoreOwner)
			}
			if _, err := h.requestSandboxOwner(c, sandbox, team); err != nil || m.reads != 1 {
				t.Fatalf("ownership not reused: reads=%d err=%v", m.reads, err)
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
