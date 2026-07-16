package api

import (
	"context"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func TestFailSavedSnapshotAndSourceRequiresDurableFallbackProofBeforeDestroy(t *testing.T) {
	for _, tt := range []struct {
		name        string
		fallbackOK  bool
		wantDestroy bool
	}{
		{name: "fallback transition commits", fallbackOK: true, wantDestroy: true},
		{name: "fallback transition returns no proof", fallbackOK: false, wantDestroy: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			teamID, sourceID, snapshotID := uuid.New(), uuid.New(), uuid.New()
			hostID := "snapshot-host"
			saved := db.Snapshot{
				ID: snapshotID, SandboxID: sourceID, TeamID: teamID,
				Kind: db.SnapshotKindSaved, Status: db.SnapshotStatusCreating, HostID: &hostID,
			}
			var revocationPersisted, fallbackAttempted bool
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "-- name: FailSavedSnapshotAndSource :one"):
						return notFoundRow()
					case strings.Contains(sql, "-- name: FailSavedSnapshotSourceAfterRevocation :one"):
						fallbackAttempted = true
						if tt.fallbackOK {
							return uuidRow(sourceID)
						}
						return notFoundRow()
					default:
						t.Fatalf("unexpected DB row query: %s", sql)
						return notFoundRow()
					}
				},
				execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					if !strings.Contains(sql, "-- name: UpsertSandboxRevocation :exec") {
						t.Fatalf("unexpected DB exec: %s", sql)
					}
					revocationPersisted = true
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				},
			}
			var revoked, destroyed bool
			vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{
				revokeSandboxFn: func(context.Context, string) error {
					revoked = true
					return nil
				},
				destroyFn: func(context.Context, string, bool) error {
					destroyed = true
					return nil
				},
			}}

			(&Handlers{DB: db.New(mock)}).failSavedSnapshotAndSource(context.Background(), saved, vmd, "source_resume_failed")

			if !revocationPersisted || !fallbackAttempted || !revoked {
				t.Fatalf("fallback actions = revocation:%t transition:%t direct-revoke:%t, want all true", revocationPersisted, fallbackAttempted, revoked)
			}
			if destroyed != tt.wantDestroy {
				t.Fatalf("host destroy = %t, want %t", destroyed, tt.wantDestroy)
			}
		})
	}
}

func TestDeleteSavedSnapshotReturnsNoContentForExistingTombstone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	teamID, sourceID, snapshotID := uuid.New(), uuid.New(), uuid.New()
	hostID := "snapshot-host"
	tombstone := db.Snapshot{
		ID: snapshotID, SandboxID: sourceID, TeamID: teamID,
		Kind: db.SnapshotKindSaved, Status: db.SnapshotStatusDeleting, HostID: &hostID,
		DeletedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: GetSavedSnapshotForDelete :one") {
				t.Fatalf("unexpected DB row query: %s", sql)
			}
			return savedSnapshotRow(tombstone)
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			t.Fatalf("unexpected DB exec: %s", sql)
			return pgconn.CommandTag{}, nil
		},
	}
	deleteCalled := false
	vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{}, deleteSavedFn: func(context.Context, string, string) error {
		deleteCalled = true
		return nil
	}}

	w := httptest.NewRecorder()
	savedSnapshotDeleteTestRouter(&Handlers{DB: db.New(mock), VMD: vmd}, teamID).ServeHTTP(w,
		httptest.NewRequest(http.MethodDelete, "/snapshots/"+snapshotID.String(), nil))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if deleteCalled {
		t.Fatal("tombstoned snapshot invoked host cleanup")
	}
}

func TestDeleteSavedSnapshotAdoptsConcurrentDeletingClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)
	teamID, sourceID, snapshotID := uuid.New(), uuid.New(), uuid.New()
	hostID := "snapshot-host"
	ready := db.Snapshot{
		ID: snapshotID, SandboxID: sourceID, TeamID: teamID,
		Kind: db.SnapshotKindSaved, Status: db.SnapshotStatusReady, HostID: &hostID,
	}
	deleting := ready
	deleting.Status = db.SnapshotStatusDeleting
	deleted := deleting
	deleted.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	lookupCalls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSavedSnapshotForDelete :one"):
				lookupCalls++
				if lookupCalls == 1 {
					return savedSnapshotRow(ready)
				}
				return savedSnapshotRow(deleting)
			case strings.Contains(sql, "-- name: ClaimDeleteSavedSnapshotIfLeaf :one"):
				return notFoundRow()
			case strings.Contains(sql, "-- name: FinalizeSavedSnapshotDelete :one"):
				return savedSnapshotRow(deleted)
			default:
				t.Fatalf("unexpected DB row query: %s", sql)
				return notFoundRow()
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			t.Fatalf("unexpected DB exec: %s", sql)
			return pgconn.CommandTag{}, nil
		},
	}
	deleteCalls := 0
	vmd := &stubSavedSnapshotVMD{stubVMD: &stubVMD{}, deleteSavedFn: func(_ context.Context, gotSourceID, gotSnapshotID string) error {
		deleteCalls++
		if gotSourceID != sourceID.String() || gotSnapshotID != snapshotID.String() {
			t.Fatalf("host delete identity = (%s, %s), want (%s, %s)", gotSourceID, gotSnapshotID, sourceID, snapshotID)
		}
		return nil
	}}

	w := httptest.NewRecorder()
	savedSnapshotDeleteTestRouter(&Handlers{DB: db.New(mock), VMD: vmd}, teamID).ServeHTTP(w,
		httptest.NewRequest(http.MethodDelete, "/snapshots/"+snapshotID.String(), nil))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if lookupCalls != 2 || deleteCalls != 1 {
		t.Fatalf("race adoption calls = lookups:%d host-deletes:%d, want 2 and 1", lookupCalls, deleteCalls)
	}
}

func TestCreateSnapshotAdoptsSameKeyWinnerAfterAdmissionNoRows(t *testing.T) {
	gin.SetMode(gin.TestMode)
	teamID, sourceID, snapshotID := uuid.New(), uuid.New(), uuid.New()
	hostID := "snapshot-host"
	idempotencyKey := "same-request"
	vcpu, memoryMiB, diskMiB := int32(2), int32(2048), int32(8192)
	source := db.Sandbox{
		ID: sourceID, TeamID: teamID, Status: db.SandboxStatusActive,
		HostID: hostID, VcpuCount: vcpu, MemoryMib: memoryMiB, DiskMib: diskMiB,
	}
	winnerSource := source
	winnerSource.SnapshotOperationID = pgtype.UUID{Bytes: snapshotID, Valid: true}
	winner := db.Snapshot{
		ID: snapshotID, SandboxID: sourceID, TeamID: teamID,
		Kind: db.SnapshotKindSaved, Status: db.SnapshotStatusCreating,
		IdempotencyKey: &idempotencyKey, HostID: &hostID,
		VcpuCount: &vcpu, MemoryMib: &memoryMiB, DiskMib: &diskMiB,
		SourceStatus: db.NullSandboxStatus{SandboxStatus: db.SandboxStatusActive, Valid: true},
	}
	getSandboxCalls, idempotencyLookups, beginCalls := 0, 0, 0
	quota := int64(1 << 50)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: IsFeatureEnabledForTeam :one"):
				return boolRow(true)
			case strings.Contains(sql, "-- name: GetSandbox :one"):
				getSandboxCalls++
				if getSandboxCalls == 1 {
					return sandboxRow(source)
				}
				return sandboxRow(winnerSource)
			case strings.Contains(sql, "-- name: GetSavedSnapshotByIdempotencyKey :one"):
				idempotencyLookups++
				if idempotencyLookups == 1 {
					return notFoundRow()
				}
				return savedSnapshotRow(winner)
			case strings.Contains(sql, "-- name: GetSavedSnapshotQuotaUsage :one"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = 100
					*dest[1].(*int32) = 100
					*dest[2].(**int64) = &quota
					*dest[3].(*int64) = 0
					*dest[4].(*int64) = 0
					return nil
				}}
			case strings.Contains(sql, "-- name: BeginSavedSnapshot :one"):
				beginCalls++
				return notFoundRow()
			default:
				t.Fatalf("unexpected DB row query: %s", sql)
				return notFoundRow()
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			t.Fatalf("unexpected DB exec: %s", sql)
			return pgconn.CommandTag{}, nil
		},
	}
	var capturedSnapshotID string
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		createSavedFn: func(_ context.Context, gotSourceID, gotSnapshotID string) (vmdclient.SavedSnapshotArtifacts, error) {
			if gotSourceID != sourceID.String() {
				t.Fatalf("capture source = %s, want %s", gotSourceID, sourceID)
			}
			capturedSnapshotID = gotSnapshotID
			return vmdclient.SavedSnapshotArtifacts{}, status.Error(codes.Unavailable, "host retry")
		},
	}
	h := &Handlers{DB: db.New(mock), VMD: vmd}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("team_id", teamID.String())
		c.Next()
	})
	r.POST("/sandboxes/:sandbox_id/snapshots", h.CreateSnapshot)
	req := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sourceID.String()+"/snapshots", strings.NewReader(`{}`))
	req.Header.Set("Idempotency-Key", idempotencyKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 after adopted host retry; body: %s", w.Code, w.Body.String())
	}
	if capturedSnapshotID != snapshotID.String() {
		t.Fatalf("captured snapshot ID = %q, want adopted winner %s", capturedSnapshotID, snapshotID)
	}
	if getSandboxCalls != 2 || idempotencyLookups != 2 || beginCalls != 1 {
		t.Fatalf("admission-race calls = source:%d key:%d begin:%d, want 2/2/1", getSandboxCalls, idempotencyLookups, beginCalls)
	}
}

func savedSnapshotDeleteTestRouter(h *Handlers, teamID uuid.UUID) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("team_id", teamID.String())
		c.Next()
	})
	r.DELETE("/snapshots/:snapshot_id", h.DeleteSavedSnapshot)
	return r
}
