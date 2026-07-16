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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type savedSnapshotOutcomeRecorder struct {
	outcomes []telemetry.SavedSnapshotOutcome
}

func (*savedSnapshotOutcomeRecorder) RecordSandboxTransition(context.Context, telemetry.SandboxTransition) {
}
func (*savedSnapshotOutcomeRecorder) RecordVMDCall(context.Context, telemetry.VMDCall) {}
func (r *savedSnapshotOutcomeRecorder) RecordSavedSnapshotOutcome(_ context.Context, outcome telemetry.SavedSnapshotOutcome) {
	r.outcomes = append(r.outcomes, outcome)
}
func (*savedSnapshotOutcomeRecorder) RecordHostCapacity(context.Context, telemetry.HostCapacity) {}
func (*savedSnapshotOutcomeRecorder) RecordDBPoolStats(context.Context, telemetry.DBPoolStats)   {}

func useSavedSnapshotOutcomeRecorder(t *testing.T) *savedSnapshotOutcomeRecorder {
	t.Helper()
	recorder := &savedSnapshotOutcomeRecorder{}
	SetTelemetryRecorder(recorder)
	t.Cleanup(func() { SetTelemetryRecorder(nil) })
	return recorder
}

func TestSnapshotDependencyConflictRecordsBoundedOutcome(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := useSavedSnapshotOutcomeRecorder(t)
	snapshotID, teamID := uuid.New(), uuid.New()
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if !strings.Contains(sql, "-- name: GetSavedSnapshotDependencyCounts :one") {
			t.Fatalf("unexpected row query: %s", sql)
		}
		return &mockRow{scanFn: func(dest ...any) error {
			*dest[0].(*int64) = 2
			*dest[1].(*int64) = 1
			return nil
		}}
	}}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/snapshots/"+snapshotID.String(), nil)
	SetTelemetryHostID(c, "host-a")
	(&Handlers{DB: db.New(mock)}).respondSnapshotDependencyConflict(c, snapshotID, teamID)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if len(recorder.outcomes) != 1 {
		t.Fatalf("outcomes = %+v, want one dependency block", recorder.outcomes)
	}
	got := recorder.outcomes[0]
	if got.Operation != telemetry.SavedSnapshotOperationDelete || got.Outcome != telemetry.SavedSnapshotOutcomeDependencyBlocked || got.HostID != "host-a" {
		t.Fatalf("outcome = %+v", got)
	}
}

func TestMarkSavedSnapshotUnavailableRecordsOnlyCommittedTransition(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := useSavedSnapshotOutcomeRecorder(t)
	hostID := "host-a"
	saved := db.Snapshot{
		ID: uuid.New(), SandboxID: uuid.New(), TeamID: uuid.New(),
		Kind: db.SnapshotKindSaved, Status: db.SnapshotStatusReady, HostID: &hostID,
		Trigger: "api", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	call := 0
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if !strings.Contains(sql, "-- name: MarkSavedSnapshotUnavailable :one") {
			t.Fatalf("unexpected row query: %s", sql)
		}
		call++
		if call == 2 {
			return notFoundRow()
		}
		updated := saved
		updated.Status = db.SnapshotStatusUnavailable
		return savedSnapshotRow(updated)
	}}
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/sandboxes", nil)

	h.markSavedSnapshotUnavailable(c, saved, "artifact_restore_failed")
	h.markSavedSnapshotUnavailable(c, saved, "artifact_restore_failed")

	if len(recorder.outcomes) != 1 {
		t.Fatalf("outcomes = %+v, want only the committed ready->unavailable transition", recorder.outcomes)
	}
	got := recorder.outcomes[0]
	if got.Operation != telemetry.SavedSnapshotOperationRestore || got.Outcome != telemetry.SavedSnapshotOutcomeUnavailable || got.HostID != hostID {
		t.Fatalf("outcome = %+v", got)
	}
}

func TestCapturedSnapshotCleanupRecordsRetryAndSuccess(t *testing.T) {
	recorder := useSavedSnapshotOutcomeRecorder(t)
	hostID := "host-a"
	saved := db.Snapshot{ID: uuid.New(), SandboxID: uuid.New(), HostID: &hostID}
	deleteErr := status.Error(codes.Unavailable, "delete failed")
	vmd := &stubSavedSnapshotVMD{
		stubVMD: &stubVMD{},
		deleteSavedFn: func(context.Context, string, string) error {
			return deleteErr
		},
	}
	h := &Handlers{}

	if err := h.deleteCapturedSnapshotBestEffort(context.Background(), vmd, saved); status.Code(err) != codes.Unavailable {
		t.Fatalf("cleanup error = %v, want %v", err, deleteErr)
	}
	vmd.deleteSavedFn = func(context.Context, string, string) error { return nil }
	if err := h.deleteCapturedSnapshotBestEffort(context.Background(), vmd, saved); err != nil {
		t.Fatalf("cleanup success: %v", err)
	}

	if len(recorder.outcomes) != 2 {
		t.Fatalf("outcomes = %+v, want retry then success", recorder.outcomes)
	}
	if recorder.outcomes[0].Outcome != telemetry.SavedSnapshotOutcomeRetry || recorder.outcomes[1].Outcome != telemetry.SavedSnapshotOutcomeSuccess {
		t.Fatalf("cleanup outcomes = %+v", recorder.outcomes)
	}
	for _, outcome := range recorder.outcomes {
		if outcome.Operation != telemetry.SavedSnapshotOperationCleanup || outcome.HostID != hostID {
			t.Fatalf("cleanup outcome dimensions = %+v", outcome)
		}
	}
}
