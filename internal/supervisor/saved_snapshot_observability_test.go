package supervisor

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type supervisorSnapshotOutcomeRecorder struct {
	outcomes []telemetry.SavedSnapshotOutcome
}

func (*supervisorSnapshotOutcomeRecorder) RecordSandboxTransition(context.Context, telemetry.SandboxTransition) {
}
func (*supervisorSnapshotOutcomeRecorder) RecordVMDCall(context.Context, telemetry.VMDCall) {}
func (r *supervisorSnapshotOutcomeRecorder) RecordSavedSnapshotOutcome(_ context.Context, outcome telemetry.SavedSnapshotOutcome) {
	r.outcomes = append(r.outcomes, outcome)
}
func (*supervisorSnapshotOutcomeRecorder) RecordHostCapacity(context.Context, telemetry.HostCapacity) {
}
func (*supervisorSnapshotOutcomeRecorder) RecordDBPoolStats(context.Context, telemetry.DBPoolStats) {}

func TestSavedSnapshotSupervisorRecordsCleanupRetry(t *testing.T) {
	row := savedSnapshotFixture()
	row.Status = db.SnapshotStatusDeleting
	store := &fakeSavedSnapshotStore{deleting: []db.Snapshot{row}}
	client := &fakeSavedSnapshotClient{deleteErr: status.Error(codes.Unavailable, "host restarting")}
	recorder := &supervisorSnapshotOutcomeRecorder{}
	var hosts []string
	s := testSavedSnapshotSupervisor(store, client, &hosts).WithTelemetry(recorder)

	s.tick(context.Background())

	if len(recorder.outcomes) != 1 {
		t.Fatalf("outcomes = %+v, want one cleanup retry", recorder.outcomes)
	}
	got := recorder.outcomes[0]
	if got.Operation != telemetry.SavedSnapshotOperationCleanup || got.Outcome != telemetry.SavedSnapshotOutcomeRetry || got.HostID != "host-a" {
		t.Fatalf("cleanup retry = %+v", got)
	}
}

func TestSavedSnapshotSupervisorRecordsCorruptionAndQueuedCleanup(t *testing.T) {
	row := savedSnapshotFixture()
	store := &fakeSavedSnapshotStore{creating: []db.Snapshot{row}}
	artifacts := savedSnapshotArtifactsFixture()
	artifacts.SchemaVersion = 0
	client := &fakeSavedSnapshotClient{
		createArtifacts: artifacts,
		deleteErr:       status.Error(codes.Unavailable, "host cleanup unavailable"),
	}
	recorder := &supervisorSnapshotOutcomeRecorder{}
	var hosts []string
	s := testSavedSnapshotSupervisor(store, client, &hosts).WithTelemetry(recorder)

	s.tick(context.Background())

	want := []string{
		telemetry.SavedSnapshotOutcomeArtifactCorrupt,
		telemetry.SavedSnapshotOutcomeRetry,
		telemetry.SavedSnapshotOutcomeQueued,
	}
	if len(recorder.outcomes) != len(want) {
		t.Fatalf("outcomes = %+v, want %v", recorder.outcomes, want)
	}
	for i, outcome := range recorder.outcomes {
		if outcome.Outcome != want[i] || outcome.HostID != "host-a" {
			t.Fatalf("outcome[%d] = %+v, want outcome=%s host=host-a", i, outcome, want[i])
		}
	}
	if recorder.outcomes[0].Operation != telemetry.SavedSnapshotOperationCapture {
		t.Fatalf("corruption operation = %q, want capture", recorder.outcomes[0].Operation)
	}
	for _, outcome := range recorder.outcomes[1:] {
		if outcome.Operation != telemetry.SavedSnapshotOperationCleanup {
			t.Fatalf("cleanup operation = %q", outcome.Operation)
		}
	}
}
