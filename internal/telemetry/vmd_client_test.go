package telemetry

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type captureRecorder struct {
	vmdCalls []VMDCall
}

func (r *captureRecorder) RecordSandboxTransition(context.Context, SandboxTransition) {}

func (r *captureRecorder) RecordVMDCall(_ context.Context, call VMDCall) {
	r.vmdCalls = append(r.vmdCalls, call)
}

func (r *captureRecorder) RecordSavedSnapshotOutcome(context.Context, SavedSnapshotOutcome) {}

func (r *captureRecorder) RecordHostCapacity(context.Context, HostCapacity) {}

func (r *captureRecorder) RecordDBPoolStats(context.Context, DBPoolStats) {}

func TestInstrumentedVMDClientRecordsHostID(t *testing.T) {
	recorder := &captureRecorder{}

	client := &instrumentedVMDClient{
		recorder: recorder,
		region:   "us-central1",
		hostID:   "host-123",
	}

	client.record(
		context.Background(),
		"BuildTemplate",
		time.Now().Add(-time.Second),
		nil,
	)

	if len(recorder.vmdCalls) != 1 {
		t.Fatalf("recorded %d VMD calls, want 1", len(recorder.vmdCalls))
	}

	got := recorder.vmdCalls[0]

	if got.HostID != "host-123" {
		t.Errorf("HostID = %q, want %q", got.HostID, "host-123")
	}

	if got.Region != "us-central1" {
		t.Errorf("Region = %q, want %q", got.Region, "us-central1")
	}

	if got.Method != "BuildTemplate" {
		t.Errorf("Method = %q, want %q", got.Method, "BuildTemplate")
	}

	if got.Result != ResultSuccess {
		t.Errorf("Result = %q, want %q", got.Result, ResultSuccess)
	}

	if got.Duration <= 0 {
		t.Errorf("Duration = %s, want positive duration", got.Duration)
	}
}

type capabilityClientStub struct {
	vmdclient.Client
	checkCalls       int
	checkErr         error
	measureCalls     int
	measureLogical   int64
	measureExclusive int64
	measureErr       error
}

func (s *capabilityClientStub) CheckSavedSnapshotSupport(context.Context) error {
	s.checkCalls++
	return s.checkErr
}

func (*capabilityClientStub) CreateSavedSnapshot(context.Context, string, string) (vmdclient.SavedSnapshotArtifacts, error) {
	return vmdclient.SavedSnapshotArtifacts{}, nil
}

func (*capabilityClientStub) RestoreSavedSnapshot(context.Context, string, string, string, string, string, vmdclient.SavedSnapshotNetwork, []string, string, map[int32]vmdclient.PortPolicy, int64) (string, uint32, uint32, error) {
	return "", 0, 0, nil
}

func (*capabilityClientStub) DeleteSavedSnapshot(context.Context, string, string) error {
	return nil
}

func (s *capabilityClientStub) MeasureSandboxWritableLayer(context.Context, string) (int64, int64, error) {
	s.measureCalls++
	return s.measureLogical, s.measureExclusive, s.measureErr
}

func TestInstrumentedVMDClientForwardsWritableLayerUsage(t *testing.T) {
	stub := &capabilityClientStub{measureLogical: 8192, measureExclusive: 4096}
	wrapped := WrapVMDClient(stub, NewNoopRecorder(), "test", "host-a")
	saved, ok := wrapped.(vmdclient.SavedSnapshotClient)
	if !ok {
		t.Fatal("instrumented client does not expose saved snapshot extension")
	}
	logical, exclusive, err := saved.MeasureSandboxWritableLayer(context.Background(), "sandbox-a")
	if err != nil {
		t.Fatalf("measure writable layer: %v", err)
	}
	if logical != 8192 || exclusive != 4096 || stub.measureCalls != 1 {
		t.Fatalf("writable layer result = (%d, %d), calls=%d", logical, exclusive, stub.measureCalls)
	}
}

func TestInstrumentedVMDClientForwardsSavedSnapshotCapabilityCheck(t *testing.T) {
	stub := &capabilityClientStub{checkErr: status.Error(codes.Unimplemented, "old VMD")}
	wrapped := WrapVMDClient(stub, NewNoopRecorder(), "test", "host-a")
	saved, ok := wrapped.(vmdclient.SavedSnapshotClient)
	if !ok {
		t.Fatal("instrumented client does not expose saved snapshot extension")
	}
	err := saved.CheckSavedSnapshotSupport(context.Background())
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("capability error code = %s, want Unimplemented: %v", status.Code(err), err)
	}
	if stub.checkCalls != 1 {
		t.Fatalf("capability checks = %d, want 1", stub.checkCalls)
	}
}
