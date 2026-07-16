package telemetry

import (
	"context"
	"testing"
	"time"
)

type captureRecorder struct {
	vmdCalls []VMDCall
}

func (r *captureRecorder) RecordSandboxTransition(context.Context, SandboxTransition) {}

func (r *captureRecorder) RecordVMDCall(_ context.Context, call VMDCall) {
	r.vmdCalls = append(r.vmdCalls, call)
}

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
