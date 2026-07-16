package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

func TestRetryUnavailableRetriesUntilSuccess(t *testing.T) {
	calls := 0
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		if calls < 3 {
			return grpcstatus.Error(grpccodes.Unavailable, "connection refused")
		}
		return nil
	}
	err := retryUnavailableUnaryInterceptor(5*time.Second)(context.Background(), "m", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryUnavailableDoesNotRetryOtherCodes(t *testing.T) {
	calls := 0
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return grpcstatus.Error(grpccodes.NotFound, "no such vm")
	}
	err := retryUnavailableUnaryInterceptor(5*time.Second)(context.Background(), "m", nil, nil, nil, invoker)
	if grpcstatus.Code(err) != grpccodes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt, got %d", calls)
	}
}

func TestRetryUnavailableStopsAtWindow(t *testing.T) {
	calls := 0
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		return grpcstatus.Error(grpccodes.Unavailable, "connection refused")
	}
	start := time.Now()
	err := retryUnavailableUnaryInterceptor(600*time.Millisecond)(context.Background(), "m", nil, nil, nil, invoker)
	if grpcstatus.Code(err) != grpccodes.Unavailable {
		t.Fatalf("expected Unavailable after window, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 attempts inside the window, got %d", calls)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("retry loop ran %v, expected to stop shortly after the 600ms window", elapsed)
	}
}

func TestRetryUnavailableStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		calls++
		cancel() // ctx is already cancelled when the backoff select runs
		return grpcstatus.Error(grpccodes.Unavailable, "connection refused")
	}
	err := retryUnavailableUnaryInterceptor(5*time.Second)(ctx, "m", nil, nil, nil, invoker)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected ctx.Err(), got %v", err)
	}
	if grpcstatus.Code(err) == grpccodes.Unavailable {
		t.Fatalf("a cancelled caller must not surface Unavailable (dead-host signal), got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected cancellation to stop after 1 attempt, got %d", calls)
	}
}

// fakeVMDClient stubs only StreamBuildLogs; other methods panic via the
// embedded nil interface.
type fakeVMDClient struct {
	vmdpb.VMDaemonClient
	opens            int
	opensFn          func(call int) (vmdpb.VMDaemon_StreamBuildLogsClient, error)
	capabilitiesFn   func() (*vmdpb.GetCapabilitiesResponse, error)
	createSnapshotFn func() (*vmdpb.CreateSnapshotResponse, error)
}

func (f *fakeVMDClient) GetCapabilities(context.Context, *vmdpb.GetCapabilitiesRequest, ...grpc.CallOption) (*vmdpb.GetCapabilitiesResponse, error) {
	return f.capabilitiesFn()
}

func (f *fakeVMDClient) CreateSnapshot(context.Context, *vmdpb.CreateSnapshotRequest, ...grpc.CallOption) (*vmdpb.CreateSnapshotResponse, error) {
	return f.createSnapshotFn()
}

func (f *fakeVMDClient) StreamBuildLogs(ctx context.Context, req *vmdpb.StreamBuildLogsRequest, opts ...grpc.CallOption) (vmdpb.VMDaemon_StreamBuildLogsClient, error) {
	f.opens++
	return f.opensFn(f.opens)
}

func TestGRPCVMDClientSavedSnapshotCapabilityFailsClosedOnOldVMD(t *testing.T) {
	fake := &fakeVMDClient{capabilitiesFn: func() (*vmdpb.GetCapabilitiesResponse, error) {
		return nil, grpcstatus.Error(grpccodes.Unimplemented, "unknown method GetCapabilities")
	}}
	err := (&grpcVMDClient{client: fake}).CheckSavedSnapshotSupport(context.Background())
	if grpcstatus.Code(err) != grpccodes.Unimplemented {
		t.Fatalf("capability error code = %s, want Unimplemented: %v", grpcstatus.Code(err), err)
	}
}

func TestGRPCVMDClientSavedSnapshotCapabilityRequiresAdvertisement(t *testing.T) {
	fake := &fakeVMDClient{capabilitiesFn: func() (*vmdpb.GetCapabilitiesResponse, error) {
		return &vmdpb.GetCapabilitiesResponse{}, nil
	}}
	err := (&grpcVMDClient{client: fake}).CheckSavedSnapshotSupport(context.Background())
	if grpcstatus.Code(err) != grpccodes.Unimplemented {
		t.Fatalf("capability error code = %s, want Unimplemented: %v", grpcstatus.Code(err), err)
	}
}

func TestGRPCVMDClientMissingSavedSnapshotArtifactsAreRetryable(t *testing.T) {
	fake := &fakeVMDClient{createSnapshotFn: func() (*vmdpb.CreateSnapshotResponse, error) {
		return &vmdpb.CreateSnapshotResponse{}, nil
	}}
	_, err := (&grpcVMDClient{client: fake}).CreateSavedSnapshot(context.Background(), "source", "snapshot")
	if grpcstatus.Code(err) != grpccodes.Unavailable {
		t.Fatalf("missing artifact error code = %s, want Unavailable: %v", grpcstatus.Code(err), err)
	}
}

func TestGRPCVMDClientSanitizesSavedSnapshotErrorsFromOlderVMD(t *testing.T) {
	const hostPath = "/var/lib/superserve/private/snapshots/source/snapshot/manifest.json"
	st, err := grpcstatus.New(grpccodes.DataLoss, "read "+hostPath+": input/output error").WithDetails(&errdetails.ErrorInfo{
		Reason: vmdclient.SavedSnapshotSourceResumeFailureReason,
		Domain: "vmd.superserve.ai",
		Metadata: map[string]string{
			"artifact_path": hostPath,
		},
	})
	if err != nil {
		t.Fatalf("attach VMD error details: %v", err)
	}
	fake := &fakeVMDClient{createSnapshotFn: func() (*vmdpb.CreateSnapshotResponse, error) {
		return nil, st.Err()
	}}

	_, err = (&grpcVMDClient{client: fake}).CreateSavedSnapshot(context.Background(), "source", "snapshot")
	if grpcstatus.Code(err) != grpccodes.DataLoss {
		t.Fatalf("code = %s, want DataLoss (%v)", grpcstatus.Code(err), err)
	}
	if !vmdclient.GRPCErrorHasReason(err, vmdclient.SavedSnapshotSourceResumeFailureReason) {
		t.Fatalf("stable error reason was not preserved: %v", err)
	}
	if strings.Contains(err.Error(), hostPath) || strings.Contains(err.Error(), "artifact_path") {
		t.Fatalf("control-plane boundary exposed host artifact path: %v", err)
	}
}

func TestGRPCVMDClientRejectsInvalidSavedSnapshotMetadata(t *testing.T) {
	validResponse := func() *vmdpb.CreateSnapshotResponse {
		return &vmdpb.CreateSnapshotResponse{
			Artifacts: &vmdpb.SavedSnapshotArtifacts{
				SchemaVersion:  1,
				ManifestPath:   "/snapshots/saved/manifest.json",
				ManifestDigest: strings.Repeat("a", 64),
				SnapshotPath:   "/snapshots/saved/vmstate.snap",
				MemFilePath:    "/snapshots/saved/mem.snap",
				DiskFullPath:   "/snapshots/saved/rootfs.ext4",
			},
			ResourceLimits: &vmdpb.ResourceLimits{VcpuCount: 2, MemoryMib: 2048, DiskSizeMib: 8192},
			SourceState:    "running",
		}
	}

	tests := []struct {
		name   string
		mutate func(*vmdpb.CreateSnapshotResponse)
	}{
		{name: "logical", mutate: func(resp *vmdpb.CreateSnapshotResponse) { resp.LogicalSizeBytes = -1 }},
		{name: "exclusive", mutate: func(resp *vmdpb.CreateSnapshotResponse) { resp.ExclusiveSizeBytes = -1 }},
		{name: "source logical", mutate: func(resp *vmdpb.CreateSnapshotResponse) { resp.SourceLogicalSizeBytes = -1 }},
		{name: "source exclusive", mutate: func(resp *vmdpb.CreateSnapshotResponse) { resp.SourceExclusiveSizeBytes = -1 }},
		{name: "uppercase manifest digest", mutate: func(resp *vmdpb.CreateSnapshotResponse) {
			resp.Artifacts.ManifestDigest = strings.Repeat("A", 64)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validResponse()
			tt.mutate(resp)
			fake := &fakeVMDClient{createSnapshotFn: func() (*vmdpb.CreateSnapshotResponse, error) {
				return resp, nil
			}}
			_, err := (&grpcVMDClient{client: fake}).CreateSavedSnapshot(context.Background(), "source", "snapshot")
			if grpcstatus.Code(err) != grpccodes.Unavailable {
				t.Fatalf("invalid metadata error code = %s, want Unavailable: %v", grpcstatus.Code(err), err)
			}
		})
	}
}

// fakeLogStream serves the given events, then errAfter (or io.EOF).
type fakeLogStream struct {
	grpc.ClientStream
	events   []*vmdpb.BuildLogEvent
	errAfter error
	i        int
}

func (s *fakeLogStream) Recv() (*vmdpb.BuildLogEvent, error) {
	if s.i < len(s.events) {
		s.i++
		return s.events[s.i-1], nil
	}
	if s.errAfter != nil {
		return nil, s.errAfter
	}
	return nil, io.EOF
}

func TestStreamBuildLogs_RetriesOpenUntilSuccess(t *testing.T) {
	fake := &fakeVMDClient{opensFn: func(call int) (vmdpb.VMDaemon_StreamBuildLogsClient, error) {
		if call < 3 {
			return nil, grpcstatus.Error(grpccodes.Unavailable, "connection refused")
		}
		return &fakeLogStream{events: []*vmdpb.BuildLogEvent{{Text: "hi", Finished: true, Status: "ready"}}}, nil
	}}
	c := &grpcVMDClient{client: fake}

	var got []vmdclient.BuildLogEvent
	err := c.StreamBuildLogs(context.Background(), "b-1", func(ev vmdclient.BuildLogEvent) error {
		got = append(got, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after open retries, got %v", err)
	}
	if fake.opens != 3 {
		t.Fatalf("expected 3 opens, got %d", fake.opens)
	}
	if len(got) != 1 || got[0].Text != "hi" || !got[0].Finished {
		t.Fatalf("unexpected events: %+v", got)
	}
}

func TestStreamBuildLogs_NoRetryAfterDelivery(t *testing.T) {
	fake := &fakeVMDClient{opensFn: func(call int) (vmdpb.VMDaemon_StreamBuildLogsClient, error) {
		return &fakeLogStream{
			events:   []*vmdpb.BuildLogEvent{{Text: "partial"}},
			errAfter: grpcstatus.Error(grpccodes.Unavailable, "transport is closing"),
		}, nil
	}}
	c := &grpcVMDClient{client: fake}

	delivered := 0
	err := c.StreamBuildLogs(context.Background(), "b-1", func(ev vmdclient.BuildLogEvent) error {
		delivered++
		return nil
	})
	if err == nil {
		t.Fatal("expected the mid-stream error to surface")
	}
	if fake.opens != 1 {
		t.Fatalf("a stream that delivered events must not be retried (would replay history), got %d opens", fake.opens)
	}
	if delivered != 1 {
		t.Fatalf("expected 1 delivered event, got %d", delivered)
	}
}

func TestStreamBuildLogs_NoRetryOnOtherCodes(t *testing.T) {
	fake := &fakeVMDClient{opensFn: func(call int) (vmdpb.VMDaemon_StreamBuildLogsClient, error) {
		return nil, grpcstatus.Error(grpccodes.NotFound, "no such build")
	}}
	c := &grpcVMDClient{client: fake}

	err := c.StreamBuildLogs(context.Background(), "b-1", func(vmdclient.BuildLogEvent) error { return nil })
	if grpcstatus.Code(err) != grpccodes.NotFound {
		t.Fatalf("expected NotFound to surface unretried, got %v", err)
	}
	if fake.opens != 1 {
		t.Fatalf("expected 1 open, got %d", fake.opens)
	}
}
