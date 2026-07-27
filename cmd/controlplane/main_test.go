package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/preview"
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

func TestPreviewPortsToProtoCarriesTokenVersion(t *testing.T) {
	ports := previewPortsToProto(map[int32]vmdclient.PortPolicy{
		3000: {Access: preview.AccessPrivateTokenV1, TokenVersion: 17},
	})
	if len(ports) != 1 || ports[0].GetPort() != 3000 ||
		ports[0].GetAccess() != preview.AccessPrivateTokenV1 || ports[0].GetTokenVersion() != 17 {
		t.Fatalf("preview proto = %#v, want port/access/token version", ports)
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
	opens   int
	opensFn func(call int) (vmdpb.VMDaemon_StreamBuildLogsClient, error)
}

func (f *fakeVMDClient) StreamBuildLogs(ctx context.Context, req *vmdpb.StreamBuildLogsRequest, opts ...grpc.CallOption) (vmdpb.VMDaemon_StreamBuildLogsClient, error) {
	f.opens++
	return f.opensFn(f.opens)
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
