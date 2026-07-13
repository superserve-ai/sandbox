package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
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
		cancel() // cancel while the interceptor is in its backoff sleep
		return grpcstatus.Error(grpccodes.Unavailable, "connection refused")
	}
	err := retryUnavailableUnaryInterceptor(5*time.Second)(ctx, "m", nil, nil, nil, invoker)
	if grpcstatus.Code(err) != grpccodes.Unavailable {
		t.Fatalf("expected the last Unavailable error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected cancellation to stop after 1 attempt, got %d", calls)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("test setup: ctx should be cancelled")
	}
}
