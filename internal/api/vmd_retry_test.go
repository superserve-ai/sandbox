package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRetryBootOnDeadline(t *testing.T) {
	grpcDeadline := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	// The dial-site interceptor's expired-window shape: a wrapped plain
	// context error, which status.Code reads as Unknown.
	wrappedCtxDeadline := fmt.Errorf("%w (last attempt: %v)", context.DeadlineExceeded, grpcDeadline)
	other := errors.New("boom")

	boot := func(results []error, calls *int) func(context.Context) (string, uint32, uint32, error) {
		return func(context.Context) (string, uint32, uint32, error) {
			err := results[*calls]
			*calls++
			if err != nil {
				return "", 0, 0, err
			}
			return "10.0.0.9", 2, 512, nil
		}
	}

	t.Run("success first try", func(t *testing.T) {
		calls := 0
		ip, vcpu, mem, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{nil}, &calls))
		if err != nil || retried || calls != 1 || ip != "10.0.0.9" || vcpu != 2 || mem != 512 {
			t.Fatalf("got ip=%q vcpu=%d mem=%d retried=%v err=%v calls=%d", ip, vcpu, mem, retried, err, calls)
		}
	})

	t.Run("non-deadline error is not retried", func(t *testing.T) {
		calls := 0
		_, _, _, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{other}, &calls))
		if !errors.Is(err, other) || retried || calls != 1 {
			t.Fatalf("err=%v retried=%v calls=%d, want boom/false/1", err, retried, calls)
		}
	})

	t.Run("grpc deadline retried once then succeeds with attempt-2 outputs", func(t *testing.T) {
		calls := 0
		ip, _, _, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{grpcDeadline, nil}, &calls))
		if err != nil || !retried || calls != 2 || ip != "10.0.0.9" {
			t.Fatalf("got ip=%q retried=%v err=%v calls=%d", ip, retried, err, calls)
		}
	})

	t.Run("wrapped context deadline from the interceptor is retried", func(t *testing.T) {
		calls := 0
		_, _, _, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{wrappedCtxDeadline, nil}, &calls))
		if err != nil || !retried || calls != 2 {
			t.Fatalf("err=%v retried=%v calls=%d, want nil/true/2", err, retried, calls)
		}
	})

	t.Run("unavailable that outlived the interceptor window is retried", func(t *testing.T) {
		calls := 0
		_, _, _, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{status.Error(codes.Unavailable, "connection refused"), nil}, &calls))
		if err != nil || !retried || calls != 2 {
			t.Fatalf("err=%v retried=%v calls=%d, want nil/true/2", err, retried, calls)
		}
	})

	t.Run("deadline twice returns the second error", func(t *testing.T) {
		calls := 0
		_, _, _, retried, err := retryTransientBoot(context.Background(), "sb", boot([]error{grpcDeadline, grpcDeadline}, &calls))
		if !isVMDDeadline(err) || !retried || calls != 2 {
			t.Fatalf("err=%v retried=%v calls=%d, want deadline/true/2", err, retried, calls)
		}
	})

	t.Run("dead caller skips the retry", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		_, _, _, retried, err := retryTransientBoot(parent, "sb", boot([]error{grpcDeadline, nil}, &calls))
		if !isVMDDeadline(err) || retried || calls != 1 {
			t.Fatalf("err=%v retried=%v calls=%d, want deadline/false/1", err, retried, calls)
		}
	})
}

func TestIsVMDDeadline(t *testing.T) {
	if !isVMDDeadline(status.Error(codes.DeadlineExceeded, "x")) {
		t.Error("grpc deadline status should classify")
	}
	if !isVMDDeadline(fmt.Errorf("wrap: %w", context.DeadlineExceeded)) {
		t.Error("wrapped context deadline should classify")
	}
	if isVMDDeadline(nil) || isVMDDeadline(errors.New("boom")) ||
		isVMDDeadline(status.Error(codes.Unavailable, "x")) || isVMDDeadline(context.Canceled) {
		t.Error("nil, plain, Unavailable, and Canceled must not classify")
	}
}
