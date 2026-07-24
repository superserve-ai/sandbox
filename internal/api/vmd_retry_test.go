package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRetryBootOnDeadline(t *testing.T) {
	deadline := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	other := errors.New("boom")

	t.Run("success first try", func(t *testing.T) {
		calls := 0
		err := retryBootOnDeadline(context.Background(), "sb", func(context.Context) error {
			calls++
			return nil
		})
		if err != nil || calls != 1 {
			t.Fatalf("err=%v calls=%d, want nil/1", err, calls)
		}
	})

	t.Run("non-deadline error is not retried", func(t *testing.T) {
		calls := 0
		err := retryBootOnDeadline(context.Background(), "sb", func(context.Context) error {
			calls++
			return other
		})
		if !errors.Is(err, other) || calls != 1 {
			t.Fatalf("err=%v calls=%d, want boom/1", err, calls)
		}
	})

	t.Run("deadline retried once then succeeds", func(t *testing.T) {
		calls := 0
		err := retryBootOnDeadline(context.Background(), "sb", func(context.Context) error {
			calls++
			if calls == 1 {
				return deadline
			}
			return nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("err=%v calls=%d, want nil/2", err, calls)
		}
	})

	t.Run("deadline twice returns the second error", func(t *testing.T) {
		calls := 0
		err := retryBootOnDeadline(context.Background(), "sb", func(context.Context) error {
			calls++
			return deadline
		})
		if !isVMDDeadline(err) || calls != 2 {
			t.Fatalf("err=%v calls=%d, want deadline/2", err, calls)
		}
	})

	t.Run("dead request skips the retry", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		err := retryBootOnDeadline(parent, "sb", func(context.Context) error {
			calls++
			return deadline
		})
		if !isVMDDeadline(err) || calls != 1 {
			t.Fatalf("err=%v calls=%d, want deadline/1", err, calls)
		}
	})
}
