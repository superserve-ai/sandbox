package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

func TestRunWithLockRetrySucceedsAfterHolderReleases(t *testing.T) {
	restoreBackoff := lockedRunBackoff
	lockedRunBackoff = time.Millisecond
	defer func() { lockedRunBackoff = restoreBackoff }()

	calls := 0
	err := runWithLockRetry(context.Background(), uuid.New(), func() error {
		calls++
		if calls < 3 {
			return tenantstore.ErrLocked
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestRunWithLockRetryPassesThroughNonLockedErrors(t *testing.T) {
	wantErr := errors.New("boom")
	calls := 0
	err := runWithLockRetry(context.Background(), uuid.New(), func() error {
		calls++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry on a non-lock error)", calls)
	}
}

// TestRunWithLockRetryGivesUpRetryable is the regression test for the
// finding that a still-locked tenant, once the wait is exhausted, must not
// be treated as done: exiting 0 leaves both this execution's intent and a
// slow-but-genuinely-superseded holder's cleanup unexecuted until the next
// stale reclaim. The fix is to return ErrLocked so Cloud Run retries this
// job execution instead of silently accepting a still-held lock as success.
func TestRunWithLockRetryGivesUpRetryable(t *testing.T) {
	restoreBackoff := lockedRunBackoff
	lockedRunBackoff = time.Millisecond
	defer func() { lockedRunBackoff = restoreBackoff }()

	calls := 0
	err := runWithLockRetry(context.Background(), uuid.New(), func() error {
		calls++
		return tenantstore.ErrLocked
	})
	if !errors.Is(err, tenantstore.ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked (must not be swallowed into a success exit)", err)
	}
	if want := lockedRunRetries + 1; calls != want {
		t.Fatalf("calls = %d, want %d", calls, want)
	}
}

func TestRunWithLockRetryStopsOnContextCancel(t *testing.T) {
	restoreBackoff := lockedRunBackoff
	lockedRunBackoff = time.Hour
	defer func() { lockedRunBackoff = restoreBackoff }()

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- runWithLockRetry(ctx, uuid.New(), func() error {
			calls++
			return tenantstore.ErrLocked
		})
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runWithLockRetry did not return after context cancel")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (cancel during the first backoff wait)", calls)
	}
}
