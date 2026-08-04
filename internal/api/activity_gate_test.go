package api

import (
	"context"
	"testing"
	"time"
)

func TestActivityGateBoundsConcurrency(t *testing.T) {
	h := &Handlers{}
	ctx := context.Background()

	for i := 0; i < activityWriteConcurrency; i++ {
		if !h.acquireActivityGate(ctx) {
			t.Fatalf("acquire %d should succeed immediately", i+1)
		}
	}

	// With all permits held, the next acquire must wait — and give up at the
	// caller's deadline rather than blocking forever.
	deadlineCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if h.acquireActivityGate(deadlineCtx) {
		t.Fatal("acquire past the cap should fail once the deadline expires")
	}

	// Releasing a permit unblocks the next waiter.
	h.releaseActivityGate()
	if !h.acquireActivityGate(ctx) {
		t.Fatal("acquire should succeed after a release")
	}
}
