package vm

import (
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestWaitForFlush covers the async-pause flush handshake: idle is a no-op, a
// waiter blocks until the flush ends and then sees its outcome, and once settled
// it's idle again.
func TestWaitForFlush(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	inst := &VMInstance{ID: "vm1"}

	// No flush in progress → returns nil immediately.
	if err := m.waitForFlush(inst); err != nil {
		t.Fatalf("waitForFlush(idle) = %v, want nil", err)
	}

	// Begin a flush; a waiter must block until endFlush, then get its error.
	m.beginFlush(inst)
	want := errors.New("flush boom")
	done := make(chan error, 1)
	go func() { done <- m.waitForFlush(inst) }()

	select {
	case <-done:
		t.Fatal("waitForFlush returned before endFlush")
	case <-time.After(20 * time.Millisecond):
	}

	m.endFlush(inst, want)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("waitForFlush = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForFlush did not unblock after endFlush")
	}

	// Settled → idle again.
	if err := m.waitForFlush(inst); err != nil {
		t.Fatalf("waitForFlush(after) = %v, want nil", err)
	}
}
