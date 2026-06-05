package analytics

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDistinctID(t *testing.T) {
	tests := []struct {
		name, actor, team, want string
	}{
		{"actor known -> person", "user-123", "team-9", "user-123"},
		{"no actor -> team-scoped", "", "team-9", "team:team-9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := distinctID(tc.actor, tc.team); got != tc.want {
				t.Errorf("distinctID(%q,%q) = %q, want %q", tc.actor, tc.team, got, tc.want)
			}
		})
	}
}

func TestCaptureNoopWhenUnconfigured(t *testing.T) {
	c, err := New("", "", zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Must not panic or error when PostHog is unconfigured.
	c.Capture("user-1", "team-1", "sandbox_created", map[string]any{"id": "abc"})
	c.Close()

	// A nil receiver is also a safe no-op.
	var nilClient *Client
	nilClient.Capture("u", "t", "evt", nil)
}

func TestCaptureNonBlockingAndCloseBounded(t *testing.T) {
	// Bogus endpoint exercises the worker + bounded Close path without network.
	c, err := New("phc_test", "http://127.0.0.1:1", zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			c.Capture("user-1", "team-1", "command_run", map[string]any{"i": i})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Capture blocked under load (buffer drop not working)")
	}

	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within bound")
	}
}
