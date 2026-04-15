package telemetry

import (
	"context"
	"testing"
)

// TestNewNoOpWhenEndpointUnset is the contract the rest of the codebase
// relies on: when OTEL_EXPORTER_OTLP_ENDPOINT is not set the constructor
// must succeed and Shutdown must be a no-op. Local dev and CI depend on
// this so they incur zero telemetry overhead.
func TestNewNoOpWhenEndpointUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	c, err := New(context.Background(), "test", "v0", "node-1")
	if err != nil {
		t.Fatalf("New returned error with endpoint unset: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
	if c.Enabled() {
		t.Error("Client.Enabled() should be false when endpoint unset")
	}
	if err := c.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on no-op client returned error: %v", err)
	}
}

func TestShutdownNilClient(t *testing.T) {
	var c *Client
	if err := c.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on nil client returned error: %v", err)
	}
}
