package vmruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/superserve-ai/sandbox/internal/hostlease"
)

// Keep the socket path short (unix sun_path is ~104-108 bytes) and outside the
// long macOS TempDir.
func shortSock(t *testing.T) string {
	t.Helper()
	p := filepath.Join("/tmp", fmt.Sprintf("vmr-%d.sock", os.Getpid()))
	t.Cleanup(func() { os.Remove(p) })
	return p
}

func TestPreflightValidatesRequiredFiles(t *testing.T) {
	if _, err := Preflight(Config{
		SocketPath:    shortSock(t),
		RequiredFiles: []string{filepath.Join(t.TempDir(), "does-not-exist")},
	}); err == nil {
		t.Fatal("Preflight accepted a missing required file")
	}
}

func TestActivateRequiresCapability(t *testing.T) {
	present := filepath.Join(t.TempDir(), "kernel")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pre, err := Preflight(Config{SocketPath: shortSock(t), RequiredFiles: []string{present}})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	// No capability → refused. The preflight owns nothing, so this is safe.
	if _, err := Activate(pre, nil); err != ErrNoCapability {
		t.Fatalf("Activate(nil cap) = %v, want ErrNoCapability", err)
	}

	// With a real lease capability → activates.
	_, cap, err := hostlease.Acquire(filepath.Join(t.TempDir(), "writer.lock"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	act, err := Activate(pre, cap)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// Teardown runs in reverse registration order, exactly once.
	var order []string
	act.AddCloser("stores", func() error { order = append(order, "stores"); return nil })
	act.AddCloser("producers", func() error { order = append(order, "producers"); return nil })
	if err := act.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := act.Close(); err != nil {
		t.Fatalf("second Close not idempotent: %v", err)
	}
	if len(order) != 2 || order[0] != "producers" || order[1] != "stores" {
		t.Fatalf("teardown order = %v, want [producers stores]", order)
	}
}
