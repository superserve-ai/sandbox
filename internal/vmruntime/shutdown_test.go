package vmruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/hostlease"
)

func newTestActive(t *testing.T) *ActiveRuntime {
	t.Helper()
	sock := filepath.Join("/tmp", fmt.Sprintf("vmr-sd-%d.sock", os.Getpid()))
	t.Cleanup(func() { os.Remove(sock) })
	pre, err := Preflight(Config{SocketPath: sock})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	_, cap, err := hostlease.Acquire(filepath.Join(t.TempDir(), "writer.lock"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	act, err := Activate(pre, cap)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return act
}

func TestShutdownDrainsRejectsAndBoundsClosers(t *testing.T) {
	act := newTestActive(t)

	// Admitted before drain.
	done, ok := act.TrackRPC()
	if !ok {
		t.Fatal("TrackRPC must admit before drain")
	}

	var mu sync.Mutex
	var ran []string
	act.AddCloser("fast", func() error {
		mu.Lock()
		ran = append(ran, "fast")
		mu.Unlock()
		return nil
	})
	act.AddCloser("hung", func() error { time.Sleep(2 * time.Second); return nil })

	// The still-open RPC (done not yet called) must overrun the drain grace,
	// and the hung closer must overrun its per-step budget; fast must not.
	overran := act.Shutdown(50*time.Millisecond, 100*time.Millisecond)
	done()

	if !contains(overran, "in-flight-rpcs") {
		t.Errorf("expected in-flight-rpcs to overrun, got %v", overran)
	}
	if !contains(overran, "hung") {
		t.Errorf("expected hung closer to overrun, got %v", overran)
	}
	if contains(overran, "fast") {
		t.Errorf("fast closer should not overrun, got %v", overran)
	}
	mu.Lock()
	if len(ran) != 1 || ran[0] != "fast" {
		t.Errorf("fast closer should have run, ran=%v", ran)
	}
	mu.Unlock()

	// After drain, new RPCs are refused.
	if _, ok := act.TrackRPC(); ok {
		t.Error("TrackRPC must refuse after drain")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
