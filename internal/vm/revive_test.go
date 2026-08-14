package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Revive refuses invalid ids, missing disks, live VMs, and healthy
// paused VMs; the boot itself is exercised by the integration
// environment since it needs a real Firecracker.
func TestReviveVMGuards(t *testing.T) {
	m := newTestManager()
	m.vms = map[string]*VMInstance{}
	disk := filepath.Join(t.TempDir(), "salvaged.ext4")
	if err := os.WriteFile(disk, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.ReviveVM(context.Background(), "../escape", disk, 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("traversal id: %v, want InvalidArgument", err)
	}
	if _, err := m.ReviveVM(context.Background(), "vm-1", filepath.Join(t.TempDir(), "absent.ext4"), 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing disk: %v, want InvalidArgument", err)
	}

	// The liveness probe (a recorded-running zombie whose process is
	// gone proceeds; a real live Firecracker refuses) and the boot
	// itself need a real host and are exercised by the staging revive
	// drill, not this unit harness.

	// A paused VM with its snapshot is healthy and refused.
	m.mu.Lock()
	m.vms["vm-paused"] = &VMInstance{ID: "vm-paused", Status: StatusPaused, SnapshotPath: "/snapshots/vm-paused/vmstate.snap"}
	m.mu.Unlock()
	if _, err := m.ReviveVM(context.Background(), "vm-paused", disk, 1, 128, nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("healthy paused: %v, want FailedPrecondition", err)
	}
}
