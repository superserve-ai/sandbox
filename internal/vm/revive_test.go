package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Revive refuses invalid ids, missing disks, live VMs, and healthy
// paused VMs; the boot itself is exercised by the integration
// The map is linked beside the disk on the same filesystem and copied
// across a filesystem boundary.
func TestPlaceBlockMapLinksOrCopies(t *testing.T) {
	src := filepath.Join(t.TempDir(), "vmstate.snap.overlay")
	if err := os.WriteFile(src, []byte("blocks"), 0o600); err != nil {
		t.Fatal(err)
	}
	sameFS := filepath.Join(t.TempDir(), "rootfs.ext4")
	if err := placeBlockMap(src, sameFS); err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(src)
	b, err := os.Stat(sameFS + ".bitmap")
	if err != nil || !os.SameFile(a, b) {
		t.Fatalf("same filesystem: want a link to the map, got %v", err)
	}

	shm, err := os.MkdirTemp("/dev/shm", "block-map-")
	if err != nil {
		t.Skip("no /dev/shm for a second filesystem")
	}
	defer os.RemoveAll(shm)
	otherFS := filepath.Join(shm, "rootfs.ext4")
	if err := placeBlockMap(src, otherFS); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(otherFS + ".bitmap"); err != nil || string(data) != "blocks" {
		t.Fatalf("other filesystem: want a copy of the map, got %q, %v", data, err)
	}
}

// environment since it needs a real Firecracker.
func TestReviveVMGuards(t *testing.T) {
	m := newTestManager()
	m.vms = map[string]*VMInstance{}
	disk := filepath.Join(t.TempDir(), "salvaged.ext4")
	if err := os.WriteFile(disk, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.ReviveVM(context.Background(), "../escape", disk, "", "", false, false, "", "", 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("traversal id: %v, want InvalidArgument", err)
	}
	if _, err := m.ReviveVM(context.Background(), "vm-1", filepath.Join(t.TempDir(), "absent.ext4"), "", "", false, false, "", "", 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing disk: %v, want InvalidArgument", err)
	}

	// A block map must be a real file, and only an overlay has one.
	if _, err := m.ReviveVM(context.Background(), "vm-1", disk, "", filepath.Join(t.TempDir(), "absent.overlay"), false, false, "", "", 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing block map: %v, want InvalidArgument", err)
	}
	blockMap := filepath.Join(t.TempDir(), "vmstate.snap.overlay")
	if err := os.WriteFile(blockMap, []byte("blocks"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReviveVM(context.Background(), "vm-1", disk, "", blockMap, true, false, "", "", 1, 128, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("block map with a standalone disk: %v, want InvalidArgument", err)
	}
	// Like the disk and base, a map inside the run directory would be
	// deleted by revival's own teardown; it is refused before that runs.
	m.cfg.RunDir = t.TempDir()
	m.unitDead = func(context.Context, string) bool { return true } // at rest: a dead zombie
	base := filepath.Join(t.TempDir(), "base.ext4")
	if err := os.WriteFile(base, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	insideRunDir := filepath.Join(m.cfg.RunDir, "vm-1", "vmstate.snap.overlay")
	if err := os.MkdirAll(filepath.Dir(insideRunDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(insideRunDir, []byte("blocks"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReviveVM(context.Background(), "vm-1", disk, base, insideRunDir, false, true, "team", "", 1, 128, nil); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "run directory") {
		t.Fatalf("block map inside the run dir: %v, want InvalidArgument naming the run directory", err)
	}

	// The liveness probe (a recorded-running zombie whose process is
	// gone proceeds; a real live Firecracker refuses) and the boot
	// itself need a real host and are exercised by the staging revive
	// drill, not this unit harness.

	// A paused VM with its snapshot is healthy and refused.
	m.mu.Lock()
	m.vms["vm-paused"] = &VMInstance{ID: "vm-paused", Status: StatusPaused, SnapshotPath: "/snapshots/vm-paused/vmstate.snap"}
	m.mu.Unlock()
	if _, err := m.ReviveVM(context.Background(), "vm-paused", disk, "", "", false, false, "", "", 1, 128, nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("healthy paused: %v, want FailedPrecondition", err)
	}
}
