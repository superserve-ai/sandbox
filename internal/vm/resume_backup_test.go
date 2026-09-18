package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

func touch(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPausedDiskPath(t *testing.T) {
	if got := pausedDiskPath("/run", "vm-1", "/rec/disk.ext4", "", ""); got != "/rec/disk.ext4" {
		t.Fatalf("recorded disk wins, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "", ""); got != "/run/vm-1/rootfs.ext4" {
		t.Fatalf("plain rootfs, got %s", got)
	}
	if got := pausedDiskPath("/run", "vm-1", "", "rd-9", "/tpl/base.ext4"); got != "/run/rd-9/overlay.ext4" {
		t.Fatalf("overlay under the run dir id, got %s", got)
	}
}

func TestPauseArtifactsMissing(t *testing.T) {
	dir := t.TempDir()
	snap := touch(t, filepath.Join(dir, "snap", "vmstate.snap"))
	mem := touch(t, filepath.Join(dir, "snap", "mem.snap"))
	touch(t, filepath.Join(dir, "run", "vm-1", "rootfs.ext4"))
	mgr := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{RunDir: filepath.Join(dir, "run")},
		vms: map[string]*VMInstance{"vm-1": {ID: "vm-1", Status: StatusPaused}},
	}
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("every artifact present must not read as missing")
	}
	if err := os.Remove(mem); err != nil {
		t.Fatal(err)
	}
	if !mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("a missing memory file must read as missing")
	}
	mgr.vms["vm-1"].Status = StatusRunning
	if mgr.pauseArtifactsMissing("vm-1", snap, mem) {
		t.Fatal("only paused records qualify")
	}
	if mgr.pauseArtifactsMissing("vm-2", snap, mem) {
		t.Fatal("an unknown vm must not qualify")
	}
}
