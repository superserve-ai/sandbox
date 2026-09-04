package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
)

func TestPauseIntentBlocks(t *testing.T) {
	t.Run("absent_does_not_block", func(t *testing.T) {
		if blocked, why := pauseIntentBlocks(t.TempDir(), "a"); blocked {
			t.Fatalf("blocked: %s", why)
		}
	})
	t.Run("unreadable_blocks", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(pauseIntentPath(dir), []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}
		if blocked, _ := pauseIntentBlocks(dir, "a"); !blocked {
			t.Fatal("an unreadable intent must block until inspected")
		}
	})
	t.Run("another_pauses_intent_blocks", func(t *testing.T) {
		dir := t.TempDir()
		if err := writePauseIntent(dir, pauseIntent{VMID: "vm", ArtifactID: "other"}); err != nil {
			t.Fatal(err)
		}
		if blocked, _ := pauseIntentBlocks(dir, "a"); !blocked {
			t.Fatal("an intent from an interrupted pause must block")
		}
		if _, err := os.Stat(pauseIntentPath(dir)); err != nil {
			t.Fatal("a blocking intent must be left for inspection")
		}
	})
	t.Run("completed_pauses_intent_clears", func(t *testing.T) {
		dir := t.TempDir()
		if err := writePauseIntent(dir, pauseIntent{VMID: "vm", ArtifactID: "a"}); err != nil {
			t.Fatal(err)
		}
		if blocked, why := pauseIntentBlocks(dir, "a"); blocked {
			t.Fatalf("blocked by a completed pause's leftover: %s", why)
		}
		if _, err := os.Stat(pauseIntentPath(dir)); !os.IsNotExist(err) {
			t.Fatal("the leftover was not cleared")
		}
	})
}

// The floor is up on any host that holds an intent; a host whose floor is
// down looks for none.
func raiseFloorForTest(t *testing.T) {
	t.Helper()
	wakeProtocolEvidenceDone.Store(true)
	t.Cleanup(func() { wakeProtocolEvidenceDone.Store(false) })
}

func TestInterruptedPauseRefusesResumeAndRestore(t *testing.T) {
	raiseFloorForTest(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vm.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(dir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "interrupted"}); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := pauseIntentBlocks(dir, "other"); !blocked {
		t.Fatal("intent not visible after write")
	}
	launched := false
	launch := func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}

	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs,
	}
	mgr := &Manager{
		log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{},
		vms: map[string]*VMInstance{"vm-1": inst}, restoreSem: make(chan struct{}, 1),
	}
	mgr.launchFirecrackerHook = launch
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
	unlock()
	if status.Code(rerr) != codes.FailedPrecondition || launched {
		t.Fatalf("resume: err=%v launched=%v, want FailedPrecondition before launch", rerr, launched)
	}

	// An in-place restore of the same VM meets the intent too.
	known := &VMInstance{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs}
	fresh := &Manager{
		log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, netMgr: &fakeNetMgr{},
		vms: map[string]*VMInstance{"vm-1": known}, restoreSem: make(chan struct{}, 1),
	}
	fresh.launchFirecrackerHook = launch
	_, cerr := fresh.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if status.Code(cerr) != codes.FailedPrecondition || launched {
		t.Fatalf("restore: err=%v launched=%v, want FailedPrecondition before launch", cerr, launched)
	}

	if err := clearPauseIntent(dir); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if blocked, _ := pauseIntentBlocks(dir, ""); blocked {
		t.Fatal("still blocked after clear")
	}
}

// A host whose floor is down has never written an intent, so its resumes
// look for none: an intent placed there by hand is not consulted.
func TestFloorDownLooksForNoIntent(t *testing.T) {
	dir := t.TempDir()
	snapPath, memPath, rootfs := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap"), filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(dir, pauseIntent{VMID: "vm-1", ArtifactID: "interrupted"}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}}
	launched := false
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil || !launched {
		t.Fatalf("resume: err=%v launched=%v, want the resume to proceed without looking", err, launched)
	}
	if _, err := os.Stat(pauseIntentPath(dir)); err != nil {
		t.Error("the intent was touched on a host whose floor is down")
	}
}

func TestCompletedPauseIntentClearsItself(t *testing.T) {
	raiseFloorForTest(t)
	dir := t.TempDir()
	snapPath, memPath, rootfs := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap"), filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePauseIntent(dir, pauseIntent{VMID: "vm-1", FreezeToken: "tok", ArtifactID: "done"}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit,
		SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs, ArtifactID: "done",
	}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}}
	launched := false
	mgr.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(string, string, string, string, *network.VMNetInfo) (bool, string, error) { return false, "", nil }
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil || !launched {
		t.Fatalf("resume: err=%v launched=%v, want the completed pause's intent cleared and the resume to proceed", err, launched)
	}
	if _, err := os.Stat(pauseIntentPath(dir)); !os.IsNotExist(err) {
		t.Error("intent still present after the resume")
	}
}
