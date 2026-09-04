package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func seedFrozenManifest(t *testing.T, memPath, token string) {
	t.Helper()
	if err := WriteWallClockManifest(memPath, WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "a", WorkloadFrozen: true, GuestCorrectsClock: true, FreezeToken: token}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
}

// A test's evidence lives in its own directory and starts unrecognised.
func isolateEvidence(t *testing.T, dir string) {
	t.Helper()
	orig := wakeProtocolEvidencePath
	wakeProtocolEvidencePath = filepath.Join(dir, "evidence")
	wakeProtocolEvidenceDone.Store(false)
	t.Cleanup(func() { wakeProtocolEvidencePath = orig; wakeProtocolEvidenceDone.Store(false) })
}

func TestImageManifest(t *testing.T) {
	frozen := func(t *testing.T, path string) string {
		t.Helper()
		seedFrozenManifest(t, path, "tok")
		return path
	}

	t.Run("own_image", func(t *testing.T) {
		mem := frozen(t, filepath.Join(t.TempDir(), "mem.snap"))
		m, err := imageManifest(mem)
		if err != nil || m == nil || !m.WorkloadFrozen || m.FreezeToken != "tok" {
			t.Fatalf("m=%+v err=%v", m, err)
		}
	})
	t.Run("overlay_never_inherits_its_frozen_base", func(t *testing.T) {
		dir := t.TempDir()
		frozen(t, filepath.Join(dir, "template.snap"))
		m, err := imageManifest(filepath.Join(dir, "mem.diff"))
		if err != nil || m != nil {
			t.Fatalf("m=%+v err=%v, want legacy: a paused overlay without its own manifest may hold a running workload", m, err)
		}
	})
	t.Run("absent_is_legacy", func(t *testing.T) {
		dir := t.TempDir()
		m, err := imageManifest(filepath.Join(dir, "mem.snap"))
		if err != nil || m != nil {
			t.Fatalf("m=%+v err=%v, want nil, nil", m, err)
		}
	})
	t.Run("unreadable_is_refused", func(t *testing.T) {
		for name, body := range map[string]string{"empty": "", "garbage": "{", "future": `{"version":2}`, "frozen_without_token": `{"version":1,"workload_frozen":true}`} {
			mem := filepath.Join(t.TempDir(), "mem.snap")
			if err := os.WriteFile(WallClockMarkerPath(mem), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := imageManifest(mem); !errors.Is(err, ErrWallClockManifest) {
				t.Errorf("%s: err=%v, want ErrWallClockManifest", name, err)
			}
		}
	})
	t.Run("write_is_atomic_and_readable", func(t *testing.T) {
		mem := filepath.Join(t.TempDir(), "mem.snap")
		want := WallClockManifest{Version: 1, ArtifactID: NewArtifactID(), WorkloadFrozen: false, GuestCorrectsClock: true}
		if err := WriteWallClockManifest(mem, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadWallClockManifest(mem)
		if err != nil || got == nil || *got != want {
			t.Fatalf("got=%+v err=%v want=%+v", got, err, want)
		}
		if _, err := os.Stat(WallClockMarkerPath(mem) + ".tmp"); !os.IsNotExist(err) {
			t.Error("temp file left behind")
		}
	})
}

func TestWallClockMarkerPathMatchesInternal(t *testing.T) {
	if got, want := WallClockMarkerPath("/x/mem.snap"), clockFreezeMarkerPath("/x/mem.snap"); got != want {
		t.Fatalf("exported %q != internal %q", got, want)
	}
}

// The first manifest read on a host leaves evidence for the deploy guard; an
// absent manifest is not one.
func TestReadingAManifestLeavesWakeProtocolEvidence(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)

	mem := filepath.Join(dir, "mem.snap")
	if _, err := ReadWallClockManifest(mem); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); !os.IsNotExist(err) {
		t.Fatal("an absent manifest is not evidence")
	}
	seedFrozenManifest(t, mem, "tok")
	if _, err := ReadWallClockManifest(mem); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(wakeProtocolEvidencePath)
	if err != nil || len(b) == 0 {
		t.Fatalf("evidence = %q, %v; want a non-empty file", b, err)
	}
}

// Templates are seeded while the daemon runs; the first frozen one to land
// raises the floor here, at the builder's real layout depth.
func TestTemplateManifestsLeaveEvidence(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)

	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	if n := m.scanTemplateManifests(); n != 0 {
		t.Fatalf("found %d manifests in an empty tree", n)
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); !os.IsNotExist(err) {
		t.Fatal("no templates is not evidence")
	}
	// The builder's layout: templates/<template>/<build>/mem.snap.
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
	if n := m.scanTemplateManifests(); n != 1 {
		t.Fatalf("found %d manifests, want 1", n)
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err != nil {
		t.Fatalf("evidence not written after a frozen template landed: %v", err)
	}
}

// Starting a daemon creates no evidence — or every host with the switches off
// would raise the floor and block a rollback of itself — but evidence a
// previous process made durable is recognised.
func TestStartupRecognisesButNeverRaisesTheFloor(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}}
	ctx, cancel := context.WithCancel(context.Background())
	m.WatchTemplateManifests(ctx, zerolog.Nop())
	cancel()
	if recognizeWakeProtocolFloor() {
		t.Fatal("floor raised by a daemon that holds no frozen image")
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); !os.IsNotExist(err) {
		t.Fatal("startup created evidence")
	}
	if err := os.WriteFile(wakeProtocolEvidencePath, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !recognizeWakeProtocolFloor() {
		t.Fatal("existing evidence not recognised")
	}
}

func TestExistingWakeProtocolEvidenceNeedsNoWrite(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	if err := os.WriteFile(wakeProtocolEvidencePath, []byte("older-process\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureWakeProtocolFloor(); err != nil || !wakeProtocolEvidenceDone.Load() {
		t.Fatalf("err=%v done=%v", err, wakeProtocolEvidenceDone.Load())
	}
	if b, _ := os.ReadFile(wakeProtocolEvidencePath); string(b) != "older-process\n" {
		t.Errorf("existing evidence rewritten: %q", b)
	}
}

func TestWakeProtocolEvidenceRetriesAfterFailure(t *testing.T) {
	dir := t.TempDir()
	orig := wakeProtocolEvidencePath
	// A path inside a directory that exists but is a file: the write fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidencePath = filepath.Join(blocker, "evidence")
	wakeProtocolEvidenceDone.Store(false)
	t.Cleanup(func() { wakeProtocolEvidencePath = orig; wakeProtocolEvidenceDone.Store(false) })

	mem := filepath.Join(dir, "mem.snap")
	seedFrozenManifest(t, mem, "tok")
	if _, err := ReadWallClockManifest(mem); err != nil {
		t.Fatal(err)
	}
	if wakeProtocolEvidenceDone.Load() {
		t.Fatal("a failed write must not be remembered as done")
	}
	wakeProtocolEvidencePath = filepath.Join(dir, "evidence")
	if _, err := ReadWallClockManifest(mem); err != nil {
		t.Fatal(err)
	}
	if !wakeProtocolEvidenceDone.Load() {
		t.Fatal("the retry did not land")
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err != nil {
		t.Fatalf("evidence missing after retry: %v", err)
	}
}

// An image whose workload is frozen owes a wake this supervisor cannot give:
// both resume and restore refuse it before anything is launched, rather than
// restore it with its workload stopped for good.
func TestFrozenImageIsRefusedBeforeLaunch(t *testing.T) {
	isolateEvidence(t, t.TempDir())
	dir := t.TempDir()
	snapPath, memPath, rootfs := filepath.Join(dir, "vm.snap"), filepath.Join(dir, "mem.snap"), filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfs} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFrozenManifest(t, memPath, "tok")
	launched := false
	launch := func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		return 4321, SupervisionUnit, nil
	}
	// A record that lost the answer goes to the disk, and the disk says frozen.
	inst := &VMInstance{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, restoreSem: make(chan struct{}, 1)}
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
	fresh := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1)}
	fresh.launchFirecrackerHook = launch
	_, cerr := fresh.RestoreVMSnapshot(context.Background(), "vm-2", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if status.Code(cerr) != codes.FailedPrecondition || launched {
		t.Fatalf("restore: err=%v launched=%v, want FailedPrecondition before launch", cerr, launched)
	}
}
