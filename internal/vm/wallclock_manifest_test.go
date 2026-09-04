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
	// The zero-byte marker an earlier supervisor wrote carries no manifest:
	// the image is restored the older way, never refused.
	t.Run("empty_marker_is_legacy", func(t *testing.T) {
		mem := filepath.Join(t.TempDir(), "mem.snap")
		if err := os.WriteFile(WallClockMarkerPath(mem), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := imageManifest(mem)
		if err != nil || m != nil {
			t.Fatalf("m=%+v err=%v, want nil, nil", m, err)
		}
		if guestCorrectsWallClock(mem, "") {
			t.Fatal("an empty marker is not proof the guest corrects its clock")
		}
	})
	t.Run("unreadable_is_refused", func(t *testing.T) {
		for name, body := range map[string]string{
			"garbage":                     "{",
			"future":                      `{"version":2}`,
			"no_artifact":                 `{"version":1,"guest_corrects_clock":true}`,
			"frozen_without_token":        `{"version":1,"artifact_id":"a","workload_frozen":true,"guest_corrects_clock":true}`,
			"frozen_guest_not_correcting": `{"version":1,"artifact_id":"a","workload_frozen":true,"freeze_token":"t"}`,
		} {
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

// Starting a daemon creates no evidence — or every host with the switches off
// would raise the floor and block a rollback of itself — but evidence a
// previous process made durable is recognised, and only then are pause
// intents looked for.
func TestStartupRecognisesButNeverRaisesTheFloor(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	if RecognizeWakeProtocolFloor() || wakeProtocolFloorRaised() {
		t.Fatal("floor raised on a host that holds no frozen image")
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); !os.IsNotExist(err) {
		t.Fatal("startup created evidence")
	}
	if err := os.WriteFile(wakeProtocolEvidencePath, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !RecognizeWakeProtocolFloor() || !wakeProtocolFloorRaised() {
		t.Fatal("existing evidence not recognised")
	}
}

// The builder raises the floor before it publishes a frozen image; a later
// process finds it durable, and a raise that cannot land is an error.
func TestRaiseWakeProtocolFloorIsDurable(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	if err := RaiseWakeProtocolFloor(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(wakeProtocolEvidencePath)
	if err != nil || len(b) == 0 {
		t.Fatalf("evidence = %q, %v; want a non-empty file", b, err)
	}
	wakeProtocolEvidenceDone.Store(false) // a fresh process
	if !RecognizeWakeProtocolFloor() {
		t.Fatal("a fresh process did not recognise the evidence")
	}
	// Created once: a second raise leaves the file as it is and no temp file
	// behind; and existence alone is the fact, an empty file included, as it
	// is for the host guard.
	if err := os.WriteFile(wakeProtocolEvidencePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidenceDone.Store(false)
	if !RecognizeWakeProtocolFloor() {
		t.Fatal("an empty evidence file was not recognised")
	}
	// A raise over a file this process has not proven durable syncs the
	// directory and counts it, without rewriting it.
	wakeProtocolEvidenceDone.Store(false)
	if err := RaiseWakeProtocolFloor(); err != nil || !wakeProtocolFloorRaised() {
		t.Fatalf("err=%v raised=%v; want the existing file counted once its directory is synced", err, wakeProtocolFloorRaised())
	}
	if b, _ := os.ReadFile(wakeProtocolEvidencePath); len(b) != 0 {
		t.Errorf("existing evidence rewritten: %q", b)
	}
	if left, _ := filepath.Glob(wakeProtocolEvidencePath + ".tmp.*"); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidencePath = filepath.Join(blocker, "evidence")
	wakeProtocolEvidenceDone.Store(false)
	if err := RaiseWakeProtocolFloor(); err == nil || wakeProtocolFloorRaised() {
		t.Fatalf("err=%v raised=%v; a raise that cannot land must fail and not be remembered", err, wakeProtocolFloorRaised())
	}
}

// A template build is immutable once published, so its manifest is read once
// per daemon; any other image is read every time.
func TestTemplateManifestIsReadOncePerDaemon(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1", "mem.snap")
	if err := os.MkdirAll(filepath.Dir(tpl), 0o755); err != nil {
		t.Fatal(err)
	}
	if man, err := m.imageManifestCached(tpl); err != nil || man != nil {
		t.Fatalf("first read: man=%+v err=%v, want legacy", man, err)
	}
	seedFrozenManifest(t, tpl, "tok")
	if man, err := m.imageManifestCached(tpl); err != nil || man != nil {
		t.Fatalf("second read: man=%+v err=%v, want the first answer kept", man, err)
	}
	// A path that only looks like a template's is not one, and is not kept.
	dotted := filepath.Join(dir, TemplatesDirName, "..", "vm-2", "mem.snap")
	if err := os.MkdirAll(filepath.Dir(dotted), 0o755); err != nil {
		t.Fatal(err)
	}
	if man, err := m.imageManifestCached(dotted); err != nil || man != nil {
		t.Fatalf("dotted path, first read: man=%+v err=%v", man, err)
	}
	seedFrozenManifest(t, dotted, "tok")
	if man, err := m.imageManifestCached(dotted); err != nil || man == nil {
		t.Fatalf("dotted path, second read: man=%+v err=%v, want the disk consulted, not a cached answer", man, err)
	}
	other := filepath.Join(dir, "vm-1", "mem.snap")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if man, err := m.imageManifestCached(other); err != nil || man != nil {
		t.Fatalf("paused image, first read: man=%+v err=%v", man, err)
	}
	seedFrozenManifest(t, other, "tok")
	if man, err := m.imageManifestCached(other); err != nil || man == nil || !man.WorkloadFrozen {
		t.Fatalf("paused image, second read: man=%+v err=%v, want the disk consulted", man, err)
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
