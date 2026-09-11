package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	resetEvidence := func() { wakeProtocolEvidenceSeen.Store(false); wakeProtocolEvidenceDurable.Store(false) }
	resetEvidence()
	t.Cleanup(func() { wakeProtocolEvidencePath = orig; resetEvidence() })
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
		// The lazy form is the same file, minus the barriers.
		lazy := filepath.Join(t.TempDir(), "mem.snap")
		if err := writeWallClockManifestLazy(lazy, want); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadWallClockManifest(lazy); err != nil || got == nil || *got != want {
			t.Fatalf("lazy: got=%+v err=%v want=%+v", got, err, want)
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
	wakeProtocolEvidenceSeen.Store(false) // a fresh process
	wakeProtocolEvidenceDurable.Store(false)
	if !RecognizeWakeProtocolFloor() {
		t.Fatal("a fresh process did not recognise the evidence")
	}
	// Recognition is seeing, not proving: a raise after it must still make
	// the file durable itself, without rewriting it, and only then count it.
	if wakeProtocolEvidenceDurable.Load() {
		t.Fatal("recognition counted the file as durable")
	}
	if err := RaiseWakeProtocolFloor(); err != nil || !wakeProtocolEvidenceDurable.Load() {
		t.Fatalf("err=%v durable=%v; want the recognised file made durable by the raise", err, wakeProtocolEvidenceDurable.Load())
	}
	// Created once: existence alone is the fact, an empty file included, as
	// it is for the host guard; a raise over it leaves it as it is and no
	// temp file behind.
	if err := os.WriteFile(wakeProtocolEvidencePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidenceSeen.Store(false)
	wakeProtocolEvidenceDurable.Store(false)
	if !RecognizeWakeProtocolFloor() {
		t.Fatal("an empty evidence file was not recognised")
	}
	if err := RaiseWakeProtocolFloor(); err != nil || !wakeProtocolFloorRaised() || !wakeProtocolEvidenceDurable.Load() {
		t.Fatalf("err=%v raised=%v durable=%v; want the existing file counted once its directory is synced", err, wakeProtocolFloorRaised(), wakeProtocolEvidenceDurable.Load())
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
	wakeProtocolEvidenceSeen.Store(false)
	wakeProtocolEvidenceDurable.Store(false)
	if err := RaiseWakeProtocolFloor(); err == nil || wakeProtocolFloorRaised() {
		t.Fatalf("err=%v raised=%v; a raise that cannot land must fail and not be remembered", err, wakeProtocolFloorRaised())
	}
}

// A template image replaced at the same path is seen as it is now, in both
// directions: nothing remembers a manifest by path.
func TestTemplateManifestIsReadOnEveryRestore(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1", "mem.snap")
	if err := os.MkdirAll(filepath.Dir(tpl), 0o755); err != nil {
		t.Fatal(err)
	}
	if man, err := imageManifest(tpl); err != nil || man != nil {
		t.Fatalf("legacy: man=%+v err=%v", man, err)
	}
	seedFrozenManifest(t, tpl, "tok")
	if man, err := imageManifest(tpl); err != nil || man == nil || !man.WorkloadFrozen {
		t.Fatalf("legacy replaced by frozen: man=%+v err=%v, want the frozen manifest seen", man, err)
	}
	if err := os.Remove(WallClockMarkerPath(tpl)); err != nil {
		t.Fatal(err)
	}
	if man, err := imageManifest(tpl); err != nil || man != nil {
		t.Fatalf("frozen replaced by legacy: man=%+v err=%v, want legacy seen", man, err)
	}
}

// A frozen image is only restored once the rollback floor is durable on this
// host; a floor that cannot be written refuses the restore before any launch.
func TestFrozenRestoreRequiresTheFloor(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	isolateEvidence(t, blocker) // a path inside a file: the raise cannot land

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
	frozen := true
	inst := &VMInstance{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit, SnapshotPath: snapPath, MemFilePath: memPath, DiskPath: rootfs, SnapshotWorkloadFrozen: &frozen, FreezeToken: "tok"}
	mgr := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: dir}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{"vm-1": inst}, restoreSem: make(chan struct{}, 1)}
	mgr.launchFirecrackerHook = launch
	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, rerr := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
	unlock()
	if status.Code(rerr) != codes.Unavailable || launched {
		t.Fatalf("resume: err=%v launched=%v, want Unavailable before launch", rerr, launched)
	}
	fresh := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{RunDir: t.TempDir()}, netMgr: &fakeNetMgr{}, vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1)}
	fresh.launchFirecrackerHook = launch
	_, cerr := fresh.RestoreVMSnapshot(context.Background(), "vm-2", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if status.Code(cerr) != codes.Unavailable || launched {
		t.Fatalf("restore: err=%v launched=%v, want Unavailable before launch", cerr, launched)
	}
}

// Templates are seeded while the daemon runs; the first frozen one to land
// raises the floor here, at the builder's real layout depth. An unfrozen
// manifest raises nothing.
func TestTemplateManifestsLeaveEvidence(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)

	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	if n := m.scanTemplateManifests(); n != 0 {
		t.Fatalf("found %d frozen manifests in an empty tree", n)
	}
	// The builder's layout: templates/<template>/<build>/mem.snap.
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteWallClockManifest(filepath.Join(tpl, "mem.snap"), WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "a", GuestCorrectsClock: true}); err != nil {
		t.Fatal(err)
	}
	if n := m.scanTemplateManifests(); n != 0 || wakeProtocolFloorRaised() {
		t.Fatalf("n=%d raised=%v; an unfrozen manifest is not evidence", n, wakeProtocolFloorRaised())
	}
	seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
	if n := m.scanTemplateManifests(); n != 1 {
		t.Fatalf("found %d frozen manifests, want 1", n)
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err != nil {
		t.Fatalf("evidence not written after a frozen template landed: %v", err)
	}
}

// The daemon's own raise is durable once and then free; a raise that cannot
// land is not remembered, so the next one tries again.
func TestEnsureWakeProtocolFloor(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	if err := os.WriteFile(wakeProtocolEvidencePath, []byte("older-process\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureWakeProtocolFloor(); err != nil || !wakeProtocolEvidenceDurable.Load() {
		t.Fatalf("err=%v durable=%v", err, wakeProtocolEvidenceDurable.Load())
	}
	if b, _ := os.ReadFile(wakeProtocolEvidencePath); string(b) != "older-process\n" {
		t.Errorf("existing evidence rewritten: %q", b)
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wakeProtocolEvidencePath = filepath.Join(blocker, "evidence")
	wakeProtocolEvidenceSeen.Store(false)
	wakeProtocolEvidenceDurable.Store(false)
	if err := ensureWakeProtocolFloor(); err == nil || wakeProtocolEvidenceDurable.Load() {
		t.Fatalf("err=%v durable=%v; a failed raise must not be remembered as done", err, wakeProtocolEvidenceDurable.Load())
	}
	wakeProtocolEvidencePath = filepath.Join(dir, "evidence2")
	if err := ensureWakeProtocolFloor(); err != nil || !wakeProtocolEvidenceDurable.Load() {
		t.Fatalf("retry: err=%v durable=%v", err, wakeProtocolEvidenceDurable.Load())
	}
}

// A host with the switch off does no work for the watch: a frozen template
// already on disk raises nothing until the switch is on.
func TestTemplateWatchRunsOnlyWhenTheSwitchIsOn(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	off := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	select {
	case <-off.WatchTemplateManifests(ctx, zerolog.Nop()):
	default:
		t.Fatal("a watch with the switch off must start nothing")
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
		t.Fatal("the watch scanned the templates with the switch off")
	}

	on := &Manager{cfg: ManagerConfig{SnapshotDir: dir, GuestClockFreezeEnabled: true}}
	stopped := on.WatchTemplateManifests(ctx, zerolog.Nop())
	// The watcher must be gone before the evidence path is restored by the
	// cleanup, or it would read a path being rewritten under it.
	defer func() { cancel(); <-stopped }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the watch never raised the floor with the switch on")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Recognised evidence is proven durable in the background at startup, so the
// first request that needs the floor after a restart pays nothing; a host
// without evidence primes nothing and raises nothing.
func TestPrimeWakeProtocolFloor(t *testing.T) {
	t.Run("recognised_evidence_becomes_durable_off_the_request_path", func(t *testing.T) {
		dir := t.TempDir()
		isolateEvidence(t, dir)
		if err := os.WriteFile(wakeProtocolEvidencePath, []byte(wakeProtocolEvidenceNote), 0o644); err != nil {
			t.Fatal(err)
		}
		if !RecognizeWakeProtocolFloor() || wakeProtocolEvidenceDurable.Load() {
			t.Fatal("precondition: seen at startup, not yet durable")
		}
		PrimeWakeProtocolFloor(zerolog.Nop())
		deadline := time.Now().Add(3 * time.Second)
		for !wakeProtocolEvidenceDurable.Load() {
			if time.Now().After(deadline) {
				t.Fatal("priming never proved the recognised floor durable")
			}
			time.Sleep(5 * time.Millisecond)
		}
		// The request path then does no work and records no phase.
		sink := &phaseSink{}
		m := &Manager{recorder: sink}
		if err := m.ensureWakeFloorTimed("restore"); err != nil || sink.has("restore", "wake_floor") {
			t.Fatalf("err=%v phases=%+v; a durable floor must cost a request nothing", err, sink.phases)
		}
	})

	t.Run("no_evidence_primes_nothing", func(t *testing.T) {
		dir := t.TempDir()
		isolateEvidence(t, dir)
		if RecognizeWakeProtocolFloor() {
			t.Fatal("precondition: nothing to recognise")
		}
		PrimeWakeProtocolFloor(zerolog.Nop())
		time.Sleep(50 * time.Millisecond)
		if _, err := os.Stat(wakeProtocolEvidencePath); err == nil || wakeProtocolEvidenceDurable.Load() {
			t.Fatal("priming raised a floor on a host that had none")
		}
	})

	// A request that does have to prove the floor attributes the cost.
	t.Run("a_request_that_proves_it_records_the_phase", func(t *testing.T) {
		dir := t.TempDir()
		isolateEvidence(t, dir)
		sink := &phaseSink{}
		m := &Manager{recorder: sink}
		if err := m.ensureWakeFloorTimed("pause"); err != nil || !sink.has("pause", "wake_floor") {
			t.Fatalf("err=%v phases=%+v; the fallback must be timed as its own phase", err, sink.phases)
		}
	})
}

// A frozen template that lands after the watch started is witnessed as it
// lands, not at the next periodic scan: the floor is up within moments.
func TestTemplateWatchWitnessesATemplateAsItLands(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, TemplatesDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir, GuestClockFreezeEnabled: true}}
	stopped := m.WatchTemplateManifests(ctx, zerolog.Nop())
	defer func() { cancel(); <-stopped }()
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
		t.Fatal("nothing had landed yet")
	}
	// The copy: directories first, then the manifest, renamed into place.
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the frozen template that landed was not witnessed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A manifest streamed into its final path, created empty and written after,
// is witnessed at its last write, not left for the next periodic scan.
func TestTemplateWatchWitnessesAManifestStreamedIntoPlace(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir, GuestClockFreezeEnabled: true}}
	stopped := m.WatchTemplateManifests(ctx, zerolog.Nop())
	defer func() { cancel(); <-stopped }()
	time.Sleep(50 * time.Millisecond)

	path := WallClockMarkerPath(filepath.Join(tpl, "mem.snap"))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the create is seen while the file is empty
	body := `{"version":1,"artifact_id":"a","workload_frozen":true,"guest_corrects_clock":true,"freeze_token":"tok"}`
	if _, err := f.WriteString(body[:20]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // a partial write does not parse
	if _, err := f.WriteString(body[20:]); err != nil {
		t.Fatal(err)
	}
	f.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the streamed frozen manifest was not witnessed at its last write")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A watch started before the templates root exists still witnesses the first
// template to land: the root is created so the watch attaches to it.
func TestTemplateWatchAttachesBeforeTheRootExists(t *testing.T) {
	dir := t.TempDir()
	isolateEvidence(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir, GuestClockFreezeEnabled: true}}
	stopped := m.WatchTemplateManifests(ctx, zerolog.Nop())
	defer func() { cancel(); <-stopped }()
	time.Sleep(50 * time.Millisecond)
	tpl := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	seedFrozenManifest(t, filepath.Join(tpl, "mem.snap"), "tok")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a template landing under a root created after the watch started was not witnessed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A manifest that cannot be read may have described a frozen image, so its
// removal is made durable like a frozen one's: where the directory cannot be
// synced, the removal is reported as failed rather than as done.
func TestRemovingAnUnreadableManifestIsDurable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a directory the process cannot open for sync; root can")
	}
	dir := t.TempDir()
	isolateEvidence(t, dir)
	raiseFloorForTest(t)
	imgDir := filepath.Join(dir, "img")
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := filepath.Join(imgDir, "mem.snap")
	if err := os.WriteFile(WallClockMarkerPath(mem), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Writable and searchable but not readable: the unlink succeeds, the
	// directory sync cannot open it.
	if err := os.Chmod(imgDir, 0o333); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(imgDir, 0o755) })
	if _, err := removeWallClockManifest(mem); err == nil {
		t.Fatal("removing an unreadable manifest without a durable sync must not report success")
	}
}
