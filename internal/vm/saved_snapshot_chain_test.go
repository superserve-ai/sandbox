package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// chainFC serves the Firecracker API on a unix socket and writes what a
// snapshot asks for: the vmstate file, the pages the guest dirtied since the
// last snapshot into the memory file at their offsets, and the presence map
// as the union of what the file held and what was written. It keeps the
// generation a real Firecracker keeps, 0 when armed and one more per
// snapshot, and refuses a guarded diff that names another, before touching
// anything.
type chainFC struct {
	socketPath string
	mu         sync.Mutex
	generation int64
	calls      int
	bodies     []string
	// dirty is what the guest dirtied before each snapshot, by call.
	dirty []map[int]byte
	// hang, when set, holds a diff until the request is abandoned.
	hang bool
}

func startChainFC(t *testing.T, dirty ...map[int]byte) *chainFC {
	t.Helper()
	f := &chainFC{socketPath: filepath.Join(t.TempDir(), "fc.sock"), dirty: dirty}
	ln, err := net.Listen("unix", f.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	waitForUnixSocket(t, f.socketPath)
	return f
}

func (f *chainFC) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPatch && r.URL.Path == "/vm":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"state":"Running"}`)
	case r.Method == http.MethodPut && r.URL.Path == "/snapshot/create":
		b, _ := io.ReadAll(r.Body)
		var req struct {
			SnapshotPath       string `json:"snapshot_path"`
			MemFilePath        string `json:"mem_file_path"`
			SnapshotType       string `json:"snapshot_type"`
			ExpectedSessionID  string `json:"expected_session_id"`
			ExpectedGeneration *int64 `json:"expected_generation"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		if req.ExpectedSessionID != "" && (req.ExpectedGeneration == nil || *req.ExpectedGeneration != f.generation) {
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, mismatchPayload)
			return
		}
		if f.hang && req.SnapshotType == "Diff" {
			f.mu.Unlock()
			<-r.Context().Done()
			return
		}
		call := f.calls
		f.calls++
		f.generation++
		var pages map[int]byte
		if call < len(f.dirty) {
			pages = f.dirty[call]
		}
		f.mu.Unlock()
		if err := writeSnapshotFiles(req.SnapshotPath, req.MemFilePath, req.SnapshotType == "Diff", pages); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

const chainPages = 4

// writeSnapshotFiles is the write a Firecracker does: a diff adds the dirtied
// pages to the memory file it is given and names them in its presence map on
// top of what was there; a full image writes every page.
func writeSnapshotFiles(vmstate, mem string, diff bool, pages map[int]byte) error {
	if err := os.WriteFile(vmstate, []byte("vmstate"), 0o644); err != nil {
		return err
	}
	if !diff {
		pages = map[int]byte{}
		for i := 0; i < chainPages; i++ {
			pages[i] = 'F'
		}
	}
	if _, err := os.Stat(mem); err != nil {
		if err := createSparseFile(mem, chainPages*testPage); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(mem, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	bits := make([]uint64, 1)
	if prior, err := presence.Read(mem); err == nil && len(prior.Bits) == 1 {
		bits[0] = prior.Bits[0]
	}
	for p, b := range pages {
		if _, err := f.WriteAt(bytes.Repeat([]byte{b}, testPage), int64(p*testPage)); err != nil {
			return err
		}
		bits[0] |= 1 << uint(p)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if diff {
		return presence.Write(mem, testPage, chainPages, bits)
	}
	return nil
}

func (f *chainFC) snapshotBodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

// presentPages is the set of pages an overlay's presence map names.
func presentPages(t *testing.T, mem string) map[int]bool {
	t.Helper()
	p, err := presence.Read(mem)
	if err != nil {
		t.Fatalf("presence of %s: %v", mem, err)
	}
	out := map[int]bool{}
	for i := 0; i < int(p.NPages); i++ {
		if p.IsSet(i) {
			out[i] = true
		}
	}
	return out
}

func samePages(a map[int]bool, want ...int) bool {
	if len(a) != len(want) {
		return false
	}
	for _, p := range want {
		if !a[p] {
			return false
		}
	}
	return true
}

// seedRunningSource is a running, dirty-tracked source on a template base:
// first pass, still served straight from the base, or accumulating on its
// own overlay. Its host has the floors up and its record persisted.
func seedRunningSource(t *testing.T, m *Manager, fc *chainFC, firstPass bool) *VMInstance {
	t.Helper()
	useTempFloor(t)
	origStaged := stagedIntentEvidencePath
	stagedIntentEvidencePath = filepath.Join(t.TempDir(), "staged-intent-evidence")
	stagedIntentEvidenceDurable.Store(false)
	t.Cleanup(func() {
		stagedIntentEvidencePath = origStaged
		stagedIntentEvidenceDurable.Store(false)
	})
	origFree := savedFreeBytes
	savedFreeBytes = func(string) (int64, error) { return 4 << 30, nil }
	t.Cleanup(func() { savedFreeBytes = origFree })

	m.cfg.IncrementalSnapshotEnabled = true
	m.cfg.DirtyTrackingSessionEnabled = true
	m.dirtyTrackingSessionCapable.Store(true)
	m.stopVMHook = func(context.Context, string, Supervision) error { return nil }
	if m.state == nil {
		store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		m.state = store
	}

	vmID := uuid.NewString()
	snapDir := filepath.Join(m.cfg.SnapshotDir, vmID)
	runDir := filepath.Join(m.cfg.RunDir, vmID)
	tplDir := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, "tpl", "build-1")
	for _, d := range []string{snapDir, runDir, tplDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(tplDir, "mem.snap")
	pageFile(t, base, chainPages, map[int]byte{0: 'B', 1: 'B', 2: 'B', 3: 'B'}, false)
	baseDisk := filepath.Join(tplDir, "base.ext4")
	if err := os.WriteFile(baseDisk, []byte("base-disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(runDir, "overlay.ext4")
	pageFile(t, disk, 8, map[int]byte{3: 'D'}, false)
	inst := &VMInstance{
		ID:                     vmID,
		Status:                 StatusRunning,
		SocketPath:             fc.socketPath,
		SnapshotPath:           filepath.Join(snapDir, "vmstate.snap"),
		DiskPath:               disk,
		MemFilePath:            base,
		BaseMemPath:            base,
		DirtyTracked:           true,
		DirtyTrackingSessionID: "tok",
		Supervision:            SupervisionCgroup,
		Config:                 VMConfig{VCPU: 1, MemoryMiB: 1, DiskSizeMiB: 4096, BasePath: baseDisk},
	}
	if !firstPass {
		overlay := filepath.Join(snapDir, "mem.diff")
		pageFile(t, overlay, chainPages, map[int]byte{1: 'S'}, true)
		if err := os.WriteFile(layeredBaseSidecarPath(overlay), []byte(base), 0o644); err != nil {
			t.Fatal(err)
		}
		inst.MemFilePath = overlay
	}
	m.mu.Lock()
	m.vms[vmID] = inst
	m.mu.Unlock()
	if !m.persistState(inst) {
		t.Fatal("seed not persisted")
	}
	return inst
}

func expectedGenerationOf(t *testing.T, body string) int64 {
	t.Helper()
	var req struct {
		ExpectedGeneration *int64 `json:"expected_generation"`
		SnapshotType       string `json:"snapshot_type"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.SnapshotType != "Diff" || req.ExpectedGeneration == nil {
		t.Fatalf("not a guarded diff: %s", body)
	}
	return *req.ExpectedGeneration
}

// Two captures of a running source and then its pause: every image is a
// diff on the chain, each snapshot holds what the source had written by
// then, and the pause's overlay holds all of it.
func TestRunningCaptureKeepsTheSourcesPauseIncremental(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'}, map[int]byte{3: 'Y'}, map[int]byte{0: 'Z'})
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, true)
	ctx := context.Background()
	overlay := filepath.Join(m.cfg.SnapshotDir, inst.ID, "mem.diff")
	base := inst.BaseMemPath

	first, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	// The chain moved on: the source accumulates on its overlay from here,
	// at the generation Firecracker moved to, durably.
	inst.mu.RLock()
	memFile, baseMem, gen, tracked, st := inst.MemFilePath, inst.BaseMemPath, inst.DirtyTrackingGeneration, inst.DirtyTracked, inst.Status
	inst.mu.RUnlock()
	if memFile != overlay || baseMem != base || gen != 1 || !tracked || st != StatusRunning {
		t.Fatalf("after the capture: mem=%s base=%s gen=%d tracked=%v status=%v", memFile, baseMem, gen, tracked, st)
	}
	if rec, err := m.state.Get(inst.ID); err != nil || rec == nil || rec.MemFilePath != overlay || rec.DirtyTrackingGeneration != 1 {
		t.Fatalf("chain advance not persisted: %+v %v", rec, err)
	}
	if got := presentPages(t, overlay); !samePages(got, 2) {
		t.Fatalf("chain overlay after the first capture names %v, want page 2", got)
	}
	if b, ok := readLayeredBase(overlay); !ok || b != base {
		t.Fatalf("chain overlay base record %q, want %s", b, base)
	}
	// The snapshot is the chain's image, with its map and base.
	if first.MemPath != filepath.Join(filepath.Dir(first.DiskPath), "mem.diff") || first.BaseMemPath != base {
		t.Fatalf("first snapshot names mem=%s base=%s", first.MemPath, first.BaseMemPath)
	}
	if pageAt(t, first.MemPath, 2) != 'X' || !samePages(presentPages(t, first.MemPath), 2) {
		t.Fatalf("first snapshot does not hold the capture's page")
	}
	if b, ok := readLayeredBase(first.MemPath); !ok || b != base {
		t.Fatalf("first snapshot base record %q", b)
	}
	if _, err := os.Stat(first.SnapshotPath); err != nil {
		t.Fatalf("first snapshot has no vmstate: %v", err)
	}

	second, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	if pageAt(t, second.MemPath, 2) != 'X' || pageAt(t, second.MemPath, 3) != 'Y' || !samePages(presentPages(t, second.MemPath), 2, 3) {
		t.Fatalf("second snapshot does not hold both captures' pages")
	}
	if !samePages(presentPages(t, first.MemPath), 2) {
		t.Fatal("the second capture changed the first snapshot")
	}
	inst.mu.RLock()
	gen = inst.DirtyTrackingGeneration
	inst.mu.RUnlock()
	if gen != 2 {
		t.Fatalf("generation after two captures %d, want 2", gen)
	}

	// The pause is a diff on the same overlay, naming the generation the
	// captures moved to, and leaves the whole chain in it.
	if _, memPath, _, err := m.PauseVM(ctx, inst.ID, "", "tok-test"); err != nil {
		t.Fatalf("pause after captures: %v", err)
	} else if memPath != overlay {
		t.Fatalf("pause wrote %s, want the chain overlay", memPath)
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 3 {
		t.Fatalf("want three diffs, got %d", len(bodies))
	}
	for i, want := range []int64{0, 1, 2} {
		if got := expectedGenerationOf(t, bodies[i]); got != want {
			t.Fatalf("snapshot %d named generation %d, want %d", i, got, want)
		}
	}
	if !samePages(presentPages(t, overlay), 0, 2, 3) || pageAt(t, overlay, 0) != 'Z' || pageAt(t, overlay, 2) != 'X' || pageAt(t, overlay, 3) != 'Y' {
		t.Fatalf("paused overlay names %v; want every page written since the base", presentPages(t, overlay))
	}
	inst.mu.RLock()
	st, memFile = inst.Status, inst.MemFilePath
	inst.mu.RUnlock()
	if st != StatusPaused || memFile != overlay {
		t.Fatalf("after the pause: status=%v mem=%s", st, memFile)
	}
}

// A source accumulating on its overlay keeps what the overlay held.
func TestRunningCaptureOfAnAccumulatingSourceKeepsEarlierPages(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'})
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, false)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	if !samePages(presentPages(t, man.MemPath), 1, 2) || pageAt(t, man.MemPath, 1) != 'S' || pageAt(t, man.MemPath, 2) != 'X' {
		t.Fatalf("snapshot names %v; want the overlay's page and the capture's", presentPages(t, man.MemPath))
	}
	if got := expectedGenerationOf(t, fc.snapshotBodies()[0]); got != 0 {
		t.Fatalf("first diff named generation %d", got)
	}
}

// A vmd restart between the capture and the pause: the record carries the
// chain and its generation, so the pause is still a diff.
func TestRunningCaptureSurvivesAVmdRestart(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'}, map[int]byte{3: 'Y'})
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, true)
	ctx := context.Background()
	if _, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS); err != nil {
		t.Fatal(err)
	}
	rec, err := m.state.Get(inst.ID)
	if err != nil || rec == nil {
		t.Fatalf("record: %v", err)
	}
	// The daemon that comes back knows only the record.
	m2 := newSavedTestManager(t)
	m2.cfg = m.cfg
	m2.state = m.state
	m2.dirtyTrackingSessionCapable.Store(true)
	m2.stopVMHook = m.stopVMHook
	again := toInstance(*rec)
	m2.mu.Lock()
	m2.vms[inst.ID] = again
	m2.mu.Unlock()
	if !again.DirtyTracked || again.DirtyTrackingGeneration != 1 || again.MemFilePath != filepath.Join(m.cfg.SnapshotDir, inst.ID, "mem.diff") {
		t.Fatalf("reattached source: tracked=%v gen=%d mem=%s", again.DirtyTracked, again.DirtyTrackingGeneration, again.MemFilePath)
	}
	if _, _, _, err := m2.PauseVM(ctx, inst.ID, "", "tok-test"); err != nil {
		t.Fatalf("pause after restart: %v", err)
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || expectedGenerationOf(t, bodies[1]) != 1 {
		t.Fatalf("the pause after a restart did not name generation 1: %v", bodies)
	}
	overlay := again.MemFilePath
	if !samePages(presentPages(t, overlay), 2, 3) {
		t.Fatalf("paused overlay names %v, want both diffs", presentPages(t, overlay))
	}
}

// The chain has moved on once the write is in: a reflink that fails after
// it fails the capture, not the chain.
func TestRunningCaptureAdvancesTheChainBeforeTheReflink(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'})
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, true)
	m.reflinkFile = func(context.Context, string, string) error { return errors.New("no space for a reflink") }
	id := uuid.NewString()
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, id, SavedSnapshotMemFS); err == nil {
		t.Fatal("a failed reflink must fail the capture")
	}
	overlay := filepath.Join(m.cfg.SnapshotDir, inst.ID, "mem.diff")
	inst.mu.RLock()
	memFile, gen, tracked, st := inst.MemFilePath, inst.DirtyTrackingGeneration, inst.DirtyTracked, inst.Status
	inst.mu.RUnlock()
	if memFile != overlay || gen != 1 || !tracked || st != StatusRunning {
		t.Fatalf("chain not advanced: mem=%s gen=%d tracked=%v status=%v", memFile, gen, tracked, st)
	}
	if rec, _ := m.state.Get(inst.ID); rec == nil || rec.DirtyTrackingGeneration != 1 {
		t.Fatalf("advance not persisted: %+v", rec)
	}
	if !samePages(presentPages(t, overlay), 2) {
		t.Fatal("the chain overlay does not hold the write")
	}
	dir, _ := m.savedSnapshotDir(id)
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed capture left a snapshot: %v", err)
	}
}

// A write whose outcome is unknown spends the baseline: the source keeps
// running, its next pause is a full one, and the torn overlay cannot be
// restored.
func TestRunningCaptureTimeoutAbandonsTheBaseline(t *testing.T) {
	fc := startChainFC(t)
	fc.hang = true
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, true)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS); err == nil {
		t.Fatal("a timed-out write must fail the capture")
	}
	inst.mu.RLock()
	tracked, session, st, memFile := inst.DirtyTracked, inst.DirtyTrackingSessionID, inst.Status, inst.MemFilePath
	inst.mu.RUnlock()
	if tracked || session != "" || st != StatusRunning {
		t.Fatalf("after a timeout: tracked=%v session=%q status=%v; want the baseline abandoned and the source running", tracked, session, st)
	}
	if memFile != inst.BaseMemPath {
		t.Fatalf("a failed first pass moved the record to %s", memFile)
	}
	overlay := filepath.Join(m.cfg.SnapshotDir, inst.ID, "mem.diff")
	for _, p := range []string{overlay, layeredBaseSidecarPath(overlay), presence.SidecarPath(overlay)} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left after a torn first pass: %v", filepath.Base(p), err)
		}
	}
}

// A guard Firecracker rejects means something else consumed the bitmap:
// the capture takes a full image of its own and the chain is untouched.
func TestRunningCaptureWithARejectedGuardTakesAFullImage(t *testing.T) {
	fc := startChainFC(t, map[int]byte{2: 'X'})
	fc.generation = 5
	m := newSavedTestManager(t)
	inst := seedRunningSource(t, m, fc, true)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(man.MemPath) != "mem.snap" || man.BaseMemPath != "" {
		t.Fatalf("want a full image of its own, got mem=%s base=%s", man.MemPath, man.BaseMemPath)
	}
	if pageAt(t, man.MemPath, 0) != 'F' {
		t.Fatal("the full image was not written")
	}
	bodies := fc.snapshotBodies()
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"snapshot_type":"Diff"`) || strings.Contains(bodies[1], `"snapshot_type":"Diff"`) {
		t.Fatalf("want a refused diff then a full, got %v", bodies)
	}
	inst.mu.RLock()
	tracked, memFile, gen := inst.DirtyTracked, inst.MemFilePath, inst.DirtyTrackingGeneration
	inst.mu.RUnlock()
	if tracked || memFile != inst.BaseMemPath || gen != 0 {
		t.Fatalf("after a full image: tracked=%v mem=%s gen=%d; want the baseline spent and the chain untouched", tracked, memFile, gen)
	}
	overlay := filepath.Join(m.cfg.SnapshotDir, inst.ID, "mem.diff")
	if _, err := os.Stat(layeredBaseSidecarPath(overlay)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a base record was left for an overlay that never followed: %v", err)
	}
}

func TestRunningCaptureHeadroomIsOneImage(t *testing.T) {
	m := newSavedTestManager(t)
	orig := savedFreeBytes
	t.Cleanup(func() { savedFreeBytes = orig })
	savedFreeBytes = func(string) (int64, error) { return int64(savedCaptureHeadroom) + 1<<30 + 1<<20, nil }
	inst := &VMInstance{ID: uuid.NewString(), Config: VMConfig{MemoryMiB: 1024}}
	release, err := m.savedCaptureHeadroom(SavedSnapshotMemFS, StatusRunning, inst)
	if status.Code(err) == codes.ResourceExhausted {
		t.Fatal("a running capture needs one guest's worth of space, not two")
	}
	if err != nil {
		t.Fatal(err)
	}
	release()
}
