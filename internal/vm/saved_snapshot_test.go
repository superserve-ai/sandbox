package vm

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/presence"
)

const testPage = 4096

func newSavedTestManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	m := &Manager{
		log: zerolog.Nop(),
		cfg: ManagerConfig{
			SnapshotDir: filepath.Join(root, "snapshots"),
			RunDir:      filepath.Join(root, "rundir"),
		},
		vms: map[string]*VMInstance{},
		// Every seeded source is at rest; the real probe needs systemd and cgroups.
		unitDead: func(context.Context, string) bool { return true },
		// The test filesystem may not reflink; the refusal has its own test.
		reflinkFile: cloneOrCopyFile,
	}
	if err := os.MkdirAll(m.cfg.SnapshotDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// pageFile writes a sparse file of npages pages with the given pages filled
// by fill(page), and a presence map naming exactly those pages.
func pageFile(t *testing.T, path string, npages int, pages map[int]byte, withPresence bool) {
	t.Helper()
	if err := createSparseFile(path, int64(npages*testPage)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	bits := make([]uint64, (npages+63)/64)
	for p, b := range pages {
		if _, err := f.WriteAt(bytes.Repeat([]byte{b}, testPage), int64(p*testPage)); err != nil {
			t.Fatal(err)
		}
		bits[p/64] |= 1 << (uint(p) % 64)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if withPresence {
		if err := presence.Write(path, testPage, uint64(npages), bits); err != nil {
			t.Fatal(err)
		}
	}
}

func pageAt(t *testing.T, path string, page int) byte {
	t.Helper()
	b := make([]byte, testPage)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.ReadAt(b, int64(page*testPage)); err != nil {
		t.Fatal(err)
	}
	return b[0]
}

func seedPausedSource(t *testing.T, m *Manager, layered bool) (*VMInstance, string) {
	t.Helper()
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
	pageFile(t, base, 4, map[int]byte{0: 'B', 1: 'B', 2: 'B', 3: 'B'}, false)
	baseDisk := filepath.Join(tplDir, "base.ext4")
	if err := os.WriteFile(baseDisk, []byte("base-disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	vmstate := filepath.Join(snapDir, "vmstate.snap")
	if err := os.WriteFile(vmstate, []byte("vmstate-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vmstate+".overlay", []byte("overlay-sidecar"), 0o644); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(runDir, "overlay.ext4")
	pageFile(t, overlay, 8, map[int]byte{3: 'D', 7: 'D'}, false)
	inst := &VMInstance{
		ID:           vmID,
		Status:       StatusPaused,
		SocketPath:   filepath.Join(runDir, "firecracker.sock"),
		SnapshotPath: vmstate,
		DiskPath:     overlay,
		Config:       VMConfig{VCPU: 1, MemoryMiB: 1024, DiskSizeMiB: 4096, BasePath: baseDisk},
	}
	if layered {
		mem := filepath.Join(snapDir, "mem.diff")
		pageFile(t, mem, 4, map[int]byte{1: 'S'}, true)
		if err := os.WriteFile(layeredBaseSidecarPath(mem), []byte(base), 0o644); err != nil {
			t.Fatal(err)
		}
		inst.MemFilePath, inst.BaseMemPath = mem, base
	} else {
		mem := filepath.Join(snapDir, "mem.snap")
		pageFile(t, mem, 4, map[int]byte{0: 'F', 1: 'F', 2: 'F', 3: 'F'}, false)
		inst.MemFilePath = mem
	}
	m.vms[vmID] = inst
	return inst, base
}

func TestSavedSnapshotDirRejectsBadIDs(t *testing.T) {
	m := newSavedTestManager(t)
	for _, id := range []string{"", "not-a-uuid", "../" + uuid.NewString(), uuid.NewString() + "/x"} {
		if _, err := m.savedSnapshotDir(id); status.Code(err) != codes.InvalidArgument {
			t.Errorf("id %q: want InvalidArgument, got %v", id, err)
		}
	}
	if _, err := m.CreateSavedSnapshot(context.Background(), uuid.NewString(), uuid.NewString(), "ram"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad kind: want InvalidArgument, got %v", err)
	}
}

func TestCreateSavedSnapshotPausedLayered(t *testing.T) {
	m := newSavedTestManager(t)
	inst, base := seedPausedSource(t, m, true)
	ctx := context.Background()
	id := uuid.NewString()

	man, err := m.CreateSavedSnapshot(ctx, inst.ID, id, SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, id)
	if man.MemPath != filepath.Join(dir, "mem.diff") || man.BaseMemPath != base ||
		man.SnapshotPath != filepath.Join(dir, "vmstate.snap") || man.DiskPath != filepath.Join(dir, "overlay.ext4") ||
		man.BasePath != inst.Config.BasePath || man.VCPU != 1 || man.MemoryMiB != 1024 || man.SizeBytes == 0 {
		t.Fatalf("manifest: %+v", man)
	}
	for _, f := range []string{"vmstate.snap", "vmstate.snap.overlay", "mem.diff", "mem.diff.presence", "mem.diff.base", "overlay.ext4", savedSnapshotManifestName} {
		if !fileExists(filepath.Join(dir, f)) {
			t.Errorf("missing %s", f)
		}
	}
	if got := pageAt(t, man.MemPath, 1); got != 'S' {
		t.Errorf("mem page 1 = %q, want S", got)
	}
	if got := pageAt(t, man.DiskPath, 7); got != 'D' {
		t.Errorf("disk page 7 = %q, want D", got)
	}
	if b, _ := os.ReadFile(layeredBaseSidecarPath(man.MemPath)); string(b) != base {
		t.Errorf("base record = %q", b)
	}
	p, err := presence.Read(man.MemPath)
	if err != nil || !p.IsSet(1) || p.IsSet(0) {
		t.Errorf("presence: %v %+v", err, p)
	}
	// The source's own files are untouched.
	if got := pageAt(t, inst.MemFilePath, 1); got != 'S' {
		t.Errorf("source mem page 1 = %q", got)
	}

	// A retry returns the committed manifest without capturing again.
	before, _ := os.Stat(filepath.Join(dir, savedSnapshotManifestName))
	again, err := m.CreateSavedSnapshot(ctx, inst.ID, id, SavedSnapshotMemFS)
	if err != nil || again.CreatedAt != man.CreatedAt {
		t.Fatalf("retry: %v %+v", err, again)
	}
	after, _ := os.Stat(filepath.Join(dir, savedSnapshotManifestName))
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("retry rewrote the manifest")
	}
	// The same id for another source, or for another kind, is refused.
	if _, err := m.CreateSavedSnapshot(ctx, uuid.NewString(), id, SavedSnapshotMemFS); status.Code(err) != codes.AlreadyExists {
		t.Errorf("foreign retry: want AlreadyExists, got %v", err)
	}
	if _, err := m.CreateSavedSnapshot(ctx, inst.ID, id, SavedSnapshotFS); status.Code(err) != codes.AlreadyExists {
		t.Errorf("retry with another kind: want AlreadyExists, got %v", err)
	}

	if err := m.DeleteSavedSnapshot(ctx, id); err != nil {
		t.Fatal(err)
	}
	if fileExists(dir) {
		t.Error("directory survived delete")
	}
	if err := m.DeleteSavedSnapshot(ctx, id); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

func TestCreateSavedSnapshotPausedFSOnly(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	if man.MemPath != "" || man.SnapshotPath != "" || man.BaseMemPath != "" {
		t.Fatalf("fs snapshot carries memory: %+v", man)
	}
	// The seeded overlay is 8 pages; the size is the file's, not the config's.
	if man.DiskSizeMiB != 1 {
		t.Errorf("disk size %d MiB, want 1 from the file", man.DiskSizeMiB)
	}
	entries, _ := os.ReadDir(filepath.Dir(man.DiskPath))
	if len(entries) != 2 {
		t.Errorf("want disk and manifest only, got %d entries", len(entries))
	}
	if got := pageAt(t, man.DiskPath, 3); got != 'D' {
		t.Errorf("disk page 3 = %q", got)
	}
}

func TestCreateSavedSnapshotRefusesOtherStates(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	inst.Status = StatusError
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("want FailedPrecondition, got %v", err)
	}
	if _, err := m.CreateSavedSnapshot(context.Background(), uuid.NewString(), uuid.NewString(), SavedSnapshotFS); status.Code(err) != codes.NotFound {
		t.Errorf("unknown vm: want NotFound, got %v", err)
	}
}

func TestAccumulateSavedMemory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	base := filepath.Join(root, "base.snap")
	pageFile(t, base, 4, map[int]byte{0: 'B', 1: 'B', 2: 'B', 3: 'B'}, false)

	t.Run("accumulating pass unions the overlay and the diff", func(t *testing.T) {
		tmp := t.TempDir()
		overlay := filepath.Join(t.TempDir(), "mem.diff")
		pageFile(t, overlay, 4, map[int]byte{1: 'S'}, true)
		raw := filepath.Join(tmp, "mem.capture.diff")
		pageFile(t, raw, 4, map[int]byte{2: 'N'}, true)
		// Page 1 was dirtied to all zeros: present in the map, a hole in the
		// file. It must overwrite the overlay's 'S'.
		if err := presence.Write(raw, testPage, 4, []uint64{1<<1 | 1<<2}); err != nil {
			t.Fatal(err)
		}
		var man SavedSnapshotManifest
		if err := accumulateSavedMemory(ctx, tmp, "/final", overlay, base, raw, &man); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "mem.diff")
		if pageAt(t, target, 1) != 0 || pageAt(t, target, 2) != 'N' || pageAt(t, target, 0) != 0 {
			t.Error("accumulated pages wrong")
		}
		p, err := presence.Read(target)
		if err != nil || !p.IsSet(1) || !p.IsSet(2) || p.IsSet(0) || p.IsSet(3) {
			t.Errorf("presence: %v %+v", err, p)
		}
		if b, _ := os.ReadFile(layeredBaseSidecarPath(target)); string(b) != base {
			t.Errorf("base record = %q", b)
		}
		if man.MemPath != "/final/mem.diff" || man.BaseMemPath != base {
			t.Errorf("manifest: %+v", man)
		}
		if fileExists(raw) {
			t.Error("raw diff left behind")
		}
	})

	t.Run("first pass over the template base is the diff alone", func(t *testing.T) {
		tmp := t.TempDir()
		raw := filepath.Join(tmp, "mem.capture.diff")
		pageFile(t, raw, 4, map[int]byte{3: 'N'}, true)
		var man SavedSnapshotManifest
		if err := accumulateSavedMemory(ctx, tmp, "/final", base, base, raw, &man); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "mem.diff")
		if pageAt(t, target, 3) != 'N' || pageAt(t, target, 0) != 0 {
			t.Error("first-pass pages wrong")
		}
		p, _ := presence.Read(target)
		if !p.IsSet(3) || p.IsSet(0) {
			t.Errorf("presence: %+v", p)
		}
	})

	t.Run("standalone image stays a full image", func(t *testing.T) {
		tmp := t.TempDir()
		full := filepath.Join(t.TempDir(), "mem.snap")
		pageFile(t, full, 4, map[int]byte{0: 'F', 1: 'F', 2: 'F', 3: 'F'}, false)
		raw := filepath.Join(tmp, "mem.capture.diff")
		pageFile(t, raw, 4, map[int]byte{2: 'N'}, true)
		var man SavedSnapshotManifest
		if err := accumulateSavedMemory(ctx, tmp, "/final", full, "", raw, &man); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "mem.snap")
		if pageAt(t, target, 2) != 'N' || pageAt(t, target, 1) != 'F' {
			t.Error("merged full image wrong")
		}
		if man.MemPath != "/final/mem.snap" || man.BaseMemPath != "" {
			t.Errorf("manifest: %+v", man)
		}
	})
}

func TestCloneOrCopyFileKeepsHoles(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	pageFile(t, src, 64, map[int]byte{5: 'X', 63: 'Y'}, false)
	dst := filepath.Join(root, "dst")
	if err := cloneOrCopyFile(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	si, _ := os.Stat(src)
	di, _ := os.Stat(dst)
	if si.Size() != di.Size() {
		t.Fatalf("size %d != %d", di.Size(), si.Size())
	}
	if pageAt(t, dst, 5) != 'X' || pageAt(t, dst, 63) != 'Y' || pageAt(t, dst, 6) != 0 {
		t.Error("content mismatch")
	}
	if n, _ := allocatedBytes(dst); n >= si.Size() {
		t.Errorf("copy is not sparse: %d allocated of %d", n, si.Size())
	}
}

func TestCreateSavedSnapshotRefusesSourceNotAtRest(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	m.unitDead = func(context.Context, string) bool { return false }
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS); status.Code(err) != codes.Unavailable {
		t.Errorf("want Unavailable, got %v", err)
	}
}

func TestSavedSnapshotIDLockSerializesDelete(t *testing.T) {
	m := newSavedTestManager(t)
	id := uuid.NewString()
	unlock, err := m.lockSavedSnapshot(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.DeleteSavedSnapshot(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("delete during a capture of the same id: want deadline exceeded, got %v", err)
	}
	unlock()
	if err := m.DeleteSavedSnapshot(context.Background(), id); err != nil {
		t.Errorf("delete after release: %v", err)
	}
}

func TestOverlayCaptureRefusesWithoutReflink(t *testing.T) {
	m := newSavedTestManager(t)
	m.reflinkFile = nil
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reflinkFileExact(context.Background(), probe, probe+".clone"); err == nil {
		t.Skip("test filesystem reflinks; the refusal cannot be exercised here")
	}
	inst, _ := seedPausedSource(t, m, false)
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("overlay capture without reflink: want FailedPrecondition, got %v", err)
	}
}

func TestSavedSnapshotIDLockIsReclaimed(t *testing.T) {
	m := newSavedTestManager(t)
	id := uuid.NewString()
	unlock, err := m.lockSavedSnapshot(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	m.savedIDMu.Lock()
	n := len(m.savedIDLocks)
	m.savedIDMu.Unlock()
	if n != 0 {
		t.Errorf("lock entries left after release: %d", n)
	}
}

func TestSweepSavedSnapshotStaging(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName)
	for _, d := range []string{"." + uuid.NewString() + ".tmp-" + uuid.NewString(), "." + uuid.NewString() + ".tmp-x"} {
		if err := os.MkdirAll(filepath.Join(root, d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	done := m.SweepSavedSnapshotStaging(zerolog.Nop())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background sweep did not finish")
	}
	if !fileExists(man.DiskPath) {
		t.Error("committed snapshot was swept")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Errorf("want only the committed snapshot left, got %d entries", len(entries))
	}
}

func TestCommittedRetryWaitsForTheIDLock(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	id := uuid.NewString()
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, id, SavedSnapshotFS); err != nil {
		t.Fatal(err)
	}
	unlock, err := m.lockSavedSnapshot(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.CreateSavedSnapshot(ctx, inst.ID, id, SavedSnapshotFS); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("retry while the id is locked: want deadline exceeded, got %v", err)
	}
	unlock()
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, id, SavedSnapshotFS); err != nil {
		t.Errorf("retry after release: %v", err)
	}
}

func TestCopyHonoursCancellation(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	pageFile(t, src, 16, map[int]byte{0: 'X', 15: 'Y'}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cloneOrCopyFile(ctx, src, filepath.Join(root, "dst")); !errors.Is(err, context.Canceled) {
		t.Errorf("copy with a cancelled context: want Canceled, got %v", err)
	}
}

func TestPlanRestoreMaterializesFork(t *testing.T) {
	if p := planRestore("/base.ext4", "/delta", true, false); p.action != restoreMaterializeFork || p.deltaDir != "" {
		t.Errorf("fork with base: %+v", p)
	}
	if p := planRestore("", "", true, false); p.action != restoreMaterializeFork {
		t.Errorf("fork of a standalone disk: %+v", p)
	}
	if p := planRestore("/base.ext4", "", true, true); p.action != restoreMaterializeFork {
		t.Errorf("a fork retry takes fresh copies: %+v", p)
	}
}

func TestCloneSavedDiskGivesTheVMItsOwnCopy(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	disk, err := m.cloneSavedDisk(context.Background(), child, man.DiskPath, man.BasePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk != filepath.Join(m.cfg.RunDir, child, "overlay.ext4") || pageAt(t, disk, 7) != 'D' {
		t.Errorf("clone: path %s", disk)
	}
	// The child's writes never reach the snapshot.
	f, err := os.OpenFile(disk, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{'C'}, 7*testPage); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if pageAt(t, man.DiskPath, 7) != 'D' {
		t.Error("snapshot disk changed under the child's write")
	}
}

func TestCloneSavedDiskLeavesNoPartialFile(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	m.reflinkFile = func(_ context.Context, _, dst string) error {
		if err := os.WriteFile(dst, []byte("partial"), 0o644); err != nil {
			return err
		}
		return errors.New("disk full")
	}
	child := uuid.NewString()
	if _, err := m.cloneSavedDisk(context.Background(), child, man.DiskPath, man.BasePath); err == nil {
		t.Fatal("clone should fail")
	}
	if fileExists(filepath.Join(m.cfg.RunDir, child, "overlay.ext4")) {
		t.Error("partial clone left behind for a retry to adopt")
	}
}

func TestCaptureQueuedOnABusyVMHoldsNoSlot(t *testing.T) {
	m := newSavedTestManager(t)
	m.cfg.SavedSnapshotConcurrency = 1
	inst, _ := seedPausedSource(t, m, false)
	release, err := m.acquireSavedCapture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	busy := uuid.NewString()
	unlockBusy, err := m.lockVMOp(context.Background(), busy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		_, _ = m.CreateSavedSnapshot(ctx, busy, uuid.NewString(), SavedSnapshotFS)
	}()
	// A slot taken on the way to the VM lock stays taken until the lock
	// frees, so a short wait is enough to see it.
	time.Sleep(100 * time.Millisecond)
	if n := len(m.savedCaptures); n != 0 {
		t.Fatalf("%d slot(s) held by a request still waiting for its VM lock", n)
	}
	tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer tcancel()
	if _, err := m.CreateSavedSnapshot(tctx, inst.ID, uuid.NewString(), SavedSnapshotFS); err != nil {
		t.Fatalf("capture of an idle VM behind a queued request for another: %v", err)
	}
	cancel()
	unlockBusy()
	<-queued
}

func TestRestoreDiscardsAFailedFork(t *testing.T) {
	m := newSavedTestManager(t)
	m.restoreSem = make(chan struct{}, 1)
	inst, _ := seedPausedSource(t, m, true)
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	// The memory copies succeed; the disk, copied last, fails.
	m.reflinkFile = func(ctx context.Context, src, dst string) error {
		if filepath.Base(dst) == "overlay.ext4" {
			_ = os.WriteFile(dst, []byte("partial"), 0o644)
			return errors.New("disk full")
		}
		return cloneOrCopyFile(ctx, src, dst)
	}
	child := uuid.NewString()
	cfg := VMConfig{VCPU: man.VCPU, MemoryMiB: man.MemoryMiB, SavedSnapshotID: man.SnapshotID}
	if _, err := m.restoreVMSnapshot(context.Background(), child, "", "", cfg, nil, "", "", "", nil, 0, ""); err == nil {
		t.Fatal("restore should fail with the disk clone")
	}
	for _, dir := range []string{filepath.Join(m.cfg.RunDir, child), filepath.Join(m.cfg.SnapshotDir, child)} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the failed fork, so a retry would reuse files that were never finished: %v", dir, err)
		}
	}
}

func TestForkHoldsTheSnapshotLockWhileItCopies(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	m.reflinkFile = func(ctx context.Context, src, dst string) error {
		once.Do(func() { close(entered) })
		<-gate
		return cloneOrCopyFile(ctx, src, dst)
	}
	child := uuid.NewString()
	forkDone := make(chan error, 1)
	go func() {
		_, err := m.materializeFork(ctx, child, man)
		forkDone <- err
	}()
	<-entered
	delDone := make(chan error, 1)
	go func() { delDone <- m.DeleteSavedSnapshot(ctx, man.SnapshotID) }()
	select {
	case err := <-delDone:
		t.Fatalf("delete finished (%v) while the fork was still copying", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	if err := <-forkDone; err != nil {
		t.Fatalf("fork: %v", err)
	}
	if err := <-delDone; err != nil {
		t.Fatalf("delete after the fork: %v", err)
	}
	// The VM owns everything it will use, and the snapshot is gone.
	own := filepath.Join(m.cfg.SnapshotDir, child)
	for _, f := range []string{"vmstate.snap", "mem.diff", "mem.diff.presence", "mem.diff.base"} {
		if !fileExists(filepath.Join(own, f)) {
			t.Errorf("the VM lacks its own %s", f)
		}
	}
	if pageAt(t, filepath.Join(own, "mem.diff"), 1) != 'S' {
		t.Error("the VM's memory copy differs from the snapshot")
	}
	if pageAt(t, filepath.Join(m.cfg.RunDir, child, "overlay.ext4"), 7) != 'D' {
		t.Error("the VM's disk copy differs from the snapshot")
	}
	if _, err := os.Stat(filepath.Dir(man.DiskPath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot dir survived its delete: %v", err)
	}
}

func TestForkAfterDeleteIsNotFound(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteSavedSnapshot(ctx, man.SnapshotID); err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	if _, err := m.materializeFork(ctx, child, man); status.Code(err) != codes.NotFound {
		t.Fatalf("fork of a deleted snapshot: want NotFound, got %v", err)
	}
	cfg := VMConfig{SavedSnapshotID: man.SnapshotID}
	if _, _, _, err := m.forkSource(child, &cfg, "", ""); status.Code(err) != codes.NotFound {
		t.Errorf("resolving a deleted snapshot: want NotFound, got %v", err)
	}
}

func TestForkSourceFixesTheVMsOwnPaths(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	cfg := VMConfig{SavedSnapshotID: man.SnapshotID}
	got, vmstate, mem, err := m.forkSource(child, &cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(m.cfg.SnapshotDir, child)
	if got.SnapshotID != man.SnapshotID || vmstate != filepath.Join(own, "vmstate.snap") || mem != filepath.Join(own, "mem.diff") || cfg.BasePath != man.BasePath {
		t.Errorf("vmstate=%s mem=%s base=%s", vmstate, mem, cfg.BasePath)
	}
	// The request may not name files of its own, nor another base.
	if _, _, _, err := m.forkSource(child, &VMConfig{SavedSnapshotID: man.SnapshotID}, man.SnapshotPath, man.MemPath); status.Code(err) != codes.InvalidArgument {
		t.Errorf("request naming the snapshot's files: want InvalidArgument, got %v", err)
	}
	if _, _, _, err := m.forkSource(child, &VMConfig{SavedSnapshotID: man.SnapshotID, BasePath: "/elsewhere/base.ext4"}, "", ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("request naming another base: want InvalidArgument, got %v", err)
	}
	// An fs snapshot has nothing to restore warm from.
	fs, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.forkSource(child, &VMConfig{SavedSnapshotID: fs.SnapshotID}, "", ""); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("warm fork of an fs snapshot: want FailedPrecondition, got %v", err)
	}
}

func TestSweepLeavesALiveCaptureStagingAlone(t *testing.T) {
	m := newSavedTestManager(t)
	id := uuid.NewString()
	dir := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, "."+id+".tmp-"+uuid.NewString())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	unlock, err := m.lockSavedSnapshot(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	done := m.SweepSavedSnapshotStaging(zerolog.Nop())
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("staging of a capture holding its id lock was swept: %v", err)
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sweep did not finish after the lock was released")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("abandoned staging survived the sweep: %v", err)
	}
}

func TestSavedSnapshotDiskSizeSurvivesReattach(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	// A reattached VM's config carries no disk size.
	inst.Config.DiskSizeMiB = 0
	man, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS)
	if err != nil {
		t.Fatal(err)
	}
	if man.DiskSizeMiB == 0 {
		t.Error("disk size lost across reattach")
	}
}

func TestRecoveryKeepsTheSourceImageManifestAfterAStagedCapture(t *testing.T) {
	raiseFloorForTest(t)
	m := newSavedTestManager(t)
	vmDir := filepath.Join(m.cfg.SnapshotDir, "vm-1")
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := filepath.Join(vmDir, "mem.diff")
	frozen := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: "resume", WorkloadFrozen: true, FreezeToken: "tok"}
	if err := WriteWallClockManifest(mem, frozen); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1"}
	if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", ArtifactID: "capture", Staged: true}); err != nil {
		t.Fatal(err)
	}
	if !m.recoverPauseIntent(context.Background(), inst, zerolog.Nop()) {
		t.Fatal("recovery after a staged capture failed")
	}
	if !fileExists(WallClockMarkerPath(mem)) {
		t.Fatal("a staged capture's recovery stripped the manifest the source image still needs")
	}
	// An interrupted in-place rewrite still strips it.
	if err := writePauseIntent(vmDir, pauseIntent{VMID: "vm-1", ArtifactID: "rewrite"}); err != nil {
		t.Fatal(err)
	}
	if !m.recoverPauseIntent(context.Background(), inst, zerolog.Nop()) {
		t.Fatal("recovery after a rewrite failed")
	}
	if fileExists(WallClockMarkerPath(mem)) {
		t.Error("an interrupted rewrite's stale manifest survived")
	}
}

func TestStandaloneSavedDiskRestoreRefusesWithoutReflink(t *testing.T) {
	m := newSavedTestManager(t)
	m.reflinkFile = nil
	saved := filepath.Join(m.cfg.SnapshotDir, "rootfs.ext4")
	if err := os.WriteFile(saved, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reflinkFileExact(context.Background(), saved, saved+".clone"); err == nil {
		t.Skip("test filesystem reflinks; the refusal cannot be exercised here")
	}
	if _, err := m.cloneSavedDisk(context.Background(), uuid.NewString(), saved, ""); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("standalone restore without reflink: want FailedPrecondition, got %v", err)
	}
}

func TestSavedCaptureHeadroomIsReservedAcrossCaptures(t *testing.T) {
	orig := savedFreeBytes
	t.Cleanup(func() { savedFreeBytes = orig })
	savedFreeBytes = func(string) (int64, error) { return 4 << 30, nil }
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	// A running capture reserves twice its memory: one fits in 4 GiB with
	// the fixed headroom, two do not.
	inst.Config.MemoryMiB = 1000
	first, err := m.savedCaptureHeadroom(SavedSnapshotMemFS, StatusRunning, inst)
	if err != nil {
		t.Fatalf("first capture: %v", err)
	}
	if _, err := m.savedCaptureHeadroom(SavedSnapshotMemFS, StatusRunning, inst); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second capture against the same free space: want ResourceExhausted, got %v", err)
	}
	first()
	second, err := m.savedCaptureHeadroom(SavedSnapshotMemFS, StatusRunning, inst)
	if err != nil {
		t.Fatalf("capture after the first released: %v", err)
	}
	second()
	if got := m.savedReserved.Load(); got != 0 {
		t.Errorf("reservation leaked: %d bytes", got)
	}
}

func TestStandaloneCaptureRefusesWithoutReflink(t *testing.T) {
	m := newSavedTestManager(t)
	m.reflinkFile = nil
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := reflinkFileExact(context.Background(), probe, probe+".clone"); err == nil {
		t.Skip("test filesystem reflinks; the refusal cannot be exercised here")
	}
	inst, _ := seedPausedSource(t, m, false)
	inst.Config.BasePath = ""
	inst.DiskPath = filepath.Join(m.cfg.RunDir, inst.ID, "overlay.ext4")
	if _, err := m.CreateSavedSnapshot(context.Background(), inst.ID, uuid.NewString(), SavedSnapshotFS); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("standalone capture without reflink: want FailedPrecondition, got %v", err)
	}
}

func TestForkOfAFrozenSnapshotOwesItsWake(t *testing.T) {
	useTempFloor(t)
	m := newSavedTestManager(t)
	m.restoreSem = make(chan struct{}, 1)
	m.netMgr = &fakeNetMgr{}
	src, _ := seedPausedSource(t, m, false)
	seedFrozenManifest(t, src.MemFilePath, "saved-token")
	man, err := m.CreateSavedSnapshot(context.Background(), src.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	launched, frozen, token := false, false, ""
	m.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		launched = true
		m.mu.RLock()
		in := m.vms[child]
		m.mu.RUnlock()
		in.mu.RLock()
		frozen = in.SnapshotWorkloadFrozen != nil && *in.SnapshotWorkloadFrozen
		token = in.FreezeToken
		in.mu.RUnlock()
		if !fileExists(WallClockMarkerPath(filepath.Join(m.cfg.SnapshotDir, child, "mem.snap"))) {
			t.Error("the VM's own manifest was not in place before the launch")
		}
		return 0, SupervisionUnit, errors.New("stop before a real launch")
	}
	_, _ = m.restoreVMSnapshot(context.Background(), child, "", "", VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: man.SnapshotID}, nil, "", "", "", nil, 0, "")
	if !launched {
		t.Fatal("restore did not reach the launch")
	}
	if !frozen || token != "saved-token" {
		t.Fatalf("frozen=%v token=%q; want the snapshot's freeze carried into the launch", frozen, token)
	}
}

func TestStrictPresenceForkValidatesTheSnapshotItself(t *testing.T) {
	useTempFloor(t)
	m := newSavedTestManager(t)
	m.restoreSem = make(chan struct{}, 1)
	m.cfg.RequirePresenceSidecar = "always"
	src, _ := seedPausedSource(t, m, true)
	man, err := m.CreateSavedSnapshot(context.Background(), src.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	clones := 0
	m.reflinkFile = func(context.Context, string, string) error {
		clones++
		return errors.New("stop at the first copy")
	}
	_, err = m.restoreVMSnapshot(context.Background(), uuid.NewString(), "", "", VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: man.SnapshotID}, nil, "", "", "", nil, 0, "")
	if clones == 0 {
		t.Fatalf("a valid layered snapshot was refused before any copy: %v", err)
	}
}

func TestCompletedForkRetryOutlivesItsSource(t *testing.T) {
	useTempFloor(t)
	m := newSavedTestManager(t)
	m.restoreSem = make(chan struct{}, 1)
	src, _ := seedPausedSource(t, m, false)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, src.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	cfg := VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: man.SnapshotID}
	_, snap, mem, err := m.forkSource(child, &cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	disk, err := m.materializeFork(ctx, child, man)
	if err != nil {
		t.Fatal(err)
	}
	// The completed fork whose response was lost.
	existing := &VMInstance{ID: child, Status: StatusRunning, SourceSnapshotID: man.SnapshotID, SnapshotPath: snap, MemFilePath: mem, DiskPath: disk, Config: cfg}
	m.mu.Lock()
	m.vms[child] = existing
	m.mu.Unlock()
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false }
	t.Cleanup(func() { vmDeadForRetry = orig })
	request := VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: man.SnapshotID}
	if got, err := m.restoreVMSnapshot(ctx, child, "", "", request, nil, "", "", "", nil, 0, ""); err != nil || got != existing {
		t.Fatalf("retry with the snapshot present: got %v, %v", got, err)
	}
	if err := m.DeleteSavedSnapshot(ctx, man.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if got, err := m.restoreVMSnapshot(ctx, child, "", "", request, nil, "", "", "", nil, 0, ""); err != nil || got != existing {
		t.Fatalf("retry after the snapshot was deleted: got %v, %v", got, err)
	}
	// The same child asked for from another snapshot is not this retry.
	other := VMConfig{VCPU: 1, MemoryMiB: 1024, SavedSnapshotID: uuid.NewString()}
	if got, _ := m.restoreVMSnapshot(ctx, child, "", "", other, nil, "", "", "", nil, 0, ""); got == existing {
		t.Fatal("a request for another snapshot adopted the child of this one")
	}
}

func TestForkSourceSurvivesTheRecord(t *testing.T) {
	inst := &VMInstance{ID: "vm-1", SourceSnapshotID: "snap-1"}
	if got := toInstance(toRecord(inst)); got.SourceSnapshotID != "snap-1" {
		t.Errorf("source snapshot lost across the record: %q", got.SourceSnapshotID)
	}
}

func TestSavedCaptureBudgetScalesWithMemory(t *testing.T) {
	if got := savedCaptureBudget(SavedSnapshotFS, 16384); got != savedCaptureBaseBudget {
		t.Errorf("fs capture budget %s, want the base", got)
	}
	if got := savedCaptureBudget(SavedSnapshotMemFS, 1024); got != savedCaptureBaseBudget+16*time.Second {
		t.Errorf("1 GiB memory capture budget %s", got)
	}
	if got := savedCaptureBudget(SavedSnapshotMemFS, 16384); got != savedCaptureBaseBudget+256*time.Second {
		t.Errorf("16 GiB memory capture budget %s", got)
	}
}

func TestAwaitFirecrackerOutlastsABusyAPI(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ready:
			_, _ = w.Write([]byte(`{"state":"Paused"}`))
		case <-r.Context().Done():
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	// Still busy: the wait gives up on its own bound, not before.
	start := time.Now()
	if err := awaitFirecracker(context.Background(), sock, 2*time.Second); err == nil {
		t.Fatal("wait returned before the API answered")
	}
	if time.Since(start) < 2*time.Second {
		t.Fatal("wait gave up before its bound")
	}
	// Done a moment later: the wait returns as soon as the API answers.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		close(ready)
	}()
	start = time.Now()
	if err := awaitFirecracker(context.Background(), sock, 30*time.Second); err != nil {
		t.Fatalf("wait after the API came back: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("wait took %s after a 1.5s recovery", d)
	}
}

func TestForkSourceTakesResourcesFromTheSnapshot(t *testing.T) {
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, inst.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	cfg := VMConfig{SavedSnapshotID: man.SnapshotID}
	if _, _, _, err := m.forkSource(uuid.NewString(), &cfg, "", ""); err != nil {
		t.Fatal(err)
	}
	if cfg.VCPU != man.VCPU || cfg.MemoryMiB != man.MemoryMiB || cfg.DiskSizeMiB != man.DiskSizeMiB {
		t.Errorf("config %+v does not carry the snapshot's shape %d/%d/%d", cfg, man.VCPU, man.MemoryMiB, man.DiskSizeMiB)
	}
	small := VMConfig{SavedSnapshotID: man.SnapshotID, VCPU: man.VCPU, MemoryMiB: man.MemoryMiB / 2}
	if _, _, _, err := m.forkSource(uuid.NewString(), &small, "", ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("request with another memory size: want InvalidArgument, got %v", err)
	}
}

func TestForkRefusesASnapshotReplacedUnderItsId(t *testing.T) {
	m := newSavedTestManager(t)
	first, _ := seedPausedSource(t, m, true)
	second, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	id := uuid.NewString()
	man, err := m.CreateSavedSnapshot(ctx, first.ID, id, SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	child := uuid.NewString()
	cfg := VMConfig{SavedSnapshotID: id}
	if _, _, _, err := m.forkSource(child, &cfg, "", ""); err != nil {
		t.Fatal(err)
	}
	// Between the read and the copy: the id is deleted and captured again
	// from another sandbox.
	if err := m.DeleteSavedSnapshot(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateSavedSnapshot(ctx, second.ID, id, SavedSnapshotMemFS); err != nil {
		t.Fatal(err)
	}
	if _, err := m.materializeFork(ctx, child, man); status.Code(err) != codes.NotFound {
		t.Fatalf("fork from a manifest the id no longer describes: want NotFound, got %v", err)
	}
	for _, dir := range []string{filepath.Join(m.cfg.RunDir, child), filepath.Join(m.cfg.SnapshotDir, child)} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind by a refused fork", dir)
		}
	}
}

func TestForkOverALiveVMRefusesWhenTheStopIsNotConfirmed(t *testing.T) {
	useTempFloor(t)
	m := newSavedTestManager(t)
	m.restoreSem = make(chan struct{}, 1)
	src, _ := seedPausedSource(t, m, true)
	ctx := context.Background()
	man, err := m.CreateSavedSnapshot(ctx, src.ID, uuid.NewString(), SavedSnapshotMemFS)
	if err != nil {
		t.Fatal(err)
	}
	// A running VM already owns the id, from another image, and its stop
	// does not confirm.
	child := uuid.NewString()
	rundir := filepath.Join(m.cfg.RunDir, child)
	if err := os.MkdirAll(rundir, 0o755); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(rundir, "overlay.ext4")
	if err := os.WriteFile(overlay, []byte("live disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.vms[child] = &VMInstance{ID: child, Status: StatusRunning, Supervision: SupervisionUnit, DiskPath: overlay, SnapshotPath: "/elsewhere/vmstate.snap", MemFilePath: "/elsewhere/mem.snap"}
	m.mu.Unlock()
	m.stopVMHook = func(context.Context, string, Supervision) error { return errors.New("unit still active") }
	_, err = m.restoreVMSnapshot(ctx, child, "", "", VMConfig{SavedSnapshotID: man.SnapshotID}, nil, "", "", "", nil, 0, "")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("fork over a VM whose stop did not confirm: want Unavailable, got %v", err)
	}
	if b, _ := os.ReadFile(overlay); string(b) != "live disk" {
		t.Fatal("the live VM's disk was replaced")
	}
	if _, err := os.Stat(rundir); err != nil {
		t.Fatal("the live VM's run dir was removed")
	}
	m.mu.RLock()
	inst := m.vms[child]
	m.mu.RUnlock()
	if inst == nil || inst.Status != StatusError {
		t.Fatalf("the id is not parked as error: %+v", inst)
	}
}

func TestSavedCaptureHeadroomReservesNothingForReflinkedImages(t *testing.T) {
	orig := savedFreeBytes
	t.Cleanup(func() { savedFreeBytes = orig })
	savedFreeBytes = func(string) (int64, error) { return 300 << 20, nil }
	m := newSavedTestManager(t)
	inst, _ := seedPausedSource(t, m, false)
	inst.Config.MemoryMiB = 16384
	inst.Config.DiskSizeMiB = 102400
	for _, kind := range []SavedSnapshotKind{SavedSnapshotFS, SavedSnapshotMemFS} {
		release, err := m.savedCaptureHeadroom(kind, StatusPaused, inst)
		if err != nil {
			t.Fatalf("paused %s capture with little free space: %v", kind, err)
		}
		release()
	}
	if _, err := m.savedCaptureHeadroom(SavedSnapshotMemFS, StatusRunning, inst); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("running memory capture with little free space: want ResourceExhausted, got %v", err)
	}
}
