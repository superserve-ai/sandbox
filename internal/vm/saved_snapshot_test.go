package vm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
			KernelPath:  "/kernel/vmlinux",
		},
		vms: map[string]*VMInstance{},
		// Every seeded source is at rest; the real probe needs systemd and cgroups.
		unitDead: func(context.Context, string) bool { return true },
		// The test filesystem may not reflink; the refusal has its own test.
		reflinkOverlay: cloneOrCopyFile,
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
	// The same id for another source is refused.
	if _, err := m.CreateSavedSnapshot(ctx, uuid.NewString(), id, SavedSnapshotMemFS); status.Code(err) != codes.AlreadyExists {
		t.Errorf("foreign retry: want AlreadyExists, got %v", err)
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
	m.reflinkOverlay = nil
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
	n, done := m.SweepSavedSnapshotStaging(zerolog.Nop())
	if n != 2 {
		t.Errorf("found %d staging dirs, want 2", n)
	}
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

func TestPlanRestoreClonesSavedDisk(t *testing.T) {
	if p := planRestore("/base.ext4", "/delta", "/saved/overlay.ext4", false); p.action != restoreCloneSavedDisk || p.deltaDir != "" {
		t.Errorf("saved disk with base: %+v", p)
	}
	if p := planRestore("", "", "/saved/rootfs.ext4", false); p.action != restoreCloneSavedDisk {
		t.Errorf("saved standalone disk: %+v", p)
	}
	if p := planRestore("/base.ext4", "", "/saved/overlay.ext4", true); p.action != restoreReuseOverlay {
		t.Errorf("in-place retry keeps its own overlay: %+v", p)
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
	m.reflinkOverlay = func(_ context.Context, _, dst string) error {
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
