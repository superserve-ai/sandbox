//go:build linux

package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	"golang.org/x/sys/unix"
)

func TestRetainedFullCopyCreatePauseBeforeInventoryAndRestart(t *testing.T) {
	useTempFloor(t)
	origProbe := boxdHealthProbe
	boxdHealthProbe = func(context.Context, string, time.Duration) error { return nil }
	t.Cleanup(func() { boxdHealthProbe = origProbe })
	root := t.TempDir()
	statePath := filepath.Join(root, "state.db")
	state, err := OpenStateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	templateID, id := uuid.NewString(), uuid.NewString()
	runDir, snapshotDir := filepath.Join(root, "run"), filepath.Join(root, "snapshots")
	rootfs := filepath.Join(runDir, TemplatesDirName, templateID, "rootfs.ext4")
	templateSnapshot := filepath.Join(snapshotDir, TemplatesDirName, templateID, "vmstate.snap")
	templateMemory := filepath.Join(filepath.Dir(templateSnapshot), "mem.snap")
	for _, path := range []string{rootfs, templateSnapshot, templateMemory} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("retained"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fc := startSnapshotAPIFake(t, func(_, body string) (int, string) {
		var req struct {
			SnapshotPath string `json:"snapshot_path"`
			MemFilePath  string `json:"mem_file_path"`
			SnapshotType string `json:"snapshot_type"`
		}
		if err := json.Unmarshal([]byte(body), &req); err != nil || req.SnapshotType != "Full" {
			t.Errorf("expected full pause: body=%s err=%v", body, err)
			return http.StatusBadRequest, ""
		}
		for _, path := range []string{req.SnapshotPath, req.MemFilePath} {
			if err := os.WriteFile(path, []byte("paused"), 0o600); err != nil {
				t.Error(err)
				return http.StatusInternalServerError, ""
			}
		}
		return http.StatusNoContent, ""
	})
	m := &Manager{
		log: zerolog.Nop(), state: state, netMgr: &fakeNetMgr{},
		cfg: ManagerConfig{RunDir: runDir, SnapshotDir: snapshotDir},
		vms: map[string]*VMInstance{}, restoreSem: make(chan struct{}, 1),
		tplLastRestore: make(map[string]time.Time),
	}
	m.launchFirecrackerHook = func(context.Context, string, string, string, string, string, Supervision, bool, bool) (int, Supervision, error) {
		return 4321, SupervisionCgroup, nil
	}
	m.restoreSnapshotHook = func(string, string, string, *bool) error { return nil }
	inst, err := m.RestoreVMSnapshot(t.Context(), id, templateSnapshot, templateMemory, VMConfig{}, nil, "example-team", "example-owner", "", nil, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created, err := state.Get(id)
	if err != nil || created == nil || created.RootfsPath != rootfs {
		t.Fatalf("create did not persist template dependency: record=%+v err=%v", created, err)
	}
	inst.mu.Lock()
	inst.SocketPath = fc.socketPath
	inst.mu.Unlock()
	// No inventory has run when the first full pause removes the memory anchors.
	pausedSnapshot, pausedMemory, _, err := m.PauseVM(t.Context(), id, "", "")
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	if len(fc.snapshotBodies()) != 1 {
		t.Fatalf("expected one full snapshot, got %v", fc.snapshotBodies())
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenStateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := state.Get(id)
	if err != nil || rec == nil || rec.Status != StatusPaused || rec.BaseMemPath != "" || rec.SnapshotPath != pausedSnapshot || rec.MemFilePath != pausedMemory || rec.RootfsPath != rootfs {
		t.Fatalf("restart lost paused dependencies: record=%+v err=%v", rec, err)
	}
	restarted := &Manager{state: state, cfg: m.cfg, vms: map[string]*VMInstance{id: toInstance(*rec)}}
	seen := map[string]bool{}
	inv, err := restarted.retainedStorageInventory(t.Context(), func(f *os.File, _ int) ([]retainedstorage.Extent, string, error) {
		seen[f.Name()] = true
		return []retainedstorage.Extent{{Device: "fs", Start: int64(len(seen)) * 4096, Length: 4096}}, f.Name(), nil
	})
	if err != nil || inv == nil || len(inv.Owners) != 1 || len(seen) != 4 {
		t.Fatalf("incomplete restarted inventory: paths=%v err=%v", seen, err)
	}
	for _, path := range []string{rec.DiskPath, rootfs, pausedSnapshot, pausedMemory} {
		if !seen[path] {
			t.Errorf("inventory omitted %q", path)
		}
	}
}

func TestRetainedFileMetadataIgnoresReadAccessTime(t *testing.T) {
	before := syscall.Stat_t{Dev: 1, Ino: 2, Nlink: 1, Size: 4096, Blocks: 8,
		Atim: syscall.Timespec{Sec: 1}, Mtim: syscall.Timespec{Sec: 2}, Ctim: syscall.Timespec{Sec: 2}}
	for _, tc := range []struct {
		name   string
		change func(*syscall.Stat_t)
		same   bool
	}{
		{"unchanged", func(*syscall.Stat_t) {}, true},
		{"manifest read", func(s *syscall.Stat_t) { s.Atim.Sec++ }, true},
		{"replacement", func(s *syscall.Stat_t) { s.Ino++ }, false},
		{"device", func(s *syscall.Stat_t) { s.Dev++ }, false},
		{"size", func(s *syscall.Stat_t) { s.Size++ }, false},
		{"allocation", func(s *syscall.Stat_t) { s.Blocks++ }, false},
		{"write", func(s *syscall.Stat_t) { s.Mtim.Nsec++ }, false},
		{"write with restored mtime", func(s *syscall.Stat_t) { s.Ctim.Nsec++ }, false},
		{"unlink", func(s *syscall.Stat_t) { s.Nlink = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			tc.change(&after)
			if got := sameRetainedFileMetadata(&before, &after); got != tc.same {
				t.Fatalf("same metadata = %v, want %v", got, tc.same)
			}
		})
	}
}

func retainedTestUnion(extents ...[]retainedstorage.Extent) int64 {
	all := []retainedstorage.Extent{}
	for _, e := range extents {
		all = append(all, e...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Device != all[j].Device {
			return all[i].Device < all[j].Device
		}
		return all[i].Start < all[j].Start
	})
	var device string
	var end, total int64
	for _, e := range all {
		if device != e.Device {
			device = e.Device
			end = 0
		}
		start := e.Start
		if start < end {
			start = end
		}
		if e.Start+e.Length > start {
			total += e.Start + e.Length - start
		}
		if e.Start+e.Length > end {
			end = e.Start + e.Length
		}
	}
	return total
}

func TestRetainedPhysicalReflinkAllocation(t *testing.T) {
	root := os.Getenv("RETAINED_STORAGE_TEST_DIR")
	if root == "" {
		t.Skip("RETAINED_STORAGE_TEST_DIR must name a qualified Linux reflink filesystem; synthetic tests do not prove sharing")
	}
	dir, err := os.MkdirTemp(root, "retained-storage-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	makeFile := func(name string) *os.File {
		t.Helper()
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	base := makeFile("mem.snap")
	if err := base.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := base.WriteAt(bytes.Repeat([]byte{0x5a}, 1<<20), 0); err != nil {
		t.Fatal(err)
	}
	if err := base.Sync(); err != nil {
		t.Fatal(err)
	}
	sample := func(f *os.File) []retainedstorage.Extent {
		t.Helper()
		e, _, err := retainedFileExtents(f, retainedstorage.MaxExtents)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	baseline := sample(base)
	var stat unix.Stat_t
	if err := unix.Fstat(int(base.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if got := retainedTestUnion(baseline); got != stat.Blocks*512 || got >= 64<<20 {
		t.Fatalf("physical=%d blocks=%d logical=%d", got, stat.Blocks*512, 64<<20)
	}
	t.Logf("sparse allocation reconciliation: union=%d st_blocks_bytes=%d apparent_bytes=%d", retainedTestUnion(baseline), stat.Blocks*512, stat.Size)
	children := []*os.File{makeFile("fork-one"), makeFile("fork-two"), makeFile("fork-three")}
	for _, child := range children {
		if err := cloneFileFD(child, base); err != nil {
			t.Fatalf("configured filesystem does not support reflink: %v", err)
		}
		if err := child.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	// Compare data ranges independently of per-inode extent-tree metadata.
	data := func(e []retainedstorage.Extent) []retainedstorage.Extent {
		out := []retainedstorage.Extent{}
		for _, r := range e {
			if !strings.Contains(r.Device, ":inode:") {
				out = append(out, r)
			}
		}
		return out
	}
	shared := data(sample(base))
	parts := [][]retainedstorage.Extent{shared}
	for _, child := range children {
		parts = append(parts, data(sample(child)))
	}
	if got, want := retainedTestUnion(parts...), retainedTestUnion(shared); got != want {
		t.Fatalf("three clones multiply baseline: %d want %d", got, want)
	}
	t.Logf("shared allocation reconciliation: baseline=%d union_with_three_clones=%d", retainedTestUnion(shared), retainedTestUnion(parts...))
	if _, err := children[0].WriteAt(bytes.Repeat([]byte{0x33}, 4096), 0); err != nil {
		t.Fatal(err)
	}
	if err := children[0].Sync(); err != nil {
		t.Fatal(err)
	}
	parts[1] = data(sample(children[0]))
	if retainedTestUnion(parts...) <= retainedTestUnion(shared) {
		t.Fatal("private fork allocation was omitted")
	}
	t.Logf("private-write allocation reconciliation: shared=%d combined=%d", retainedTestUnion(shared), retainedTestUnion(parts...))
	if err := os.Remove(base.Name()); err != nil {
		t.Fatal(err)
	}
	if err := base.Close(); err != nil {
		t.Fatal(err)
	}
	for i, child := range children {
		parts[i+1] = data(sample(child))
	}
	if got := retainedTestUnion(parts[1:]...); got != retainedTestUnion(parts...) {
		t.Fatalf("source deletion lost shared data: %d", got)
	}
	t.Logf("source-deletion allocation reconciliation: surviving_union=%d", retainedTestUnion(parts[1:]...))
	independent := makeFile("independent")
	if _, err := independent.Write(bytes.Repeat([]byte{0x5a}, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := independent.Sync(); err != nil {
		t.Fatal(err)
	}
	if retainedTestUnion(shared, data(sample(independent))) <= retainedTestUnion(shared) {
		t.Fatal("independent identical contents deduplicated")
	}
	if _, _, err := retainedFileExtents(children[0], 0); err == nil {
		t.Fatal("zero extent budget accepted an allocation")
	}
}

func TestRetainedPhysicalInventoryFullDiffAndMissing(t *testing.T) {
	root := os.Getenv("RETAINED_STORAGE_TEST_DIR")
	if root == "" {
		t.Skip("RETAINED_STORAGE_TEST_DIR is required for physical inventory qualification")
	}
	dir, err := os.MkdirTemp(root, "retained-inventory-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	state, err := OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	m := &Manager{state: state, cfg: ManagerConfig{RunDir: dir, SnapshotDir: filepath.Join(dir, "snapshots")}}
	writeData := func(path string, data []byte) string {
		t.Helper()
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write := func(name string, pages int) string {
		t.Helper()
		return writeData(filepath.Join(dir, name), bytes.Repeat([]byte{1}, pages*4096))
	}
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused, DiskPath: write("overlay.ext4", 4), SnapshotPath: write("vmstate.snap", 1), MemFilePath: write("mem.snap", 8)}
	write("mem.snap.wallclock", 1)
	rec.RootfsPath = rec.DiskPath
	save := func() {
		t.Helper()
		if err := state.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	save()
	sample := func() *retainedstorage.Inventory {
		t.Helper()
		inv, err := m.RetainedStorageInventory(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return inv
	}
	full := sample()
	if len(full.Owners) != 1 {
		t.Fatal("sandbox missing")
	}
	fullBytes := retainedTestUnion(full.Owners[0].Extents)
	t.Logf("full inventory reconciliation: allocated=%d expected=%d", fullBytes, 14*4096)
	if fullBytes != 14*4096 {
		t.Fatalf("full physical bytes=%d", fullBytes)
	}
	rec.BaseMemPath = rec.MemFilePath
	rec.MemFilePath = write("mem.diff", 2)
	for _, name := range []string{"vmstate.snap.overlay", "mem.diff.presence", "mem.diff.wallclock"} {
		write(name, 1)
	}
	writeData(rec.MemFilePath+".base", []byte(rec.BaseMemPath))
	save()
	layered := sample()
	if got := retainedTestUnion(layered.Owners[0].Extents); got != fullBytes+6*4096 {
		t.Fatalf("layered allocation=%d", got)
	}
	rec.MemFilePath = write("replacement.snap", 3)
	rec.BaseMemPath = ""
	save()
	replacement := sample()
	t.Logf("layered/replacement reconciliation: layered=%d replacement=%d", retainedTestUnion(layered.Owners[0].Extents), retainedTestUnion(replacement.Owners[0].Extents))
	if got := retainedTestUnion(replacement.Owners[0].Extents); got != 9*4096 {
		t.Fatalf("superseded full/diff images still billable: %d", got)
	}
	rec.Status = StatusRunning
	save()
	running := sample()
	if retainedTestUnion(running.Owners[0].Extents) != retainedTestUnion(replacement.Owners[0].Extents) {
		t.Fatal("resume dropped retained memory")
	}

	snapshotID := uuid.NewString()
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, snapshotID)
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotDisk := filepath.Join(snapshotDir, "overlay.ext4")
	snapshotState := filepath.Join(snapshotDir, "vmstate.snap")
	snapshotMem := filepath.Join(snapshotDir, "mem.diff")
	snapshotBaseMem := filepath.Join(snapshotDir, "mem.base")
	for _, path := range []string{snapshotState, snapshotMem, snapshotBaseMem, snapshotState + ".overlay", snapshotMem + ".presence", snapshotMem + ".base", snapshotMem + ".wallclock", snapshotBaseMem + ".wallclock"} {
		data := bytes.Repeat([]byte{7}, 4096)
		if path == snapshotMem+".base" {
			data = []byte(snapshotBaseMem)
		}
		writeData(path, data)
	}
	src, err := os.Open(rec.DiskPath)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.Create(snapshotDisk)
	if err != nil {
		src.Close()
		t.Fatal(err)
	}
	if err := cloneFileFD(dst, src); err != nil {
		src.Close()
		dst.Close()
		t.Fatal(err)
	}
	if err := dst.Sync(); err != nil {
		t.Fatal(err)
	}
	src.Close()
	dst.Close()
	man, err := json.Marshal(SavedSnapshotManifest{Version: savedSnapshotVersion, SnapshotID: snapshotID, SourceVMID: rec.ID, Kind: SavedSnapshotMemFS, DiskPath: snapshotDisk, SnapshotPath: snapshotState, MemPath: snapshotMem, BaseMemPath: snapshotBaseMem})
	if err != nil {
		t.Fatal(err)
	}
	writeData(filepath.Join(snapshotDir, savedSnapshotManifestName), man)
	if got := sample(); len(got.Owners) != 2 {
		t.Fatal("committed saved snapshot omitted")
	}
	var snapshotOwner retainedstorage.Owner
	for _, owner := range sample().Owners {
		if owner.Kind == "snapshot" {
			snapshotOwner = owner
		}
	}
	if got := retainedTestUnion(snapshotOwner.Extents); got != 13*4096 {
		t.Fatalf("mem+fs snapshot omitted retained artifacts: %d", got)
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, savedSnapshotManifestName), []byte(`{"version":1,"snapshot_id":"`+snapshotID+`","kind":"mem+fs"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RetainedStorageInventory(t.Context()); err == nil {
		t.Fatal("incomplete snapshot manifest was accepted")
	}
	writeData(filepath.Join(snapshotDir, savedSnapshotManifestName), man)
	if err := os.Remove(rec.MemFilePath); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RetainedStorageInventory(t.Context()); err == nil {
		t.Fatal("missing retained memory became zero")
	}
	if err := state.Delete(rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rec.DiskPath); err != nil {
		t.Fatal(err)
	}
	snapshotOnly := sample()
	if len(snapshotOnly.Owners) != 1 || snapshotOnly.Owners[0].Kind != "snapshot" || retainedTestUnion(snapshotOnly.Owners[0].Extents) != 13*4096 {
		t.Fatal("source deletion lost independently retained snapshot")
	}

}
