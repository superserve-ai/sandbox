package vm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

func TestRetainedRecordPathsTrackFullAndLayeredGenerations(t *testing.T) {
	root := t.TempDir()
	rec := VMRecord{ID: uuid.NewString(), SourceSnapshotID: uuid.NewString(), Status: StatusPaused, DiskPath: filepath.Join(root, "overlay.ext4"), BasePath: filepath.Join(root, "base.ext4"), SnapshotPath: filepath.Join(root, "vmstate.snap"), MemFilePath: filepath.Join(root, "mem.diff"), BaseMemPath: filepath.Join(root, "base-mem.snap")}
	paths, err := retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{rec.DiskPath, rec.BasePath, rec.SnapshotPath, rec.MemFilePath, rec.BaseMemPath}) {
		t.Fatalf("layered dependencies: %v", paths)
	}
	old := rec.MemFilePath
	rec.MemFilePath = filepath.Join(root, "mem.snap")
	rec.BaseMemPath = ""
	rec.StrandedOverlays = []string{old}
	paths, err = retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	if paths[len(paths)-1] != old || paths[3] != rec.MemFilePath || paths[4] != "" {
		t.Fatalf("full transition dependencies: %v", paths)
	}
	rec.StrandedOverlays = nil
	rec.Status = StatusRunning
	paths, err = retainedRecordPaths(rec, root)
	if err != nil || paths[3] != rec.MemFilePath {
		t.Fatalf("running retained memory: %v %v", paths, err)
	}
	rec.Status = StatusPaused
	rec.MemFilePath = ""
	if _, err = retainedRecordPaths(rec, root); err == nil {
		t.Fatal("missing paused memory was treated as absent")
	}
}

func TestRetainedRecordPathsResolvePinnedTemplateAndLayeredSidecar(t *testing.T) {
	root := t.TempDir()
	mem := filepath.Join(root, "mem.diff")
	base := filepath.Join(root, "template", "mem.snap")
	if err := os.WriteFile(mem+".base", []byte(base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused,
		DiskPath: filepath.Join(root, "overlay.ext4"), BasePath: filepath.Join(root, "template", "base.ext4"), SnapshotPath: filepath.Join(root, "vmstate.snap"),
		MemFilePath: mem, DeltaDir: filepath.Join(root, "template"), RootfsPath: filepath.Join(root, "template", "rootfs.ext4")}
	paths, err := retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{rec.DiskPath, rec.BasePath, rec.SnapshotPath, rec.MemFilePath, base, rec.RootfsPath, filepath.Join(rec.DeltaDir, "rootfs.delta")}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("retained dependencies = %v, want %v", paths, want)
	}
}

func TestRetainedInventoryRejectsLifecycleOverlap(t *testing.T) {
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	m := &Manager{state: state, cfg: ManagerConfig{SnapshotDir: t.TempDir()}}
	if _, err := m.RetainedStorageInventory(t.Context()); err != nil {
		t.Fatal(err)
	}
	unlock, err := m.lockVMOp(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	epoch := m.storageEpoch.Load()
	if m.storageMutations.Load() != 1 {
		t.Fatal("operation not fenced")
	}
	if _, err := m.RetainedStorageInventory(context.Background()); err == nil {
		t.Fatal("sampled a changing generation")
	}
	unlock()
	if m.storageMutations.Load() != 0 || m.storageEpoch.Load() <= epoch {
		t.Fatal("operation release did not advance generation")
	}
}

func TestRetainedInventorySpoolPreservesIdentityAndVersion(t *testing.T) {
	dir := t.TempDir()
	incarnation := uuid.NewString()
	cache := newHeartbeatStorageCache(dir, zerolog.Nop(), incarnation)
	inv := &retainedstorage.Inventory{Version: retainedstorage.Version, Owners: []retainedstorage.Owner{{Kind: "sandbox", ID: uuid.NewString(), Generation: strings.Repeat("1", 64), Extents: []retainedstorage.Extent{}}}}
	if err := cache.store([]heartbeatStorageMeasurement{{Retained: inv}}); err != nil {
		t.Fatal(err)
	}
	pending := cache.pendingSnapshot()
	if len(pending) != 1 {
		t.Fatalf("pending reports: %d", len(pending))
	}
	restored := newHeartbeatStorageCache(dir, zerolog.Nop(), incarnation).pendingSnapshot()
	if !reflect.DeepEqual(pending, restored) {
		t.Fatal("restart changed retained report identity or explicit zero")
	}
}

func TestRetainedPausedUpgradeDependencies(t *testing.T) {
	root := t.TempDir()
	generation := filepath.Join(root, "snapshots", "templates", uuid.NewString(), uuid.NewString())
	if err := os.MkdirAll(generation, 0700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "bases", "base.ext4")
	delta := filepath.Join(generation, "rootfs.delta")
	memory := filepath.Join(generation, "mem.snap")
	meta := `{"base_path":` + strconv.Quote(base) + `,"delta_path":` + strconv.Quote(delta) + `}`
	if err := os.WriteFile(filepath.Join(generation, buildMetaFilename), []byte(meta), 0600); err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused, BasePath: base, DiskPath: filepath.Join(root, "overlay.ext4"), SnapshotPath: filepath.Join(root, "paused", "vmstate.snap"), MemFilePath: filepath.Join(root, "paused", "mem.diff"), BaseMemPath: memory, DeltaDir: generation}
	// These are the fields that survive a pre-upgrade daemon's record rewrite.
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var oldFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &oldFields); err != nil {
		t.Fatal(err)
	}
	delete(oldFields, "delta_dir")
	delete(oldFields, "rootfs_path")
	raw, err = json.Marshal(oldFields)
	if err != nil {
		t.Fatal(err)
	}
	var rewritten VMRecord
	if err := json.Unmarshal(raw, &rewritten); err != nil {
		t.Fatal(err)
	}
	paths, err := retainedRecordPaths(rewritten, root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(paths, delta) || !slices.Contains(paths, memory) || !slices.Contains(paths, base) {
		t.Fatalf("lost pinned generation: %v", paths)
	}
	// A full pause can erase the last template-generation anchor in old
	// records. Neither a mutable latest build nor the sandbox image proves it.
	rewritten.MemFilePath = filepath.Join(root, "paused", "mem.snap")
	rewritten.BaseMemPath = ""
	if _, err := retainedRecordPaths(rewritten, root); err == nil {
		t.Fatal("unresolved paused overlay accepted")
	}
	rewritten.BasePath = ""
	if _, err := retainedRecordPaths(rewritten, root); err == nil {
		t.Fatal("unresolved full-copy template accepted")
	}
	// A durable legacy generation manifest resolves the full-copy rootfs.
	rootfs := filepath.Join(root, "templates", "legacy", "rootfs.ext4")
	if err := os.WriteFile(filepath.Join(generation, buildMetaFilename), []byte(`{"rootfs_path":`+strconv.Quote(rootfs)+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	rewritten.SnapshotPath = filepath.Join(generation, "vmstate.snap")
	paths, err = retainedRecordPaths(rewritten, root)
	if err != nil || !slices.Contains(paths, rootfs) {
		t.Fatalf("legacy generation: %v %v", paths, err)
	}
}

func TestRetainedInventoryArtifactRacePreservesAcceptedQuantity(t *testing.T) {
	for _, remove := range []bool{false, true} {
		name := "replacement"
		if remove {
			name = "deletion"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			state, err := OpenStateStore(filepath.Join(root, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			disk := filepath.Join(root, "overlay.ext4")
			if err := os.WriteFile(disk, []byte("accepted generation"), 0600); err != nil {
				t.Fatal(err)
			}
			rec := VMRecord{ID: uuid.NewString(), SourceSnapshotID: uuid.NewString(), Status: StatusRunning, DiskPath: disk}
			if err := state.Put(rec); err != nil {
				t.Fatal(err)
			}
			m := &Manager{state: state, cfg: ManagerConfig{RunDir: root, SnapshotDir: filepath.Join(root, "snapshots")}}
			measure := func(*os.File, int) ([]retainedstorage.Extent, string, error) {
				return []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}, "accepted", nil
			}
			accepted, err := m.retainedStorageInventory(t.Context(), measure)
			if err != nil {
				t.Fatal(err)
			}
			cache := newHeartbeatStorageCache(t.TempDir(), zerolog.Nop(), uuid.NewString())
			if err := cache.store([]heartbeatStorageMeasurement{{Retained: accepted}}); err != nil {
				t.Fatal(err)
			}
			before := cache.pendingSnapshot()
			raced := false
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			runRetainedStorageSampler(ctx, HeartbeatConfig{LifecycleReady: func() bool { return true }, RetainedStorage: func(context.Context) (*retainedstorage.Inventory, error) {
				defer cancel()
				return m.retainedStorageInventory(t.Context(), func(f *os.File, budget int) ([]retainedstorage.Extent, string, error) {
					raced = true
					if remove {
						if err := os.Remove(disk); err != nil {
							t.Fatal(err)
						}
					} else {
						replacement := disk + ".replacement"
						if err := os.WriteFile(replacement, []byte("new generation"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(replacement, disk); err != nil {
							t.Fatal(err)
						}
					}
					return measure(f, budget)
				})
			}}, cache, zerolog.Nop())
			if !raced {
				t.Fatal("inventory never reached artifact scan")
			}
			if !reflect.DeepEqual(before, cache.pendingSnapshot()) {
				t.Fatal("race replaced accepted report quantity")
			}
		})
	}
}
