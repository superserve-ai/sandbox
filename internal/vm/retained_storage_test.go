package vm

import (
	"context"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRetainedRecordPathsTrackFullAndLayeredGenerations(t *testing.T) {
	root := t.TempDir()
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused, DiskPath: filepath.Join(root, "overlay.ext4"), BasePath: filepath.Join(root, "base.ext4"), SnapshotPath: filepath.Join(root, "vmstate.snap"), MemFilePath: filepath.Join(root, "mem.diff"), BaseMemPath: filepath.Join(root, "base-mem.snap")}
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

func TestRetainedInventoryRejectsLifecycleOverlap(t *testing.T) {
	m := &Manager{}
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
