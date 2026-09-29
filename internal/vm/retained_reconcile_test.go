package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	bolt "go.etcd.io/bbolt"
)

func TestRetainedReconcileFullPause(t *testing.T) {
	for _, overlay := range []bool{true, false} {
		name := "full_copy"
		if overlay {
			name = "overlay"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			snapshots := filepath.Join(root, "snapshots")
			buildID := uuid.NewString()
			if overlay {
				buildID = "build-" + buildID
			}
			generation := filepath.Join(snapshots, TemplatesDirName, uuid.NewString(), buildID)
			write := func(path string, content []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused, CreatedAt: time.Now().UTC(), PausedAt: time.Now().UTC(), DiskPath: filepath.Join(root, "overlay.ext4"), SnapshotPath: filepath.Join(root, "pause", "vmstate.snap"), MemFilePath: filepath.Join(root, "pause", "mem.snap")}
			ref := RetainedCreationReference{ID: rec.ID, HostID: "example-host", CreatedAt: rec.CreatedAt.Add(-time.Second), SnapshotPath: filepath.Join(generation, "vmstate.snap"), MemPath: filepath.Join(generation, "mem.snap")}
			rootfs := filepath.Join(root, "run", TemplatesDirName, "example-template", "rootfs.ext4")
			if overlay {
				rec.BasePath = filepath.Join(root, "base.ext4")
				ref.BasePath = rec.BasePath
				ref.DeltaPath = filepath.Join(generation, "rootfs.delta")
			}
			meta, _ := json.Marshal(map[string]string{"snapshot_path": ref.SnapshotPath, "mem_path": ref.MemPath, "base_path": ref.BasePath, "delta_path": ref.DeltaPath, "rootfs_path": rootfs})
			write(filepath.Join(generation, buildMetaFilename), meta)
			for _, path := range []string{rec.DiskPath, rec.SnapshotPath, rec.MemFilePath, rootfs, ref.BasePath, ref.DeltaPath} {
				if path != "" {
					write(path, []byte("retained data"))
				}
			}
			statePath := filepath.Join(root, "state.db")
			s, err := OpenStateStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			if err := s.Put(rec); err != nil {
				t.Fatal(err)
			}
			// A future field and unrelated configuration survive the narrow patch.
			if err := s.db.Update(func(tx *bolt.Tx) error {
				var fields map[string]json.RawMessage
				b := tx.Bucket(bucketName)
				if err := json.Unmarshal(b.Get([]byte(rec.ID)), &fields); err != nil {
					return err
				}
				fields["future_field"] = json.RawMessage(`{"keep":true}`)
				fields["memory_mib"] = json.RawMessage(`777`)
				raw, err := json.Marshal(fields)
				if err != nil {
					return err
				}
				return b.Put([]byte(rec.ID), raw)
			}); err != nil {
				t.Fatal(err)
			}
			before, err := s.Get(rec.ID)
			if err != nil {
				t.Fatal(err)
			}
			measure := func(*os.File, int) ([]retainedstorage.Extent, string, error) {
				return []retainedstorage.Extent{{Device: "fixture", Start: 4096, Length: 4096}}, "fixture-generation", nil
			}
			refs := []RetainedCreationReference{ref}
			result, err := reconcileRetainedStorage(t.Context(), s, root, snapshots, ref.HostID, refs, false, measure)
			if err != nil || result.HostReady || result.Receipts[0].Status != "would_update" || result.Receipts[0].Metadata == "" {
				t.Fatalf("dry run: %+v %v", result, err)
			}
			after, _ := s.Get(rec.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("dry run changed durable state")
			}
			write(filepath.Join(generation, buildMetaFilename), []byte(`{"snapshot_path":"/different-generation/vmstate.snap"}`))
			result, err = reconcileRetainedStorage(t.Context(), s, root, snapshots, ref.HostID, refs, true, measure)
			if err != nil || result.HostReady || result.Receipts[0].Status != "unresolved" {
				t.Fatalf("bad provenance: %+v %v", result, err)
			}
			after, _ = s.Get(rec.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("unresolved record changed")
			}
			write(filepath.Join(generation, buildMetaFilename), meta)
			result, err = reconcileRetainedStorage(t.Context(), s, root, snapshots, ref.HostID, refs, true, measure)
			if err != nil || !result.HostReady || result.Receipts[0].Status != "updated" {
				t.Fatalf("apply: %+v %v", result, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenStateStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			after, err = s.Get(rec.ID)
			if err != nil {
				t.Fatal(err)
			}
			if after.BaseMemPath != "" || after.MemFilePath != rec.MemFilePath || after.SnapshotPath != rec.SnapshotPath || after.MemoryMiB != 777 {
				t.Fatalf("unrelated state changed: %+v", after)
			}
			paths, err := retainedRecordPaths(*after, root)
			wanted := rootfs
			if overlay {
				wanted = ref.DeltaPath
			}
			if err != nil || !slices.Contains(paths, wanted) || slices.Contains(paths, ref.MemPath) {
				t.Fatalf("dependencies after reopen: %v %v", paths, err)
			}
			if err := s.db.View(func(tx *bolt.Tx) error {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(tx.Bucket(bucketName).Get([]byte(rec.ID)), &fields); err != nil {
					return err
				}
				if string(fields["future_field"]) != `{"keep":true}` {
					t.Fatal("unknown field lost")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			result, err = reconcileRetainedStorage(t.Context(), s, root, snapshots, ref.HostID, refs, true, measure)
			if err != nil || !result.HostReady || result.Receipts[0].Status != "unchanged" {
				t.Fatalf("repeat: %+v %v", result, err)
			}
			// The existing compare-and-patch must reject a captured old pause.
			stale := *after
			after.PausedAt = after.PausedAt.Add(time.Minute)
			if err := s.Put(*after); err != nil {
				t.Fatal(err)
			}
			if err := s.updateRetainedDependencies(stale, stale); err == nil {
				t.Fatal("stale generation accepted")
			}
			if err := os.Remove(wanted); err != nil {
				t.Fatal(err)
			}
			result, err = reconcileRetainedStorage(t.Context(), s, root, snapshots, ref.HostID, refs, true, measure)
			if err != nil || result.HostReady || result.InventoryError == "" {
				t.Fatalf("missing inventory file: %+v %v", result, err)
			}
		})
	}
}

func TestRetainedReconcileRequiresExclusiveState(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.db")
	if _, err := ReconcileRetainedStorage(t.Context(), path, root, root, "example-host", nil, true); err == nil {
		t.Fatal("missing state accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("created missing state")
	}
	s, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, apply := range []bool{false, true} {
		if _, err := ReconcileRetainedStorage(t.Context(), path, root, root, "example-host", nil, apply); err == nil {
			t.Fatal("opened state while daemon holds it")
		}
	}
}
