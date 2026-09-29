package vm

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	bolt "go.etcd.io/bbolt"
)

// RetainedCreationReference comes from the sandbox row, never the mutable
// template row. These paths are the original creation inputs, not pause paths.
type RetainedCreationReference struct {
	ID           string    `json:"id"`
	HostID       string    `json:"host_id"`
	CreatedAt    time.Time `json:"created_at"`
	SnapshotPath string    `json:"snapshot_path"`
	MemPath      string    `json:"mem_path"`
	BasePath     string    `json:"base_path"`
	DeltaPath    string    `json:"delta_path"`
}

type RetainedReconcileReceipt struct {
	ID        string                     `json:"id"`
	Status    string                     `json:"status"`
	Reason    string                     `json:"reason,omitempty"`
	Source    *RetainedCreationReference `json:"source,omitempty"`
	Metadata  string                     `json:"build_metadata,omitempty"`
	CreatedAt time.Time                  `json:"local_created_at"`
	PausedAt  time.Time                  `json:"local_paused_at"`
	Snapshot  string                     `json:"local_snapshot_path,omitempty"`
	Memory    string                     `json:"local_mem_path,omitempty"`
	Artifact  string                     `json:"local_artifact_id,omitempty"`
	Rootfs    string                     `json:"rootfs_path,omitempty"`
	DeltaDir  string                     `json:"delta_dir,omitempty"`
}

type RetainedReconcileResult struct {
	Apply          bool                       `json:"apply"`
	HostReady      bool                       `json:"host_ready"`
	InventoryError string                     `json:"inventory_error,omitempty"`
	Receipts       []RetainedReconcileReceipt `json:"receipts"`
	Inventory      *retainedstorage.Inventory `json:"inventory,omitempty"`
}

// ReconcileRetainedStorage is used only by the one-time maintenance command.
// Bolt's process lock excludes VMD and its lifecycle writers for the entire
// operation. Opening an existing DB directly avoids
// startup recovery, index repair, and other daemon side effects.
func ReconcileRetainedStorage(ctx context.Context, statePath, runDir, snapshotDir, hostID string, refs []RetainedCreationReference, apply bool) (RetainedReconcileResult, error) {
	db, err := bolt.Open(statePath, 0600, &bolt.Options{
		ReadOnly: !apply, Timeout: time.Second,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			return os.OpenFile(name, flags&^os.O_CREATE, mode)
		},
	})
	if err != nil {
		return RetainedReconcileResult{}, fmt.Errorf("open existing state (VMD must be stopped): %w", err)
	}
	defer db.Close()
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketName) == nil {
			return fmt.Errorf("VM records bucket is missing")
		}
		return nil
	}); err != nil {
		return RetainedReconcileResult{}, err
	}
	s := &StateStore{db: db}
	return reconcileRetainedStorage(ctx, s, runDir, snapshotDir, hostID, refs, apply, retainedFileExtents)
}

func reconcileRetainedStorage(ctx context.Context, s *StateStore, runDir, snapshotDir, hostID string, refs []RetainedCreationReference, apply bool, measure func(*os.File, int) ([]retainedstorage.Extent, string, error)) (RetainedReconcileResult, error) {
	result := RetainedReconcileResult{Apply: apply, Receipts: []RetainedReconcileReceipt{}}
	if hostID == "" || !filepath.IsAbs(runDir) || !filepath.IsAbs(snapshotDir) || len(refs) > retainedstorage.MaxOwners {
		return result, fmt.Errorf("host, absolute artifact directories and bounded creation references required")
	}
	for _, dir := range []string{runDir, snapshotDir} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return result, fmt.Errorf("configured artifact directory is missing: %s", dir)
		}
	}
	byID := make(map[string]RetainedCreationReference, len(refs))
	for _, ref := range refs {
		if _, exists := byID[ref.ID]; exists || ref.HostID != hostID {
			return result, fmt.Errorf("duplicate or wrong-host creation reference")
		}
		byID[ref.ID] = ref
	}
	records, err := s.retainedRecords()
	if err != nil {
		return result, err
	}
	unresolved := false
	seen := map[string]bool{}
	for _, rec := range records {
		if _, err := uuid.Parse(rec.ID); err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		seen[rec.ID] = true
		receipt := RetainedReconcileReceipt{ID: rec.ID, Status: "unchanged", CreatedAt: rec.CreatedAt, PausedAt: rec.PausedAt,
			Snapshot: rec.SnapshotPath, Memory: rec.MemFilePath, Artifact: rec.ArtifactID, Rootfs: rec.RootfsPath, DeltaDir: rec.DeltaDir}
		ref, exists := byID[rec.ID]
		if exists {
			receipt.Source = &ref
		}
		var resolveErr error
		if !exists {
			resolveErr = fmt.Errorf("no live sandbox creation row on this host")
		} else if rec.SourceSnapshotID == "" && rec.RevivedDisk == "" && ((rec.BasePath != "" && rec.DeltaDir == "") || (rec.BasePath == "" && rec.RootfsPath == "")) {
			var resolved VMRecord
			resolved, receipt.Metadata, resolveErr = reconcileRetainedRecord(rec, ref, runDir, snapshotDir)
			if resolveErr == nil {
				receipt.Rootfs, receipt.DeltaDir = resolved.RootfsPath, resolved.DeltaDir
				receipt.Status = "would_update"
				if apply {
					resolveErr = s.updateRetainedDependencies(rec, resolved)
					if resolveErr == nil {
						receipt.Status = "updated"
					}
				}
			}
		}
		if resolveErr != nil {
			receipt.Status, receipt.Reason = "unresolved", resolveErr.Error()
			unresolved = true
		}
		result.Receipts = append(result.Receipts, receipt)
	}
	for _, ref := range refs {
		if !seen[ref.ID] {
			unresolved = true
			result.Receipts = append(result.Receipts, RetainedReconcileReceipt{ID: ref.ID, Status: "unresolved", Reason: "control-plane owner missing from durable state", Source: &ref})
		}
	}
	// A new read transaction inventories the durable result, including saved
	// snapshots. Never persist incidental discoveries from this readiness scan.
	m := &Manager{state: s, cfg: ManagerConfig{RunDir: runDir, SnapshotDir: snapshotDir}}
	inventoryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result.Inventory, err = m.retainedStorageInventoryWithPersistence(inventoryCtx, measure, false)
	if err != nil {
		result.InventoryError = err.Error()
	}
	result.HostReady = apply && !unresolved && err == nil
	return result, nil
}

func reconcileRetainedRecord(rec VMRecord, ref RetainedCreationReference, runDir, snapshotDir string) (VMRecord, string, error) {
	fail := func(reason string) (VMRecord, string, error) { return rec, "", fmt.Errorf("%s", reason) }
	if rec.ID != ref.ID || rec.Status != StatusPaused || rec.CreatedAt.IsZero() || ref.CreatedAt.IsZero() || rec.SourceSnapshotID != "" || rec.RevivedDisk != "" || rec.BasePath != ref.BasePath {
		return fail("creation identity, paused status or disk base does not match")
	}
	// Only immutable build directories qualify. Legacy flat/reused locations
	// need historical generation evidence; their current contents are not proof.
	generation := filepath.Dir(ref.SnapshotPath)
	rel, err := filepath.Rel(filepath.Join(snapshotDir, TemplatesDirName), generation)
	parts := strings.Split(rel, string(filepath.Separator))
	if err != nil || len(parts) != 2 || !validBuildPathSegment(parts[0]) || !validBuildPathSegment(parts[1]) || filepath.Base(ref.SnapshotPath) != "vmstate.snap" || ref.MemPath != filepath.Join(generation, "mem.snap") {
		return fail("creation references do not pin a template build")
	}
	buildUUID, buildUUIDErr := uuid.Parse(strings.TrimPrefix(parts[1], "build-"))
	prefix := "build-" + parts[0] + "-"
	suffix := strings.TrimPrefix(parts[1], prefix)
	_, hexErr := hex.DecodeString(suffix)
	randomBuild := strings.HasPrefix(parts[1], prefix) && len(suffix) == 8 && hexErr == nil
	if parts[1] == "build-"+parts[0] || ((buildUUIDErr != nil || buildUUID == uuid.Nil) && !randomBuild) {
		return fail("flat or reusable build identity needs historical provenance")
	}
	meta, err := readBuildMetaJSON(generation)
	if err != nil {
		return fail("pinned build metadata unavailable: " + err.Error())
	}
	if meta.SnapshotPath != ref.SnapshotPath || meta.MemFilePath != ref.MemPath || meta.BasePath != ref.BasePath || meta.DeltaPath != ref.DeltaPath {
		return fail("pinned build metadata disagrees with creation references")
	}
	resolved := rec
	if rec.BasePath != "" {
		if ref.DeltaPath != filepath.Join(generation, "rootfs.delta") {
			return fail("overlay creation does not name the pinned rootfs.delta")
		}
		resolved.DeltaDir = generation
	} else {
		if meta.RootfsPath == "" || ref.DeltaPath != "" {
			return fail("full-copy build does not identify its rootfs")
		}
		resolved.RootfsPath = meta.RootfsPath
	}
	paths, checked, err := resolveRetainedRecordPaths(resolved, runDir)
	if err != nil || checked.BaseMemPath != rec.BaseMemPath {
		return fail("pause dependencies are unresolved or require a separate memory repair")
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() {
			return fail("retained dependency missing or not a regular absolute file: " + path)
		}
	}
	return resolved, filepath.Join(generation, buildMetaFilename), nil
}
