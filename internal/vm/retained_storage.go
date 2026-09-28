package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	bolt "go.etcd.io/bbolt"
)

// Lifecycle writers only advance atomics. Discovery never takes their locks.
func (m *Manager) beginStorageMutation() func() {
	m.storageMutations.Add(1)
	m.storageEpoch.Add(1)
	return func() { m.storageEpoch.Add(1); m.storageMutations.Add(-1) }
}

func (s *StateStore) retainedRecords() ([]VMRecord, error) {
	records := make([]VMRecord, 0)
	bytes := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(k, v []byte) error {
			if len(records) >= retainedstorage.MaxOwners {
				return fmt.Errorf("retained owner budget exceeded")
			}
			bytes += len(k) + len(v)
			if bytes > retainedstorage.MaxPayloadBytes {
				return fmt.Errorf("retained record budget exceeded")
			}
			var rec VMRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			records = append(records, rec)
			return nil
		})
	})
	return records, err
}

// resolveRetainedRecordPaths returns both the files to measure and any
// generation anchors recovered from legacy records.  The latter are written
// back by the background inventory pass so a later pause cannot erase the
// only durable reference to the template generation it retained.
func resolveRetainedRecordPaths(rec VMRecord, runDir string) ([]string, VMRecord, error) {
	if rec.TeardownPending != "" || rec.RevivalPending || rec.WakePending || rec.Unverified {
		return nil, rec, fmt.Errorf("retained generation is transitioning")
	}
	if rec.Status == StatusPaused && (rec.SnapshotPath == "" || rec.MemFilePath == "") {
		return nil, rec, fmt.Errorf("paused memory dependencies are unknown")
	}
	disk := rec.DiskPath
	if disk == "" {
		disk = filepath.Join(runDir, rec.ID, "overlay.ext4")
		if _, err := os.Stat(disk); os.IsNotExist(err) {
			disk = filepath.Join(runDir, rec.ID, "rootfs.ext4")
		}
	}
	baseMem := rec.BaseMemPath
	if rec.MemFilePath != "" {
		// Restore and snapshot capture use the sidecar as the authoritative
		// dependency when older records omitted BaseMemPath. A diff without a
		// resolvable base is not a partial success: reject the observation so
		// the previous accepted quantity remains in force.
		if sidecar, ok := readLayeredBase(rec.MemFilePath); ok {
			if baseMem != "" && filepath.Clean(baseMem) != filepath.Clean(sidecar) {
				return nil, rec, fmt.Errorf("layered memory base changed during inventory")
			}
			baseMem = sidecar
		} else if isOverlayMemFile(rec.MemFilePath) && baseMem == "" {
			return nil, rec, fmt.Errorf("layered memory base is unknown")
		}
	}
	// A pause replaces SnapshotPath with the sandbox's own image. For older
	// records the layered base still pins the immutable template generation;
	// its build metadata, not the latest template directory, names the disk.
	deltaDir, rootfs := rec.DeltaDir, rec.RootfsPath
	// A revived salvage is an explicitly retained allocation when
	// no template generation anchor survived the old record.  Its durable
	// BasePath (when present) is still measured, but requiring an unrelated
	// template delta would reject the whole host after a successful revival.
	revivedWithoutTemplate := rec.RevivedDisk != "" && rec.BasePath != "" && deltaDir == ""
	if rec.SourceSnapshotID == "" && !revivedWithoutTemplate && ((rec.BasePath != "" && deltaDir == "") || (rec.BasePath == "" && rootfs == "")) {
		resolved := false
		for _, anchor := range []string{baseMem, rec.SnapshotPath} {
			if anchor == "" {
				continue
			}
			inferredRootfs, err := templateRootfsForSnapshot(runDir, anchor)
			if err != nil {
				continue
			}
			meta, err := readBuildMetaJSON(filepath.Dir(anchor))
			if os.IsNotExist(err) {
				// Legacy flat template generations predate build.meta.json.
				// Only a pinned image in that layout identifies their rootfs.
				if rec.BasePath == "" && filepath.Base(filepath.Dir(filepath.Dir(anchor))) == TemplatesDirName {
					if _, err := os.Stat(inferredRootfs); err == nil {
						rootfs, resolved = inferredRootfs, true
						break
					}
				}
				if rec.BasePath != "" {
					candidate := filepath.Join(filepath.Dir(anchor), "rootfs.delta")
					if _, err := os.Stat(candidate); err == nil {
						deltaDir, resolved = filepath.Dir(candidate), true
						break
					}
				}
			}
			if err != nil {
				continue
			}
			if rec.BasePath != "" {
				if meta.BasePath != rec.BasePath || meta.DeltaPath == "" {
					continue
				}
				deltaDir = filepath.Dir(meta.DeltaPath)
				if filepath.Base(meta.DeltaPath) != "rootfs.delta" {
					continue
				}
			} else {
				if meta.BasePath != "" || meta.RootfsPath == "" {
					continue
				}
				rootfs = meta.RootfsPath
			}
			resolved = true
			break
		}
		if !resolved {
			return nil, rec, fmt.Errorf("retained template generation dependencies are unknown")
		}
	}
	delta := ""
	if deltaDir != "" {
		delta = filepath.Join(deltaDir, "rootfs.delta")
	}
	paths := []string{disk, rec.BasePath, rec.SnapshotPath, rec.MemFilePath, baseMem}
	if rootfs != "" {
		paths = append(paths, rootfs)
	}
	if delta != "" {
		paths = append(paths, delta)
	}
	paths = append(paths, rec.StrandedOverlays...)
	// Preserve every recovered anchor, including a sidecar-derived memory base.
	// These fields are intentionally metadata-only; lifecycle code continues to
	// use the current pause paths.
	rec.BaseMemPath = baseMem
	rec.RootfsPath = rootfs
	rec.DeltaDir = deltaDir
	return paths, rec, nil
}

func retainedRecordPaths(rec VMRecord, runDir string) ([]string, error) {
	paths, _, err := resolveRetainedRecordPaths(rec, runDir)
	return paths, err
}

type retainedFileObservation struct {
	path string
	info os.FileInfo
}

// RetainedStorageInventory samples all owners as one physical-address epoch.
// Mixing a successful owner with a failed old sample could alias reused blocks.
func (m *Manager) RetainedStorageInventory(ctx context.Context) (*retainedstorage.Inventory, error) {
	return m.retainedStorageInventory(ctx, retainedFileExtents)
}

// rememberRetainedDependencies persists anchors recovered from a legacy
// record.  Inventory runs off the lifecycle hot path, so a small conditional
// record write here is preferable to allowing the next full pause to erase
// the generation identity and freeze host-wide accounting.
func (m *Manager) rememberRetainedDependencies(original, resolved VMRecord) error {
	if original.BaseMemPath == resolved.BaseMemPath && original.RootfsPath == resolved.RootfsPath && original.DeltaDir == resolved.DeltaDir {
		return nil
	}
	if m.state == nil {
		return nil
	}
	m.mu.RLock()
	inst := m.vms[original.ID]
	m.mu.RUnlock()
	if inst != nil {
		inst.mu.Lock()
		current := toRecordLocked(inst)
		if current.BaseMemPath != original.BaseMemPath || current.RootfsPath != original.RootfsPath || current.DeltaDir != original.DeltaDir {
			inst.mu.Unlock()
			return nil
		}
		inst.BaseMemPath = resolved.BaseMemPath
		inst.Config.RootfsPath = resolved.RootfsPath
		inst.Config.DeltaDir = resolved.DeltaDir
		updated := toRecordLocked(inst)
		inst.mu.Unlock()
		_, err := m.state.PutIfPresent(updated)
		return err
	}
	current, err := m.state.Get(original.ID)
	if err != nil || current == nil {
		return err
	}
	if current.BaseMemPath != original.BaseMemPath || current.RootfsPath != original.RootfsPath || current.DeltaDir != original.DeltaDir {
		return nil
	}
	current.BaseMemPath = resolved.BaseMemPath
	current.RootfsPath = resolved.RootfsPath
	current.DeltaDir = resolved.DeltaDir
	_, err = m.state.PutIfPresent(*current)
	return err
}

func (m *Manager) retainedStorageInventory(ctx context.Context, measure func(*os.File, int) ([]retainedstorage.Extent, string, error)) (*retainedstorage.Inventory, error) {
	epoch := m.storageEpoch.Load()
	if m.storageMutations.Load() != 0 || m.state == nil {
		return nil, fmt.Errorf("retained inventory not ready")
	}
	records, err := m.state.retainedRecords()
	if err != nil {
		return nil, err
	}
	inv := &retainedstorage.Inventory{Version: retainedstorage.Version, Owners: make([]retainedstorage.Owner, 0)}
	observations := make([]retainedFileObservation, 0)
	dependencyUpdates := make([]struct{ original, resolved VMRecord }, 0)
	remaining := retainedstorage.MaxExtents
	add := func(kind, id string, paths []string) error {
		if len(inv.Owners) >= retainedstorage.MaxOwners {
			return fmt.Errorf("retained owner budget exceeded")
		}
		owner := retainedstorage.Owner{Kind: kind, ID: id, Extents: make([]retainedstorage.Extent, 0)}
		seen := map[string]bool{}
		digest := sha256.New()
		sort.Strings(paths)
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				return err
			}
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			if len(observations) >= retainedstorage.MaxExtents {
				return fmt.Errorf("retained file budget exceeded")
			}
			if !filepath.IsAbs(path) {
				return fmt.Errorf("relative retained artifact path")
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			info, err := f.Stat()
			if err != nil {
				f.Close()
				return err
			}
			if !info.Mode().IsRegular() {
				f.Close()
				return fmt.Errorf("retained artifact is not regular")
			}
			extents, generation, err := measure(f, remaining)
			f.Close()
			if err != nil {
				return err
			}
			remaining -= len(extents)
			owner.Extents = append(owner.Extents, extents...)
			fmt.Fprintf(digest, "%s\x00%s\x00", path, generation)
			observations = append(observations, retainedFileObservation{path, info})
		}
		owner.Generation = hex.EncodeToString(digest.Sum(nil))
		inv.Owners = append(inv.Owners, owner)
		return nil
	}
	for _, rec := range records {
		// Warm/build VM records are not customer retention owners.
		if _, err := uuid.Parse(rec.ID); err != nil {
			continue
		}
		paths, resolved, err := resolveRetainedRecordPaths(rec, m.cfg.RunDir)
		if err != nil {
			return nil, err
		}
		if rec.BaseMemPath != resolved.BaseMemPath || rec.RootfsPath != resolved.RootfsPath || rec.DeltaDir != resolved.DeltaDir {
			dependencyUpdates = append(dependencyUpdates, struct{ original, resolved VMRecord }{rec, resolved})
		}
		if err := add("sandbox", rec.ID, paths); err != nil {
			return nil, err
		}
	}
	dir, err := os.Open(filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		defer dir.Close()
		// Read at most one more than the bound, including staging entries.
		entries, err := dir.ReadDir(retainedstorage.MaxOwners + 1)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(entries) > retainedstorage.MaxOwners {
			return nil, fmt.Errorf("snapshot inventory budget exceeded")
		}
		for _, entry := range entries {
			if _, err := uuid.Parse(entry.Name()); err != nil || !entry.IsDir() {
				continue
			}
			path := filepath.Join(dir.Name(), entry.Name(), savedSnapshotManifestName)
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			var man SavedSnapshotManifest
			err = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&man)
			info, statErr := f.Stat()
			f.Close()
			if err != nil {
				return nil, err
			}
			if statErr != nil {
				return nil, statErr
			}
			if man.Version != savedSnapshotVersion || man.SnapshotID != entry.Name() || man.DiskPath == "" || (man.Kind != SavedSnapshotFS && man.Kind != SavedSnapshotMemFS) || (man.Kind == SavedSnapshotMemFS && (man.MemPath == "" || man.SnapshotPath == "")) {
				return nil, fmt.Errorf("incomplete saved snapshot manifest")
			}
			observations = append(observations, retainedFileObservation{path, info})
			if err := add("snapshot", man.SnapshotID, []string{man.DiskPath, man.BasePath, man.SnapshotPath, man.MemPath, man.BaseMemPath}); err != nil {
				return nil, err
			}
		}
	}
	for _, o := range observations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Stat(o.path)
		if err != nil {
			return nil, err
		}
		if !os.SameFile(o.info, info) || !reflect.DeepEqual(o.info.Sys(), info.Sys()) {
			return nil, fmt.Errorf("retained artifact changed during inventory")
		}
	}
	after, err := m.state.retainedRecords()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(records, after) || m.storageMutations.Load() != 0 || m.storageEpoch.Load() != epoch {
		return nil, fmt.Errorf("retained generation changed during inventory")
	}
	for _, update := range dependencyUpdates {
		if err := m.rememberRetainedDependencies(update.original, update.resolved); err != nil {
			return nil, err
		}
	}
	if m.storageMutations.Load() != 0 || m.storageEpoch.Load() != epoch {
		return nil, fmt.Errorf("retained generation changed while persisting dependency anchors")
	}
	sort.Slice(inv.Owners, func(i, j int) bool { return inv.Owners[i].Kind+inv.Owners[i].ID < inv.Owners[j].Kind+inv.Owners[j].ID })
	return inv, inv.Validate()
}

func runRetainedStorageSampler(ctx context.Context, cfg HeartbeatConfig, cache *heartbeatStorageCache, log zerolog.Logger) {
	sample := func() {
		if cfg.LifecycleReady == nil || !cfg.LifecycleReady() {
			return
		}
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		inv, err := cfg.RetainedStorage(scanCtx)
		if err == nil && inv == nil {
			err = fmt.Errorf("retained inventory is unknown")
		}
		if err == nil {
			err = cache.store([]heartbeatStorageMeasurement{{Retained: inv}})
		}
		if err != nil {
			log.Warn().Err(err).Msg("retained storage inventory unknown; preserving accepted allocation")
		}
	}
	sample()
	ticker := time.NewTicker(overlayStorageSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}
