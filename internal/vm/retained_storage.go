package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	bolt "go.etcd.io/bbolt"
)

// Lifecycle writers advance atomics so discovery can reject overlapping work.
func (m *Manager) beginStorageMutation() func() {
	m.storageMutations.Add(1)
	m.storageEpoch.Add(1)
	return func() { m.storageEpoch.Add(1); m.storageMutations.Add(-1) }
}

func (s *StateStore) retainedLiveRecords() ([]VMRecord, error) {
	return s.retainedLiveRecordsContext(context.Background())
}

func (s *StateStore) retainedLiveRecordsContext(ctx context.Context) ([]VMRecord, error) {
	budget := retainedScanBudget{}
	return s.retainedLiveRecordsWithBudget(ctx, &budget)
}

// retainedScanBudget is shared by the live and archived projections. Keeping
// the counters in one object prevents a host with a full live set and a full
// archive set from decoding two independent owner/payload budgets.
type retainedScanBudget struct {
	visited int
	bytes   int
	owners  int
}

func (b *retainedScanBudget) accountEntry(ctx context.Context, key, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.visited++
	if b.visited > retainedstorage.MaxVisitedEntries {
		return fmt.Errorf("retained record scan budget exceeded")
	}
	b.bytes += len(key) + len(value)
	if b.bytes > retainedstorage.MaxPayloadBytes {
		return fmt.Errorf("retained record budget exceeded")
	}
	return nil
}

func (b *retainedScanBudget) reserveOwner() error {
	if b.owners >= retainedstorage.MaxOwners {
		return fmt.Errorf("retained owner budget exceeded")
	}
	b.owners++
	return nil
}

func (s *StateStore) retainedLiveRecordsWithBudget(ctx context.Context, budget *retainedScanBudget) ([]VMRecord, error) {
	records := make([]VMRecord, 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(k, v []byte) error {
			if err := budget.accountEntry(ctx, k, v); err != nil {
				return err
			}
			// Charge encoded input before any key filtering or JSON decode. A
			// UUID-keyed oversized record must not allocate an unbounded decode
			// buffer inside the Bolt read transaction, and excluded records still
			// consume the scan's independent input budget.
			// The records bucket also contains build and warm-pool entries. Their
			// values are not part of retained inventory, so reject non-UUID keys
			// before decoding them; a large unrelated fleet must not consume the
			// inventory's JSON/decode budget.
			if _, err := uuid.Parse(string(k)); err != nil {
				return nil
			}
			if isBuildVM(string(k)) {
				return nil
			}
			if err := budget.reserveOwner(); err != nil {
				return err
			}
			var rec VMRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			// Build and warm-pool records share the Bolt bucket with customer
			// sandboxes but are not retained-storage owners. Filter them before
			// applying inventory budgets so unrelated fleet state cannot freeze
			// accounting for the customer set.
			if isBuildVM(rec.ID) {
				return nil
			}
			if _, err := uuid.Parse(rec.ID); err != nil {
				return nil
			}
			if len(records) >= retainedstorage.MaxOwners {
				return fmt.Errorf("retained owner budget exceeded")
			}
			records = append(records, rec)
			return nil
		})
	})
	return records, err
}

// retainedRecords combines live lifecycle records with archived failed-owner
// metadata. A live record wins if an archive from an earlier cleanup remains.
func (s *StateStore) retainedRecords() ([]VMRecord, error) {
	return s.retainedRecordsContext(context.Background())
}

func (s *StateStore) retainedRecordsContext(ctx context.Context) ([]VMRecord, error) {
	budget := retainedScanBudget{}
	live, err := s.retainedLiveRecordsWithBudget(ctx, &budget)
	if err != nil {
		return nil, err
	}
	archived, err := s.retainedArchivedRecordsWithBudget(ctx, &budget)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(live)+len(archived))
	for _, rec := range live {
		seen[rec.ID] = struct{}{}
	}
	for _, rec := range archived {
		if _, ok := seen[rec.ID]; ok {
			continue
		}
		live = append(live, rec)
	}
	return live, nil
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
	revivedWithoutTemplate := rec.RevivedDisk != "" && deltaDir == "" && rootfs == ""
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
					candidates := []string{inferredRootfs, filepath.Join(filepath.Dir(anchor), "rootfs.ext4")}
					for _, candidate := range candidates {
						if _, statErr := os.Stat(candidate); statErr == nil {
							rootfs, resolved = candidate, true
							break
						}
					}
					if resolved {
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
	paths, err := appendRetainedCompanions(paths, rec.SnapshotPath, append([]string{rec.MemFilePath, baseMem}, rec.StrandedOverlays...)...)
	if err != nil {
		return nil, rec, err
	}
	// A stranded diff can still fault from its immutable base after a
	// layered-to-full transition. Keep that base in the retained set; if the
	// sidecar cannot resolve it, preserve the prior accepted quantity instead
	// of retiring the contribution on an incomplete observation.
	for _, stranded := range rec.StrandedOverlays {
		if base, ok := readLayeredBase(stranded); ok {
			paths = append(paths, base)
		} else if isOverlayMemFile(stranded) {
			return nil, rec, fmt.Errorf("stranded layered memory base is unknown")
		}
	}
	// Preserve every recovered anchor, including a sidecar-derived memory base.
	// These fields are intentionally metadata-only; lifecycle code continues to
	// use the current pause paths.
	rec.BaseMemPath = baseMem
	rec.RootfsPath = rootfs
	rec.DeltaDir = deltaDir
	return paths, rec, nil
}

func appendRetainedCompanions(paths []string, snapshot string, memory ...string) ([]string, error) {
	companions := make([]string, 0, 1+3*len(memory))
	if snapshot != "" {
		companions = append(companions, overlayBlockMapPath(snapshot))
	}
	for _, path := range memory {
		if path != "" {
			companions = append(companions, presence.SidecarPath(path), layeredBaseSidecarPath(path), WallClockMarkerPath(path))
		}
	}
	for _, path := range companions {
		// Legacy images may lack companions. An existing but unreadable or
		// dangling companion must reach measurement and reject the inventory.
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
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

// sameRetainedGeneration fences recovered dependencies against replacement,
// pause/resume, and deletion/recreation while allowing unrelated policy updates.
func sameRetainedGeneration(a, b VMRecord) bool {
	return a.ID == b.ID && a.CreatedAt.Equal(b.CreatedAt) && a.PausedAt.Equal(b.PausedAt) &&
		a.Status == b.Status && a.PID == b.PID && a.ArtifactID == b.ArtifactID &&
		a.DiskPath == b.DiskPath && a.BasePath == b.BasePath &&
		a.SnapshotPath == b.SnapshotPath && a.MemFilePath == b.MemFilePath &&
		a.BaseMemPath == b.BaseMemPath && a.RootfsPath == b.RootfsPath && a.DeltaDir == b.DeltaDir &&
		a.SourceSnapshotID == b.SourceSnapshotID && a.RevivedDisk == b.RevivedDisk &&
		a.BackupGeneration == b.BackupGeneration && a.TeardownPending == b.TeardownPending &&
		a.RevivalPending == b.RevivalPending && a.WakePending == b.WakePending && a.Unverified == b.Unverified &&
		a.WakeSnapshotPath == b.WakeSnapshotPath && a.WakeMemPath == b.WakeMemPath &&
		a.DirtyTrackingSessionID == b.DirtyTrackingSessionID && a.DirtyTrackingGeneration == b.DirtyTrackingGeneration &&
		slices.Equal(a.StrandedOverlays, b.StrandedOverlays)
}

// updateRetainedDependencies changes only dependency fields in the current
// record. The comparison and patch share one transaction; unknown fields and
// unrelated lifecycle/policy state must survive this background write.
func (s *StateStore) updateRetainedDependencies(original, resolved VMRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return updateRetainedDependenciesTx(tx, original, resolved)
	})
}

// retainedDependencyUpdate is a metadata-only repair captured by one
// inventory pass. It is generation-fenced when persisted so replacement or
// deletion cannot receive anchors from an older sample.
type retainedDependencyUpdate struct {
	original VMRecord
	resolved VMRecord
}

// updateRetainedDependenciesBatch applies a bounded set of repairs in one
// Bolt transaction. Callers split larger sets into bounded batches and check
// cancellation between records and transactions; a failed batch leaves that
// batch untouched while earlier committed batches remain retryable.
func (s *StateStore) updateRetainedDependenciesBatch(ctx context.Context, updates []retainedDependencyUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, update := range updates {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := updateRetainedDependenciesTx(tx, update.original, update.resolved); err != nil {
				return err
			}
		}
		return nil
	})
}

func updateRetainedDependenciesTx(tx *bolt.Tx, original, resolved VMRecord) error {
	records := tx.Bucket(bucketName)
	key := []byte(original.ID)
	raw := records.Get(key)
	target := records
	if raw == nil {
		target = tx.Bucket(retainedRecordBucketName)
		raw = target.Get(key)
	}
	if raw == nil {
		return fmt.Errorf("retained owner was removed")
	}
	var current VMRecord
	if err := json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if !sameRetainedGeneration(original, current) {
		return fmt.Errorf("retained generation changed before dependency update")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"base_mem_path": resolved.BaseMemPath,
		"rootfs_path":   resolved.RootfsPath,
		"delta_dir":     resolved.DeltaDir,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		fields[field] = encoded
	}
	updated, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return target.Put(key, updated)
}

func (m *Manager) rememberRetainedDependencies(original, resolved VMRecord) error {
	if original.BaseMemPath == resolved.BaseMemPath && original.RootfsPath == resolved.RootfsPath && original.DeltaDir == resolved.DeltaDir {
		return nil
	}
	// Preserve the single-owner helper's lifecycle exclusion for callers outside
	// the sampler. The inventory path below uses bounded batches and deliberately
	// does not acquire one vm-op lock per owner.
	ch := m.vmOpCh(original.ID)
	select {
	case ch <- struct{}{}:
		defer func() { <-ch }()
	default:
		return fmt.Errorf("retained owner lifecycle operation in progress")
	}
	return m.persistRetainedDependencies(context.Background(), []retainedDependencyUpdate{{original: original, resolved: resolved}})
}

const retainedDependencyBatchSize = 64

// persistRetainedDependencies commits dependency anchors in bounded batches.
// It deliberately avoids vmOpCh: acquiring one lifecycle lock per owner can
// turn a background inventory into thousands of contended operations. Tracked
// instances use their short-lived state mutex while the corresponding batch is
// committed, and durable generation checks remain authoritative for untracked
// or concurrently replaced records.
func (m *Manager) persistRetainedDependencies(ctx context.Context, updates []retainedDependencyUpdate) error {
	if m.state == nil || len(updates) == 0 {
		return nil
	}
	for start := 0; start < len(updates); start += retainedDependencyBatchSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+retainedDependencyBatchSize, len(updates))
		batch := updates[start:end]
		// Capture the tracked pointers as one bounded manager-lock read before
		// taking any instance mutex. Lifecycle cleanup takes m.mu before the
		// instance mutex; reacquiring m.mu for the next owner while holding an
		// earlier instance mutex would invert that order and deadlock cleanup.
		tracked := make(map[string]*VMInstance, len(batch))
		m.mu.RLock()
		for _, update := range batch {
			if _, seen := tracked[update.original.ID]; seen {
				continue
			}
			tracked[update.original.ID] = m.vms[update.original.ID]
		}
		m.mu.RUnlock()
		// A captured pointer may be removed or replaced before the Bolt write;
		// updateRetainedDependenciesTx rechecks the durable generation, so the
		// pointer snapshot never authorizes an anchor for a newer lifecycle.
		locked := make([]*VMInstance, 0, len(batch))
		lockedByID := make(map[string]*VMInstance, len(batch))
		// Lock only tracked instances, in capture order. Lifecycle writers take
		// the same instance mutex before persisting their record, so they cannot
		// overwrite a successful batch with stale dependency fields.
		for _, update := range batch {
			if err := ctx.Err(); err != nil {
				for _, held := range locked {
					held.mu.Unlock()
				}
				return err
			}
			inst := tracked[update.original.ID]
			if inst == nil {
				continue
			}
			if _, ok := lockedByID[update.original.ID]; ok {
				continue
			}
			if !inst.mu.TryLock() {
				for _, held := range locked {
					held.mu.Unlock()
				}
				return fmt.Errorf("retained instance lifecycle operation in progress")
			}
			lockedByID[update.original.ID] = inst
			locked = append(locked, inst)
			if hook := m.retainedDependencyLockHook; hook != nil {
				hook(inst.ID)
			}
		}
		err := m.state.updateRetainedDependenciesBatch(ctx, batch)
		if err == nil {
			for _, update := range batch {
				inst := lockedByID[update.original.ID]
				if inst == nil {
					continue
				}
				if !sameRetainedGeneration(update.original, toRecordLocked(inst)) {
					err = fmt.Errorf("retained instance changed before dependency update")
					break
				}
				inst.BaseMemPath = update.resolved.BaseMemPath
				inst.Config.RootfsPath = update.resolved.RootfsPath
				inst.Config.DeltaDir = update.resolved.DeltaDir
			}
		}
		for _, held := range locked {
			held.mu.Unlock()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) retainedStorageInventory(ctx context.Context, measure func(*os.File, int) ([]retainedstorage.Extent, string, error)) (*retainedstorage.Inventory, error) {
	return m.retainedStorageInventoryWithPersistence(ctx, measure, true)
}

func (m *Manager) retainedStorageInventoryWithPersistence(ctx context.Context, measure func(*os.File, int) ([]retainedstorage.Extent, string, error), persist bool) (*retainedstorage.Inventory, error) {
	epoch := m.storageEpoch.Load()
	if m.storageMutations.Load() != 0 || m.state == nil {
		return nil, fmt.Errorf("retained inventory not ready")
	}
	records, err := m.state.retainedRecordsContext(ctx)
	if err != nil {
		return nil, err
	}
	inv := &retainedstorage.Inventory{Version: retainedstorage.Version, Owners: make([]retainedstorage.Owner, 0)}
	observations := make([]retainedFileObservation, 0)
	dependencyUpdates := make([]retainedDependencyUpdate, 0)
	remaining := retainedstorage.MaxExtents
	add := func(kind, id string, paths []string, baselinePath string) error {
		if len(inv.Owners) >= retainedstorage.MaxOwners {
			return fmt.Errorf("retained owner budget exceeded")
		}
		owner := retainedstorage.Owner{Kind: kind, ID: id, Extents: make([]retainedstorage.Extent, 0)}
		seen := map[string]bool{}
		digest := sha256.New()
		var baselineBytes int64
		var baselineGeneration string
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
			if baselinePath != "" && filepath.Clean(path) == filepath.Clean(baselinePath) {
				// The shared baseline identity is derived solely from the
				// authoritative allocation generation returned for that file.
				// Do not fold private owner artifacts into this identity: their
				// replacement must advance the owner generation without making
				// a still-shared baseline look like a new allocation.
				baselineGeneration = generation
				for _, extent := range extents {
					if baselineBytes > math.MaxInt64-extent.Length {
						return fmt.Errorf("retained baseline allocation overflow")
					}
					baselineBytes += extent.Length
				}
			}
			fmt.Fprintf(digest, "%s\x00%s\x00", path, generation)
			observations = append(observations, retainedFileObservation{path, info})
		}
		owner.Generation = hex.EncodeToString(digest.Sum(nil))
		if baselinePath != "" {
			if baselineGeneration == "" {
				return fmt.Errorf("retained baseline allocation generation unavailable")
			}
			baselineDigest := sha256.Sum256([]byte(baselineGeneration))
			owner.Baseline = &retainedstorage.Baseline{Path: baselinePath, Generation: hex.EncodeToString(baselineDigest[:]), AllocatedBytes: baselineBytes}
		}
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
			dependencyUpdates = append(dependencyUpdates, retainedDependencyUpdate{original: rec, resolved: resolved})
		}
		baselinePath := resolved.RootfsPath
		if baselinePath == "" {
			baselinePath = resolved.BasePath
		}
		if err := add("sandbox", rec.ID, paths, baselinePath); err != nil {
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
		manifestBytes := 0
		for _, entry := range entries {
			if _, err := uuid.Parse(entry.Name()); err != nil || !entry.IsDir() {
				continue
			}
			path := filepath.Join(dir.Name(), entry.Name(), savedSnapshotManifestName)
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			info, statErr := f.Stat()
			if statErr != nil {
				f.Close()
				return nil, statErr
			}
			if info.Size() > 1<<20 || info.Size() < 0 || manifestBytes > retainedstorage.MaxManifestBytes-int(info.Size()) {
				f.Close()
				return nil, fmt.Errorf("saved snapshot manifest input budget exceeded")
			}
			manifestBytes += int(info.Size())
			var man SavedSnapshotManifest
			err = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&man)
			f.Close()
			if err != nil {
				return nil, err
			}
			if man.Version != savedSnapshotVersion || man.SnapshotID != entry.Name() || man.DiskPath == "" || (man.Kind != SavedSnapshotFS && man.Kind != SavedSnapshotMemFS) || (man.Kind == SavedSnapshotMemFS && (man.MemPath == "" || man.SnapshotPath == "")) {
				return nil, fmt.Errorf("incomplete saved snapshot manifest")
			}
			observations = append(observations, retainedFileObservation{path, info})
			paths, err := appendRetainedCompanions([]string{path, man.DiskPath, man.BasePath, man.SnapshotPath, man.MemPath, man.BaseMemPath}, man.SnapshotPath, man.MemPath, man.BaseMemPath)
			if err != nil {
				return nil, err
			}
			if err := add("snapshot", man.SnapshotID, paths, man.BasePath); err != nil {
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
		if !os.SameFile(o.info, info) || !sameRetainedFileMetadata(o.info.Sys(), info.Sys()) {
			return nil, fmt.Errorf("retained artifact changed during inventory")
		}
	}
	after, err := m.state.retainedRecordsContext(ctx)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(records, after) || m.storageMutations.Load() != 0 || m.storageEpoch.Load() != epoch {
		return nil, fmt.Errorf("retained generation changed during inventory")
	}
	if len(dependencyUpdates) > 0 {
		if !persist {
			return nil, fmt.Errorf("retained dependency metadata still requires persistence")
		}
		if err := m.persistRetainedDependencies(ctx, dependencyUpdates); err != nil {
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
