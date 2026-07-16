package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/presence"
	"github.com/superserve-ai/sandbox/internal/vm/fc/models"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

const (
	// SavedSnapshotsDirName is intentionally not a UUID. The disk-orphan
	// reconciler scans UUID-named direct children of SnapshotDir, so keeping
	// reusable snapshots in this separate tree prevents source-sandbox cleanup
	// from quarantining artifacts still referenced by forks.
	SavedSnapshotsDirName = "saved"

	savedSnapshotSchemaVersion = 1
	savedSnapshotManifestName  = "manifest.json"

	diskArtifactBlockDelta = "block_delta"
	diskArtifactOverlay    = "overlay"
	diskArtifactFull       = "full"

	savedSnapshotSourceRecoveryTimeout  = 30 * time.Second
	savedSnapshotSourceRecoveryAttempts = 3
	savedSnapshotSourceResumeFailedKey  = "saved_snapshot_source_resume_failed"
)

// ErrSavedSnapshotSourceResume marks the one capture failure that changes the
// source's availability: Firecracker accepted the freeze/snapshot operation
// but could not be returned to running. The gRPC adapter attaches a stable
// machine-readable reason so the control plane can fail the source row rather
// than release the capture claim while reporting it as active.
var ErrSavedSnapshotSourceResume = errors.New("saved snapshot source failed to resume")

// SavedSnapshotResources is the immutable VM shape recorded by a saved
// snapshot. Firecracker snapshots cannot be restored at a different shape.
type SavedSnapshotResources struct {
	VCPU        uint32 `json:"vcpu_count"`
	MemoryMiB   uint32 `json:"memory_mib"`
	DiskSizeMiB uint32 `json:"disk_size_mib"`
}

// SavedSnapshotArtifacts is the VMD-internal artifact metadata returned to
// the control plane. Paths must not be exposed by public API responses.
type SavedSnapshotArtifacts struct {
	ManifestPath    string
	SnapshotPath    string
	MemFilePath     string
	MemoryBasePath  string
	DiskBasePath    string
	DiskDeltaPath   string
	DiskOverlayPath string
	DiskFullPath    string
}

// SavedSnapshot is the committed result of CreateSavedSnapshot.
type SavedSnapshot struct {
	SchemaVersion          uint32
	SnapshotID             string
	SourceVMID             string
	SourceState            string
	CreatedAt              time.Time
	Resources              SavedSnapshotResources
	Artifacts              SavedSnapshotArtifacts
	LogicalSizeBytes       int64
	ExclusiveSizeBytes     int64
	SourceLogicalSizeBytes int64
	// SourceExclusiveSizeBytes is the source-owned writable generation that
	// became retained by this branch. The control-plane layer ledger transfers
	// it from current writable usage to retained usage without charging the
	// reflink again to this snapshot.
	SourceExclusiveSizeBytes int64
	ManifestDigest           string
}

// savedSnapshotManifest is the durable commit record. All owned artifact
// paths resolve inside the manifest directory; base paths are immutable
// references owned by an ancestor template/layer.
type savedSnapshotManifest struct {
	SchemaVersion        uint32                 `json:"schema_version"`
	SnapshotID           string                 `json:"snapshot_id"`
	SourceVMID           string                 `json:"source_vm_id"`
	SourceState          string                 `json:"source_state"`
	CreatedAt            time.Time              `json:"created_at"`
	Resources            SavedSnapshotResources `json:"resources"`
	VMStatePath          string                 `json:"vmstate_path"`
	Memory               savedMemoryArtifact    `json:"memory"`
	Disk                 savedDiskArtifact      `json:"disk"`
	ArtifactSHA256       map[string]string      `json:"artifact_sha256"`
	LogicalBytes         int64                  `json:"logical_size_bytes"`
	ExclusiveBytes       int64                  `json:"exclusive_size_bytes"`
	SourceLogicalBytes   int64                  `json:"source_logical_size_bytes"`
	SourceExclusiveBytes int64                  `json:"source_exclusive_size_bytes"`

	// sharedOwnedPaths are files physically branched from an existing immutable
	// layer with a mandatory reflink. They are owned by this manifest (and are
	// therefore removed with it), but their pre-existing extents are not new
	// team storage. This capture-only field is deliberately absent from JSON.
	sharedOwnedPaths      []string
	artifactSizesMeasured bool
}

// savedSourceLayerUsage measures only source-owned extents that a committed
// capture actually turns into shared immutable storage. Merely copying a
// source file (for example vmstate.snap or a Firecracker block delta) does not
// retain that source generation and therefore must not move its bytes into the
// control-plane's retained source layer.
type savedSourceLayerUsage struct {
	logicalBytes   int64
	exclusiveBytes int64
	sources        map[string]savedSourceLayerFile
	finalized      bool
}

type savedSourceLayerFile struct {
	path            string
	logicalBytes    int64
	exclusiveBefore int64
}

// reflink branches one source-owned file and records its pre-branch exclusive
// usage. finalize performs the after measurement only once all destination
// mutations are complete: applying a dirty-memory delta can COW some extents
// back out of the clone, and those bytes are not retained by the branch.
func (u *savedSourceLayerUsage) reflink(ctx context.Context, src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	key := filepath.Clean(src)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		key = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	if u.sources == nil {
		u.sources = make(map[string]savedSourceLayerFile)
	}
	if _, recorded := u.sources[key]; !recorded {
		before, err := exclusiveFileBytes(src)
		if err != nil {
			return err
		}
		u.sources[key] = savedSourceLayerFile{
			path:            src,
			logicalBytes:    info.Size(),
			exclusiveBefore: before,
		}
	}
	return reflinkImmutableFileContext(ctx, src, dst)
}

// finalize records only extents that remain shared after every capture write.
// Running captures call it before unpausing the source; paused captures call it
// while the source process is confirmed dead.
func (u *savedSourceLayerUsage) finalize() error {
	if u.finalized {
		return nil
	}
	var logical, exclusive int64
	for _, source := range u.sources {
		after, err := exclusiveFileBytes(source.path)
		if err != nil {
			return err
		}
		if after > source.exclusiveBefore {
			return fmt.Errorf("source exclusive bytes grew across capture: before=%d after=%d", source.exclusiveBefore, after)
		}
		shared := source.exclusiveBefore - after
		if shared == 0 {
			continue
		}
		if shared > math.MaxInt64-exclusive {
			return errors.New("retained source exclusive byte count overflow")
		}
		if source.logicalBytes > math.MaxInt64-logical {
			return errors.New("retained source logical byte count overflow")
		}
		exclusive += shared
		logical += source.logicalBytes
	}
	u.logicalBytes = logical
	u.exclusiveBytes = exclusive
	u.finalized = true
	return nil
}

type savedMemoryArtifact struct {
	Path     string `json:"path"`
	BasePath string `json:"base_path,omitempty"`
}

type savedDiskArtifact struct {
	Kind     string `json:"kind"`
	BasePath string `json:"base_path,omitempty"`
	Path     string `json:"path"`
}

func (s *savedSnapshotManifest) result(manifestPath string) (*SavedSnapshot, error) {
	manifestDigest, err := sha256File(manifestPath)
	if err != nil {
		return nil, savedSnapshotArtifactIOError("hash saved snapshot manifest", err)
	}
	artifacts := SavedSnapshotArtifacts{
		ManifestPath:   manifestPath,
		SnapshotPath:   s.VMStatePath,
		MemFilePath:    s.Memory.Path,
		MemoryBasePath: s.Memory.BasePath,
		DiskBasePath:   s.Disk.BasePath,
	}
	switch s.Disk.Kind {
	case diskArtifactBlockDelta:
		artifacts.DiskDeltaPath = s.Disk.Path
	case diskArtifactOverlay:
		artifacts.DiskOverlayPath = s.Disk.Path
	case diskArtifactFull:
		artifacts.DiskFullPath = s.Disk.Path
	}
	return &SavedSnapshot{
		SchemaVersion:            s.SchemaVersion,
		SnapshotID:               s.SnapshotID,
		SourceVMID:               s.SourceVMID,
		SourceState:              s.SourceState,
		CreatedAt:                s.CreatedAt,
		Resources:                s.Resources,
		Artifacts:                artifacts,
		LogicalSizeBytes:         s.LogicalBytes,
		ExclusiveSizeBytes:       s.ExclusiveBytes,
		SourceLogicalSizeBytes:   s.SourceLogicalBytes,
		SourceExclusiveSizeBytes: s.SourceExclusiveBytes,
		ManifestDigest:           manifestDigest,
	}, nil
}

func (m *Manager) savedSnapshotDir(sourceVMID, snapshotID string) (string, error) {
	if m.cfg.SnapshotDir == "" || !filepath.IsAbs(m.cfg.SnapshotDir) {
		return "", status.Error(codes.FailedPrecondition, "snapshot_dir must be configured as an absolute path")
	}
	if !isLeafName(sourceVMID) || isReservedRunDirName(sourceVMID) {
		return "", status.Error(codes.InvalidArgument, "source_vm_id must be a valid identifier")
	}
	if !isLeafName(snapshotID) {
		return "", status.Error(codes.InvalidArgument, "snapshot_id must be a valid identifier")
	}
	return filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, sourceVMID, snapshotID), nil
}

// CreateSavedSnapshot captures an immutable reusable snapshot. Active VMs are
// frozen only while Firecracker writes a full memory image and disk delta, then
// returned to running. Paused VMs are copied from their retained checkpoint and
// never woken. The final directory rename is the commit point.
func (m *Manager) CreateSavedSnapshot(ctx context.Context, sourceVMID, snapshotID string) (*SavedSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	finalDir, err := m.savedSnapshotDir(sourceVMID, snapshotID)
	if err != nil {
		return nil, err
	}

	unlock, err := m.lockVMOp(ctx, sourceVMID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	manifestPath := filepath.Join(finalDir, savedSnapshotManifestName)
	if _, statErr := os.Stat(finalDir); statErr == nil {
		manifest, loadErr := m.loadSavedSnapshotManifest(manifestPath)
		if loadErr != nil {
			if status.Code(loadErr) == codes.Unavailable {
				return nil, loadErr
			}
			return nil, status.Errorf(codes.DataLoss,
				"saved snapshot directory exists without a valid committed manifest: %v", loadErr)
		}
		if manifest.SourceVMID != sourceVMID || manifest.SnapshotID != snapshotID {
			return nil, status.Error(codes.DataLoss, "saved snapshot manifest identity mismatch")
		}
		return manifest.result(manifestPath)
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("stat saved snapshot directory: %w", statErr)
	}

	inst, err := m.getInstance(sourceVMID)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	state := inst.Status
	sourceResumePreviouslyFailed := inst.Metadata != nil && inst.Metadata[savedSnapshotSourceResumeFailedKey] == "true"
	sourceSnapshotPath := inst.SnapshotPath
	sourceMemPath := inst.MemFilePath
	sourceMemBasePath := inst.BaseMemPath
	diskPath := inst.DiskPath
	runDirID := inst.RunDirID
	basePath := inst.Config.BasePath
	resources := SavedSnapshotResources{
		VCPU:        inst.Config.VCPU,
		MemoryMiB:   inst.Config.MemoryMiB,
		DiskSizeMiB: inst.Config.DiskSizeMiB,
	}
	inst.mu.RUnlock()
	if sourceResumePreviouslyFailed {
		return nil, ErrSavedSnapshotSourceResume
	}

	if state != StatusRunning && state != StatusPaused {
		return nil, status.Errorf(codes.FailedPrecondition,
			"vm %s cannot be snapshotted from state %s", sourceVMID, state)
	}
	if state == StatusPaused {
		// PauseVM can preserve a valid checkpoint even when its final systemd
		// stop is inconclusive. That is sufficient for retrying pause, but not
		// for copying a supposedly immutable disk offline: a lingering reader/
		// writer could tear the saved artifact. Require positive process death.
		confirmCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		unitErr := unitConfirmedInactive(confirmCtx, systemdUnitName(sourceVMID))
		cancel()
		if unitErr != nil {
			return nil, status.Errorf(codes.Unavailable, "paused source process state is inconclusive: %v", unitErr)
		}
		pids, scanErr := vmFirecrackerPIDs(sourceVMID)
		if scanErr != nil {
			return nil, status.Errorf(codes.Unavailable, "inspect paused source processes: %v", scanErr)
		}
		if len(pids) > 0 {
			return nil, status.Error(codes.Unavailable, "paused source Firecracker process is still running")
		}
	}
	if resources.VCPU == 0 || resources.MemoryMiB == 0 {
		return nil, status.Error(codes.FailedPrecondition, "source VM resource shape is incomplete")
	}
	if runDirID == "" {
		runDirID = sourceVMID
	}
	if diskPath == "" {
		name := "rootfs.ext4"
		if basePath != "" {
			name = "overlay.ext4"
		}
		diskPath = filepath.Join(m.cfg.RunDir, runDirID, name)
	}
	if resources.DiskSizeMiB == 0 {
		if info, statErr := os.Stat(diskPath); statErr == nil {
			resources.DiskSizeMiB = uint32((info.Size() + (1 << 20) - 1) >> 20)
		}
	}

	parentDir := filepath.Dir(finalDir)
	savedRoot := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName)
	_, sourceDirStatErr := os.Stat(parentDir)
	sourceDirWasMissing := os.IsNotExist(sourceDirStatErr)
	if sourceDirStatErr != nil && !sourceDirWasMissing {
		return nil, fmt.Errorf("stat saved snapshot source directory: %w", sourceDirStatErr)
	}
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return nil, fmt.Errorf("create saved snapshot parent: %w", err)
	}
	if err := ensureNoSymlinkDirs(savedRoot, parentDir); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "unsafe saved snapshot directory: %v", err)
	}
	if sourceDirWasMissing {
		if err := fsyncDir(savedRoot); err != nil {
			return nil, fmt.Errorf("fsync saved snapshot root after source directory create: %w", err)
		}
	}
	// A host crash may leave the staging directory from this exact durable
	// intent behind. The source VM operation lock serializes same-source
	// captures, so these same-ID directories cannot belong to a live peer.
	stalePattern := filepath.Join(parentDir, "."+snapshotID+".tmp-*")
	if staleDirs, globErr := filepath.Glob(stalePattern); globErr != nil {
		return nil, fmt.Errorf("find stale saved snapshot staging directories: %w", globErr)
	} else {
		for _, staleDir := range staleDirs {
			if err := os.RemoveAll(staleDir); err != nil {
				return nil, fmt.Errorf("remove stale saved snapshot staging directory: %w", err)
			}
		}
	}
	tmpDir := filepath.Join(parentDir, "."+snapshotID+".tmp-"+uuid.NewString())
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("create saved snapshot staging dir: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	createdAt := time.Now().UTC()
	manifest := &savedSnapshotManifest{
		SchemaVersion: savedSnapshotSchemaVersion,
		SnapshotID:    snapshotID,
		SourceVMID:    sourceVMID,
		SourceState:   state.String(),
		CreatedAt:     createdAt,
		Resources:     resources,
		VMStatePath:   filepath.Join(finalDir, "vmstate.snap"),
		Memory: savedMemoryArtifact{
			Path: filepath.Join(finalDir, "mem.snap"),
		},
	}
	sourceLayer := &savedSourceLayerUsage{}

	if state == StatusRunning {
		err = m.captureRunningSavedSnapshot(ctx, inst, tmpDir, finalDir, diskPath, basePath, manifest, sourceLayer)
	} else {
		err = m.capturePausedSavedSnapshot(ctx, tmpDir, finalDir, sourceSnapshotPath, sourceMemPath, sourceMemBasePath, diskPath, basePath, manifest, sourceLayer)
	}
	if err != nil {
		return nil, err
	}
	if err := sourceLayer.finalize(); err != nil {
		return nil, savedSnapshotCaptureCopyError("measure retained source layer", err)
	}
	manifest.SourceLogicalBytes = sourceLayer.logicalBytes
	manifest.SourceExclusiveBytes = sourceLayer.exclusiveBytes
	if err := populateSavedSnapshotDigests(tmpDir, finalDir, manifest); err != nil {
		return nil, fmt.Errorf("digest saved snapshot artifacts: %w", err)
	}

	if !manifest.artifactSizesMeasured {
		logical, exclusive, err := snapshotArtifactSizesWithShared(
			tmpDir,
			manifest.sharedOwnedPaths,
			manifest.Memory.BasePath,
			manifest.Disk.BasePath,
		)
		if err != nil {
			return nil, fmt.Errorf("measure saved snapshot artifacts: %w", err)
		}
		manifest.LogicalBytes = logical
		manifest.ExclusiveBytes = exclusive
	}

	if err := writeSavedSnapshotManifest(tmpDir, manifest); err != nil {
		return nil, err
	}
	if err := makeSnapshotArtifactsReadOnly(tmpDir); err != nil {
		return nil, err
	}
	if err := fsyncTree(tmpDir); err != nil {
		return nil, fmt.Errorf("fsync saved snapshot artifacts: %w", err)
	}

	if err := os.Rename(tmpDir, finalDir); err != nil {
		// Another daemon/process may have committed the same id after our first
		// existence check. Treat an identical committed manifest as success.
		if existing, loadErr := m.loadSavedSnapshotManifest(manifestPath); loadErr == nil &&
			existing.SourceVMID == sourceVMID && existing.SnapshotID == snapshotID {
			return existing.result(manifestPath)
		}
		return nil, fmt.Errorf("commit saved snapshot directory: %w", err)
	}
	committed = true
	if err := fsyncDir(parentDir); err != nil {
		return nil, fmt.Errorf("fsync saved snapshot parent: %w", err)
	}
	return manifest.result(manifestPath)
}

func (m *Manager) captureRunningSavedSnapshot(ctx context.Context, inst *VMInstance, tmpDir, finalDir, diskPath, basePath string, manifest *savedSnapshotManifest, sourceLayer *savedSourceLayerUsage) error {
	tmpSnapshot := filepath.Join(tmpDir, "vmstate.snap")

	inst.mu.RLock()
	socketPath := inst.SocketPath
	dirtyTracked := inst.DirtyTracked
	sourceMemPath := inst.MemFilePath
	sourceMemBasePath := inst.BaseMemPath
	inst.mu.RUnlock()

	incremental := m.cfg.IncrementalSnapshotEnabled && dirtyTracked && sourceMemPath != "" && fileExists(sourceMemPath)
	var captureErr error
	if incremental {
		rawDelta := filepath.Join(tmpDir, "mem.capture.diff")
		captureErr = CreateDiffSnapshotContext(ctx, socketPath, tmpSnapshot, rawDelta)
		// A successful Diff consumes Firecracker's current dirty bitmap, and an
		// HTTP error cannot prove the operation was not applied before its response
		// was lost. Conservatively disarm after every attempted Diff. At worst a
		// pre-emission failure makes the next capture Full; leaving it armed after
		// an ambiguous success would silently omit consumed pages.
		inst.mu.Lock()
		inst.DirtyTracked = false
		inst.mu.Unlock()
		// DirtyTracked describes only the live Firecracker process and therefore
		// defaults to false after restart, but persist the surrounding instance
		// state now as the same durability boundary used by a successful Full.
		m.persistState(inst)
		if captureErr == nil {
			// The saved branch below is intentionally separate from the source's
			// runtime checkpoint, so that checkpoint is no longer a valid target for
			// another in-place Diff. Disarm before materialization: ENOSPC, a torn
			// presence sidecar, digest failure, or an interrupted manifest commit must
			// all force the source's next pause/capture down the Full path rather than
			// silently omit the pages consumed by this successful emission.
			captureErr = materializeSavedMemoryBranch(ctx, tmpDir, finalDir, sourceMemPath, sourceMemBasePath, rawDelta, manifest, sourceLayer)
		}
	} else {
		tmpMem := filepath.Join(tmpDir, "mem.snap")
		blockDeltaDir := ""
		if basePath != "" {
			blockDeltaDir = tmpDir
		}
		captureErr = CreateSnapshotContext(ctx, socketPath, tmpSnapshot, tmpMem, blockDeltaDir, SnapshotNormal)
		if captureErr == nil {
			manifest.Memory.Path = filepath.Join(finalDir, "mem.snap")
		}
	}
	if captureErr == nil {
		if !incremental {
			// A full snapshot resets Firecracker's dirty baseline. Persist this
			// before unpausing so a failed unpause cannot leave stale diff state.
			inst.mu.Lock()
			inst.DirtyTracked = false
			inst.mu.Unlock()
			m.persistState(inst)
		}

		if basePath != "" {
			delta := filepath.Join(tmpDir, "rootfs.delta")
			if fileExists(delta) {
				manifest.Disk = savedDiskArtifact{
					Kind:     diskArtifactBlockDelta,
					BasePath: basePath,
					Path:     filepath.Join(finalDir, "rootfs.delta"),
				}
			} else {
				// Older fork builds may accept block_delta_dir but not emit a
				// delta. Branch the frozen overlay with mandatory COW sharing;
				// silently making a physical copy would violate shadow billing.
				overlay := filepath.Join(tmpDir, "rootfs.overlay")
				if err := sourceLayer.reflink(ctx, diskPath, overlay); err != nil {
					captureErr = savedSnapshotCaptureCopyError("reflink frozen disk overlay", err)
				} else {
					manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, overlay)
					manifest.Disk = savedDiskArtifact{
						Kind:     diskArtifactOverlay,
						BasePath: basePath,
						Path:     filepath.Join(finalDir, "rootfs.overlay"),
					}
				}
			}
		} else {
			full := filepath.Join(tmpDir, "rootfs.ext4")
			if err := sourceLayer.reflink(ctx, diskPath, full); err != nil {
				captureErr = savedSnapshotCaptureCopyError("reflink frozen rootfs", err)
			} else {
				manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, full)
				manifest.Disk = savedDiskArtifact{
					Kind: diskArtifactFull,
					Path: filepath.Join(finalDir, "rootfs.ext4"),
				}
			}
		}
	}
	if captureErr == nil {
		captureErr = sourceLayer.finalize()
	}
	if captureErr == nil {
		// Measure while the source is still frozen. Once it resumes, a write can
		// COW a shared extent away from the source and make the immutable clone
		// look exclusive; charging that clone as well as the already-sealed
		// source generation would double-count the same physical block.
		manifest.LogicalBytes, manifest.ExclusiveBytes, captureErr = snapshotArtifactSizesWithShared(
			tmpDir,
			manifest.sharedOwnedPaths,
			manifest.Memory.BasePath,
			manifest.Disk.BasePath,
		)
		manifest.artifactSizesMeasured = captureErr == nil
	}

	// CreateSnapshot leaves vCPUs paused on success and can also fail after
	// its pause call. Always attempt to restore the source's prior state.
	unpauseErr := unpauseSavedSnapshotSource(socketPath)
	if unpauseErr != nil {
		inst.mu.Lock()
		inst.Status = StatusError
		inst.DirtyTracked = false
		if inst.Metadata == nil {
			inst.Metadata = make(map[string]string)
		}
		inst.Metadata[savedSnapshotSourceResumeFailedKey] = "true"
		inst.mu.Unlock()
		m.persistState(inst)
		containCtx, containCancel := context.WithTimeout(context.Background(), savedSnapshotSourceRecoveryTimeout)
		_, containErr := m.stopVMProcessAndConfirm(containCtx, inst.ID, inst)
		containCancel()
		sourceErr := fmt.Errorf("%w: %v", ErrSavedSnapshotSourceResume, unpauseErr)
		if containErr != nil {
			sourceErr = errors.Join(sourceErr, fmt.Errorf("stop failed snapshot source: %w", containErr))
		}
		if captureErr != nil {
			return errors.Join(
				fmt.Errorf("capture running VM: %w", captureErr),
				sourceErr,
			)
		}
		return sourceErr
	}
	if captureErr != nil {
		return fmt.Errorf("capture running VM: %w", captureErr)
	}
	return nil
}

func materializeSavedMemoryBranch(ctx context.Context, tmpDir, finalDir, sourceMemPath, sourceMemBasePath, rawDelta string, manifest *savedSnapshotManifest, sourceLayer *savedSourceLayerUsage) error {
	deltaPresence, err := presence.Read(rawDelta)
	if err != nil {
		return status.Errorf(codes.DataLoss, "dirty memory delta has no valid presence map: %v", err)
	}

	memName := "mem.snap"
	target := filepath.Join(tmpDir, memName)
	var priorPresence *presence.Bitmap
	if sourceMemBasePath != "" {
		memName = "mem.diff"
		target = filepath.Join(tmpDir, memName)
		if sourceMemPath == sourceMemBasePath {
			baseInfo, statErr := os.Stat(sourceMemBasePath)
			if statErr != nil {
				return savedSnapshotCaptureCopyError("stat memory base", statErr)
			}
			if err := createSparseFile(target, baseInfo.Size()); err != nil {
				return savedSnapshotCaptureCopyError("create saved memory overlay", err)
			}
			manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, target)
		} else {
			if err := sourceLayer.reflink(ctx, sourceMemPath, target); err != nil {
				return savedSnapshotCaptureCopyError("reflink prior memory overlay", err)
			}
			manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, target)
			prior, readErr := presence.Read(sourceMemPath)
			if readErr != nil {
				return status.Errorf(codes.DataLoss, "prior memory overlay has no valid presence map: %v", readErr)
			}
			priorPresence = &prior
		}
	} else {
		if err := sourceLayer.reflink(ctx, sourceMemPath, target); err != nil {
			return savedSnapshotCaptureCopyError("reflink prior full memory", err)
		}
		manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, target)
	}

	if err := applySparseFileContext(ctx, rawDelta, target); err != nil {
		return savedSnapshotCaptureCopyError("apply dirty memory delta", err)
	}
	if sourceMemBasePath != "" {
		bits := append([]uint64(nil), deltaPresence.Bits...)
		if priorPresence != nil {
			if priorPresence.PageSize != deltaPresence.PageSize || priorPresence.NPages != deltaPresence.NPages {
				return status.Error(codes.DataLoss, "memory presence maps have incompatible shapes")
			}
			for i := range bits {
				bits[i] |= priorPresence.Bits[i]
			}
		}
		if err := presence.Write(target, deltaPresence.PageSize, deltaPresence.NPages, bits); err != nil {
			return fmt.Errorf("write accumulated memory presence map: %w", err)
		}
		if err := os.WriteFile(target+".base", []byte(sourceMemBasePath+"\n"), 0o600); err != nil {
			return fmt.Errorf("write saved memory base record: %w", err)
		}
	}
	_ = os.Remove(rawDelta)
	_ = os.Remove(presence.SidecarPath(rawDelta))
	manifest.Memory.Path = filepath.Join(finalDir, memName)
	manifest.Memory.BasePath = sourceMemBasePath
	return nil
}

func unpauseSavedSnapshotSource(socketPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), savedSnapshotSourceRecoveryTimeout)
	defer cancel()
	var errs []error
	for attempt := 0; attempt < savedSnapshotSourceRecoveryAttempts; attempt++ {
		if err := UnpauseVMContext(ctx, socketPath); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
		// PATCH /vm is not an idempotency receipt: Firecracker may apply the
		// resume and lose its response. Resolve that ambiguity from GET / before
		// declaring the source failed. The probe gets a detached recovery budget
		// even when the preceding transport call consumed the outer deadline.
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		state, probeErr := FirecrackerVMStateContext(probeCtx, socketPath)
		probeCancel()
		if probeErr == nil && state == models.InstanceInfoStateRunning {
			return nil
		}
		if probeErr != nil {
			errs = append(errs, probeErr)
		} else if state != models.InstanceInfoStatePaused {
			errs = append(errs, fmt.Errorf("source VM state after unpause attempt is %q", state))
		}
		if attempt+1 < savedSnapshotSourceRecoveryAttempts {
			select {
			case <-ctx.Done():
				return errors.Join(append(errs, ctx.Err())...)
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			}
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) capturePausedSavedSnapshot(ctx context.Context, tmpDir, finalDir, sourceSnapshotPath, sourceMemPath, sourceMemBasePath, diskPath, basePath string, manifest *savedSnapshotManifest, sourceLayer *savedSourceLayerUsage) error {
	if sourceSnapshotPath == "" || sourceMemPath == "" {
		return status.Error(codes.DataLoss, "paused source has no retained runtime checkpoint")
	}
	if err := copySparseFileContext(ctx, sourceSnapshotPath, filepath.Join(tmpDir, "vmstate.snap")); err != nil {
		return savedSnapshotCaptureCopyError("copy paused VM state", err)
	}

	memoryOwnedBySource := sourceMemPath != sourceMemBasePath
	memName := "mem.snap"
	if isOverlayMemFile(sourceMemPath) {
		memName = "mem.diff"
		if sourceMemBasePath == "" {
			if recorded, ok := readLayeredBase(sourceMemPath); ok {
				sourceMemBasePath = recorded
			}
		}
		if sourceMemBasePath == "" {
			return status.Error(codes.FailedPrecondition, "paused layered memory checkpoint has no immutable base")
		}
	} else {
		sourceMemBasePath = ""
	}
	ownedMemPath := filepath.Join(tmpDir, memName)
	var memReflinkErr error
	if memoryOwnedBySource {
		memReflinkErr = sourceLayer.reflink(ctx, sourceMemPath, ownedMemPath)
	} else {
		memReflinkErr = reflinkImmutableFileContext(ctx, sourceMemPath, ownedMemPath)
	}
	if memReflinkErr != nil {
		return savedSnapshotCaptureCopyError("reflink paused memory checkpoint", memReflinkErr)
	}
	manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, ownedMemPath)
	manifest.Memory.Path = filepath.Join(finalDir, memName)
	manifest.Memory.BasePath = sourceMemBasePath
	if sourceMemBasePath != "" {
		if err := os.WriteFile(filepath.Join(tmpDir, memName)+".base", []byte(sourceMemBasePath+"\n"), 0o600); err != nil {
			return fmt.Errorf("write saved memory base record: %w", err)
		}
		presenceSrc := presence.SidecarPath(sourceMemPath)
		if !fileExists(presenceSrc) {
			return status.Error(codes.DataLoss, "paused layered memory checkpoint has no presence map")
		}
		if err := copySparseFileContext(ctx, presenceSrc, presence.SidecarPath(filepath.Join(tmpDir, memName))); err != nil {
			return savedSnapshotCaptureCopyError("copy memory presence map", err)
		}
	}

	if basePath != "" {
		overlay := filepath.Join(tmpDir, "rootfs.overlay")
		var diskReflinkErr error
		if diskPath != basePath {
			diskReflinkErr = sourceLayer.reflink(ctx, diskPath, overlay)
		} else {
			diskReflinkErr = reflinkImmutableFileContext(ctx, diskPath, overlay)
		}
		if diskReflinkErr != nil {
			return savedSnapshotCaptureCopyError("reflink paused disk overlay", diskReflinkErr)
		}
		manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, overlay)
		manifest.Disk = savedDiskArtifact{
			Kind:     diskArtifactOverlay,
			BasePath: basePath,
			Path:     filepath.Join(finalDir, "rootfs.overlay"),
		}
	} else {
		full := filepath.Join(tmpDir, "rootfs.ext4")
		if err := sourceLayer.reflink(ctx, diskPath, full); err != nil {
			return savedSnapshotCaptureCopyError("reflink paused rootfs", err)
		}
		manifest.sharedOwnedPaths = append(manifest.sharedOwnedPaths, full)
		manifest.Disk = savedDiskArtifact{
			Kind: diskArtifactFull,
			Path: filepath.Join(finalDir, "rootfs.ext4"),
		}
	}
	return nil
}

func savedSnapshotCaptureCopyError(operation string, err error) error {
	if os.IsNotExist(err) {
		return status.Errorf(codes.DataLoss, "%s: source artifact is missing", operation)
	}
	if errors.Is(err, context.Canceled) {
		return status.Errorf(codes.Canceled, "%s: canceled", operation)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Errorf(codes.DeadlineExceeded, "%s: deadline exceeded", operation)
	}
	return status.Errorf(codes.Unavailable, "%s: host filesystem unavailable", operation)
}

// RestoreSavedSnapshot resolves a committed local manifest and restores it
// using the existing snapshot loader. Disk metadata selects either delta
// hydration, a sparse-overlay copy, or a complete legacy-rootfs copy; all
// three create a new child-owned writable file.
func (m *Manager) RestoreSavedSnapshot(ctx context.Context, vmID, manifestPath, expectedManifestDigest string, netCfg *network.Config, egress *network.EgressRules, teamID, ownerID string) (*VMInstance, *SavedSnapshot, error) {
	if len(expectedManifestDigest) != sha256.Size*2 {
		return nil, nil, status.Error(codes.InvalidArgument, "expected manifest digest must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(expectedManifestDigest); err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "expected manifest digest must be a SHA-256 hex digest")
	}
	manifest, err := m.loadSavedSnapshotManifest(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	result, err := manifest.result(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(result.ManifestDigest, expectedManifestDigest) {
		return nil, nil, status.Error(codes.DataLoss, "saved snapshot manifest digest does not match the committed control-plane digest")
	}
	cfg, err := savedSnapshotVMConfig(manifest, egress)
	if err != nil {
		return nil, nil, err
	}
	inst, err := m.RestoreVMSnapshot(ctx, vmID, manifest.VMStatePath, manifest.Memory.Path, cfg, netCfg, teamID, ownerID)
	if err != nil {
		return nil, nil, m.classifySavedSnapshotRestoreError(manifestPath, err)
	}
	return inst, result, nil
}

// classifySavedSnapshotRestoreError keeps deterministic artifact failures
// distinct from host availability failures. Firecracker reports malformed
// snapshot contents as a 400; transport, process, network, and local resource
// failures reach this boundary as ordinary errors and remain retryable.
func (m *Manager) classifySavedSnapshotRestoreError(manifestPath string, restoreErr error) error {
	if restoreErr == nil {
		return nil
	}

	// An artifact can disappear after the initial manifest validation but
	// before/during disk or memory restore. Revalidate first so that race is
	// still reported as stable DataLoss rather than a generic host failure.
	if _, err := m.loadSavedSnapshotManifest(manifestPath); err != nil {
		return err
	}

	if errors.Is(restoreErr, ErrSnapshotLoadRejected) && !isTapDeviceBusyErr(restoreErr) {
		return status.Error(codes.DataLoss, "saved snapshot artifacts were rejected as invalid")
	}

	code := status.Code(restoreErr)
	if code != codes.Unknown && code != codes.Internal {
		return restoreErr
	}
	return status.Error(codes.Unavailable, "saved snapshot host restore failed")
}

func savedSnapshotVMConfig(manifest *savedSnapshotManifest, egress *network.EgressRules) (VMConfig, error) {
	cfg := VMConfig{
		VCPU:                 manifest.Resources.VCPU,
		MemoryMiB:            manifest.Resources.MemoryMiB,
		DiskSizeMiB:          manifest.Resources.DiskSizeMiB,
		EgressPolicy:         egress,
		savedSnapshotRestore: true,
	}
	switch manifest.Disk.Kind {
	case diskArtifactBlockDelta:
		cfg.BasePath = manifest.Disk.BasePath
		cfg.DeltaDir = filepath.Dir(manifest.Disk.Path)
	case diskArtifactOverlay:
		cfg.BasePath = manifest.Disk.BasePath
		cfg.RootfsPath = manifest.Disk.Path
	case diskArtifactFull:
		cfg.RootfsPath = manifest.Disk.Path
	default:
		return VMConfig{}, status.Errorf(codes.DataLoss, "unsupported saved disk artifact kind %q", manifest.Disk.Kind)
	}
	return cfg, nil
}

// DeleteSavedSnapshot removes one leaf artifact directory. Reference safety is
// a control-plane responsibility; VMD constructs the path from validated ids
// and never accepts a caller-provided delete path.
func (m *Manager) DeleteSavedSnapshot(ctx context.Context, sourceVMID, snapshotID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Serialize with capture/pause/resume/restore for the source. Without this
	// lock a cancellation could observe no final directory, finalize its DB
	// delete, and then let the still-running capture publish an unowned
	// immutable directory after the durable cleanup record had disappeared.
	unlock, err := m.lockVMOp(ctx, sourceVMID)
	if err != nil {
		return err
	}
	defer unlock()

	dir, err := m.savedSnapshotDir(sourceVMID, snapshotID)
	if err != nil {
		return err
	}
	root := filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName)
	sourceDir := filepath.Dir(dir)
	if _, statErr := os.Lstat(sourceDir); os.IsNotExist(statErr) {
		return nil
	} else if statErr != nil {
		return fmt.Errorf("stat saved snapshot source directory: %w", statErr)
	}
	if err := ensureNoSymlinkDirs(root, sourceDir); err != nil {
		return status.Errorf(codes.FailedPrecondition, "unsafe saved snapshot delete path: %v", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove saved snapshot artifacts: %w", err)
	}
	// Cancellation can race a daemon crash before the staging directory is
	// atomically renamed into place. Once the durable DB intent is deleting,
	// no later capture may adopt those bytes, so remove every exact same-ID
	// staging directory under the same source lock as the committed path.
	entries, err := os.ReadDir(sourceDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("list saved snapshot staging artifacts: %w", err)
	}
	stagingPrefix := "." + snapshotID + ".tmp-"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), stagingPrefix) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(sourceDir, entry.Name())); err != nil {
			return fmt.Errorf("remove saved snapshot staging artifacts: %w", err)
		}
	}
	// Persist removal of the snapshot entry in its direct parent. If that was
	// the last snapshot, also persist removal of the now-empty source directory
	// in the saved root.
	if err := fsyncDir(sourceDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("fsync saved snapshot source directory: %w", err)
	}
	removedSourceDir := false
	if err := os.Remove(sourceDir); err == nil {
		removedSourceDir = true
	} else if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) {
		return fmt.Errorf("remove empty saved snapshot source directory: %w", err)
	}
	if removedSourceDir {
		if err := fsyncDir(root); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("fsync saved snapshot root: %w", err)
		}
	}
	return nil
}

func (m *Manager) loadSavedSnapshotManifest(manifestPath string) (*savedSnapshotManifest, error) {
	dir, sourceVMID, snapshotID, err := m.validateSavedManifestPath(manifestPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, savedSnapshotArtifactIOError("stat saved snapshot manifest", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest is not a regular file")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, savedSnapshotArtifactIOError("read saved snapshot manifest", err)
	}
	var manifest savedSnapshotManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, status.Errorf(codes.DataLoss, "decode saved snapshot manifest: %v", err)
	}
	if manifest.SchemaVersion != savedSnapshotSchemaVersion {
		return nil, status.Errorf(codes.FailedPrecondition,
			"unsupported saved snapshot schema version %d", manifest.SchemaVersion)
	}
	if manifest.SourceVMID != sourceVMID || manifest.SnapshotID != snapshotID {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest identity does not match its path")
	}
	if manifest.SourceState != StatusRunning.String() && manifest.SourceState != StatusPaused.String() {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest has an invalid source state")
	}
	if manifest.Resources.VCPU == 0 || manifest.Resources.MemoryMiB == 0 {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest has an incomplete resource shape")
	}
	if manifest.LogicalBytes < 0 || manifest.ExclusiveBytes < 0 || manifest.SourceLogicalBytes < 0 || manifest.SourceExclusiveBytes < 0 {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest has invalid storage accounting")
	}

	if err := validateOwnedArtifact(dir, manifest.VMStatePath, "vmstate.snap"); err != nil {
		return nil, err
	}
	memName := filepath.Base(manifest.Memory.Path)
	if memName != "mem.snap" && memName != "mem.diff" {
		return nil, status.Error(codes.DataLoss, "saved snapshot manifest has an invalid memory artifact name")
	}
	if err := validateOwnedArtifact(dir, manifest.Memory.Path, memName); err != nil {
		return nil, err
	}
	if memName == "mem.diff" && manifest.Memory.BasePath == "" {
		return nil, status.Error(codes.DataLoss, "saved memory diff has no base")
	}
	if manifest.Memory.BasePath != "" {
		if err := validateReferencedArtifact(manifest.Memory.BasePath); err != nil {
			return nil, err
		}
		baseRecord := manifest.Memory.Path + ".base"
		if err := validateOwnedArtifact(dir, baseRecord, memName+".base"); err != nil {
			return nil, err
		}
		recorded, err := os.ReadFile(baseRecord)
		if err != nil {
			return nil, savedSnapshotArtifactIOError("read saved memory base record", err)
		}
		if strings.TrimSpace(string(recorded)) != manifest.Memory.BasePath {
			return nil, status.Error(codes.DataLoss, "saved memory base record does not match manifest")
		}
		presencePath := presence.SidecarPath(manifest.Memory.Path)
		if _, err := os.Lstat(presencePath); err == nil {
			if err := validateOwnedArtifact(dir, presencePath, filepath.Base(presencePath)); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, savedSnapshotArtifactIOError("stat saved memory presence map", err)
		}
	}

	var diskName string
	switch manifest.Disk.Kind {
	case diskArtifactBlockDelta:
		diskName = "rootfs.delta"
		if manifest.Disk.BasePath == "" {
			return nil, status.Error(codes.DataLoss, "saved disk delta has no base")
		}
	case diskArtifactOverlay:
		diskName = "rootfs.overlay"
		if manifest.Disk.BasePath == "" {
			return nil, status.Error(codes.DataLoss, "saved disk overlay has no base")
		}
	case diskArtifactFull:
		diskName = "rootfs.ext4"
		if manifest.Disk.BasePath != "" {
			return nil, status.Error(codes.DataLoss, "saved full rootfs unexpectedly has a base")
		}
	default:
		return nil, status.Errorf(codes.DataLoss, "saved snapshot manifest has invalid disk kind %q", manifest.Disk.Kind)
	}
	if err := validateOwnedArtifact(dir, manifest.Disk.Path, diskName); err != nil {
		return nil, err
	}
	if manifest.Disk.BasePath != "" {
		if err := validateReferencedArtifact(manifest.Disk.BasePath); err != nil {
			return nil, err
		}
	}
	if err := verifySavedSnapshotDigests(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

const (
	digestVMState          = "vmstate"
	digestMemory           = "memory"
	digestMemoryBase       = "memory_base"
	digestMemoryBaseRecord = "memory_base_record"
	digestMemoryPresence   = "memory_presence"
	digestDisk             = "disk"
	digestDiskBase         = "disk_base"
)

func savedSnapshotDigestPaths(manifest *savedSnapshotManifest) (map[string]string, error) {
	paths := map[string]string{
		digestVMState: manifest.VMStatePath,
		digestMemory:  manifest.Memory.Path,
		digestDisk:    manifest.Disk.Path,
	}
	if manifest.Memory.BasePath != "" {
		paths[digestMemoryBase] = manifest.Memory.BasePath
		paths[digestMemoryBaseRecord] = manifest.Memory.Path + ".base"
		paths[digestMemoryPresence] = presence.SidecarPath(manifest.Memory.Path)
	}
	if manifest.Disk.BasePath != "" {
		paths[digestDiskBase] = manifest.Disk.BasePath
	}
	for key, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("digest path %q is empty", key)
		}
	}
	return paths, nil
}

func populateSavedSnapshotDigests(tmpDir, finalDir string, manifest *savedSnapshotManifest) error {
	paths, err := savedSnapshotDigestPaths(manifest)
	if err != nil {
		return err
	}
	manifest.ArtifactSHA256 = make(map[string]string, len(paths))
	for key, path := range paths {
		capturePath := path
		if rel, relErr := filepath.Rel(finalDir, path); relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			capturePath = filepath.Join(tmpDir, rel)
		}
		digest, digestErr := sha256File(capturePath)
		if digestErr != nil {
			return fmt.Errorf("%s: %w", key, digestErr)
		}
		manifest.ArtifactSHA256[key] = digest
	}
	return nil
}

func verifySavedSnapshotDigests(manifest *savedSnapshotManifest) error {
	paths, err := savedSnapshotDigestPaths(manifest)
	if err != nil {
		return status.Errorf(codes.DataLoss, "saved snapshot digest manifest is invalid: %v", err)
	}
	if len(manifest.ArtifactSHA256) != len(paths) {
		return status.Error(codes.DataLoss, "saved snapshot digest manifest is incomplete")
	}
	for key, path := range paths {
		want := manifest.ArtifactSHA256[key]
		if len(want) != sha256.Size*2 {
			return status.Errorf(codes.DataLoss, "saved snapshot digest %q is missing or malformed", key)
		}
		got, digestErr := sha256File(path)
		if digestErr != nil {
			return savedSnapshotArtifactIOError("hash saved snapshot artifact", digestErr)
		}
		if got != want {
			return status.Errorf(codes.DataLoss, "saved snapshot artifact digest mismatch: %s", key)
		}
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (m *Manager) validateSavedManifestPath(manifestPath string) (dir, sourceVMID, snapshotID string, err error) {
	if m.cfg.SnapshotDir == "" || !filepath.IsAbs(m.cfg.SnapshotDir) {
		return "", "", "", status.Error(codes.FailedPrecondition, "snapshot_dir must be configured as an absolute path")
	}
	if !filepath.IsAbs(manifestPath) || filepath.Clean(manifestPath) != manifestPath {
		return "", "", "", status.Error(codes.InvalidArgument, "manifest_path must be a clean absolute path")
	}
	root := filepath.Join(filepath.Clean(m.cfg.SnapshotDir), SavedSnapshotsDirName)
	rel, relErr := filepath.Rel(root, manifestPath)
	if relErr != nil {
		return "", "", "", status.Error(codes.InvalidArgument, "manifest_path is outside the saved snapshot root")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 3 || parts[2] != savedSnapshotManifestName || !isLeafName(parts[0]) || !isLeafName(parts[1]) {
		return "", "", "", status.Error(codes.InvalidArgument,
			"manifest_path must have shape <snapshot_dir>/saved/<source_vm_id>/<snapshot_id>/manifest.json")
	}
	dir = filepath.Dir(manifestPath)
	if pathErr := ensureNoSymlinkDirs(root, dir); pathErr != nil {
		if os.IsNotExist(pathErr) {
			return "", "", "", status.Error(codes.DataLoss, "saved snapshot artifact directory is missing on this host")
		}
		var fsErr *os.PathError
		if errors.As(pathErr, &fsErr) {
			return "", "", "", status.Error(codes.Unavailable, "inspect saved snapshot artifact directory failed")
		}
		return "", "", "", status.Error(codes.InvalidArgument, "manifest_path traverses an unsafe directory")
	}
	return dir, parts[0], parts[1], nil
}

func ensureNoSymlinkDirs(root, target string) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q is outside root %q", target, root)
	}
	paths := []string{root}
	if rel != "." {
		cur := root
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			cur = filepath.Join(cur, part)
			paths = append(paths, cur)
		}
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a real directory", path)
		}
	}
	return nil
}

func validateOwnedArtifact(dir, path, name string) error {
	if path != filepath.Join(dir, name) {
		return status.Error(codes.DataLoss, "saved artifact path does not match manifest directory")
	}
	return validateReferencedArtifact(path)
}

func validateReferencedArtifact(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return status.Error(codes.DataLoss, "saved artifact path is not a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return savedSnapshotArtifactIOError("stat saved snapshot artifact", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return status.Error(codes.DataLoss, "saved artifact is not a regular non-symlink file")
	}
	return nil
}

// savedSnapshotArtifactIOError treats disappearance as corruption of the
// committed immutable snapshot, while keeping all other host filesystem
// failures retryable. The latter includes a temporarily unavailable mount,
// permission/credential refresh, and transient device I/O errors.
func savedSnapshotArtifactIOError(operation string, err error) error {
	if os.IsNotExist(err) {
		return status.Errorf(codes.DataLoss, "%s: artifact is missing", operation)
	}
	return status.Errorf(codes.Unavailable, "%s: host filesystem unavailable", operation)
}

func writeSavedSnapshotManifest(dir string, manifest *savedSnapshotManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode saved snapshot manifest: %w", err)
	}
	data = append(data, '\n')
	tmp := filepath.Join(dir, savedSnapshotManifestName+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create saved snapshot manifest: %w", err)
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write saved snapshot manifest: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close saved snapshot manifest: %w", closeErr)
	}
	if err := os.Rename(tmp, filepath.Join(dir, savedSnapshotManifestName)); err != nil {
		return fmt.Errorf("commit saved snapshot manifest: %w", err)
	}
	return fsyncDir(dir)
}

func makeSnapshotArtifactsReadOnly(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if err := os.Chmod(path, 0o444); err != nil {
			return fmt.Errorf("chmod saved artifact %s: %w", path, err)
		}
		return nil
	})
}

func fsyncTree(dir string) error {
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func snapshotArtifactSizes(dir string, referencedPaths ...string) (logical, exclusive int64, err error) {
	return snapshotArtifactSizesWithShared(dir, nil, referencedPaths...)
}

// snapshotArtifactSizesWithShared reports logical reconstruction size and the
// allocated bytes newly introduced by this capture. FIEMAP distinguishes the
// still-shared portions of a mandatory reflink from blocks COW-written into
// that inode while a memory/disk delta was materialized.
func snapshotArtifactSizesWithShared(dir string, sharedOwnedPaths []string, referencedPaths ...string) (logical, exclusive int64, err error) {
	seen := make(map[string]struct{})
	shared := make(map[string]struct{}, len(sharedOwnedPaths))
	for _, path := range sharedOwnedPaths {
		shared[filepath.Clean(path)] = struct{}{}
	}
	addLogical := func(path string, info os.FileInfo) {
		key := filepath.Clean(path)
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			key = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		logical += info.Size()
	}
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("saved artifact is not regular: %s", path)
		}
		addLogical(path, info)
		if _, isShared := shared[filepath.Clean(path)]; isShared {
			owned, usageErr := exclusiveFileBytes(path)
			if usageErr != nil {
				return usageErr
			}
			exclusive += owned
		} else {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				exclusive += st.Blocks * 512
			} else {
				exclusive += info.Size()
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	for _, path := range referencedPaths {
		if path == "" {
			continue
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			return 0, 0, statErr
		}
		if !info.Mode().IsRegular() {
			return 0, 0, fmt.Errorf("referenced snapshot base is not regular: %s", path)
		}
		addLogical(path, info)
	}
	return logical, exclusive, err
}

// reflinkImmutableFileContext creates a new inode whose existing extents stay
// physically shared with src. --reflink=always is intentional: a transparent
// byte-copy fallback would make deduplicated shadow usage dishonest. GNU cp
// only permits reflink copies with sparse=auto; the clone still preserves the
// source's holes and shared extents.
func reflinkImmutableFileContext(ctx context.Context, src, dst string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if info, err := os.Lstat(src); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", src)
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	cmd := exec.CommandContext(ctx, "cp", "--reflink=always", "--sparse=auto", "--", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mandatory reflink %s to %s: %s: %w", src, dst, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *Manager) savedSnapshotsSupported() bool {
	if m == nil || !filepath.IsAbs(m.cfg.SnapshotDir) || !filepath.IsAbs(m.cfg.RunDir) ||
		!m.cfg.UffdEnabled || !m.cfg.ResumeUffdEnabled || !m.cfg.IncrementalSnapshotEnabled {
		return false
	}
	if m.savedSnapshotCapabilityProbe == nil && !savedSnapshotExtentAccountingSupported() {
		return false
	}
	m.savedSnapshotCapabilityOnce.Do(func() {
		probe := m.savedSnapshotCapabilityProbe
		if probe == nil {
			probe = m.probeSavedSnapshotReflinks
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := probe(ctx); err != nil {
			m.log.Warn().Err(vmdclient.SanitizeSavedSnapshotError(
				vmdclient.SavedSnapshotOperationCapabilityCheck, err,
			)).Msg("saved snapshots disabled: mandatory reflink probe failed")
			return
		}
		m.savedSnapshotCapability = true
	})
	return m.savedSnapshotCapability
}

// probeSavedSnapshotReflinks verifies both CoW paths used by capture: paused
// artifacts branch within SnapshotDir, while an active VM's writable disk
// branches from RunDir into SnapshotDir. A non-empty source is intentional;
// cloning an empty file can succeed without proving extent-sharing support.
func (m *Manager) probeSavedSnapshotReflinks(ctx context.Context) error {
	probeDir, err := os.MkdirTemp(m.cfg.SnapshotDir, ".saved-snapshot-reflink-probe-")
	if err != nil {
		return fmt.Errorf("create snapshot reflink probe dir: %w", err)
	}
	defer os.RemoveAll(probeDir)
	probePayload := bytes.Repeat([]byte("superserve-saved-snapshot-reflink-capability\n"), 4096)

	writeProbe := func(dir, pattern string) (string, error) {
		f, createErr := os.CreateTemp(dir, pattern)
		if createErr != nil {
			return "", createErr
		}
		path := f.Name()
		if _, writeErr := f.Write(probePayload); writeErr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", writeErr
		}
		if syncErr := f.Sync(); syncErr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", syncErr
		}
		if closeErr := f.Close(); closeErr != nil {
			_ = os.Remove(path)
			return "", closeErr
		}
		return path, nil
	}
	verifyClone := func(label, path string) error {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s clone: %w", label, readErr)
		}
		if !bytes.Equal(got, probePayload) {
			return fmt.Errorf("%s clone content differs from its source", label)
		}
		exclusive, usageErr := exclusiveFileBytes(path)
		if usageErr != nil {
			return fmt.Errorf("measure %s clone extents: %w", label, usageErr)
		}
		if exclusive != 0 {
			return fmt.Errorf("%s clone retained %d unshared bytes", label, exclusive)
		}
		return nil
	}

	runSource, err := writeProbe(m.cfg.RunDir, ".saved-snapshot-run-probe-")
	if err != nil {
		return fmt.Errorf("create run-dir reflink probe: %w", err)
	}
	defer os.Remove(runSource)
	runClone := filepath.Join(probeDir, "from-run")
	if err := reflinkImmutableFileContext(ctx, runSource, runClone); err != nil {
		return fmt.Errorf("probe RunDir to SnapshotDir reflink: %w", err)
	}
	if err := verifyClone("RunDir to SnapshotDir", runClone); err != nil {
		return fmt.Errorf("probe reflink extent accounting: %w", err)
	}

	snapshotSource, err := writeProbe(probeDir, "snapshot-source-")
	if err != nil {
		return fmt.Errorf("create snapshot-dir reflink probe: %w", err)
	}
	snapshotClone := filepath.Join(probeDir, "within-snapshot")
	if err := reflinkImmutableFileContext(ctx, snapshotSource, snapshotClone); err != nil {
		return fmt.Errorf("probe SnapshotDir reflink: %w", err)
	}
	if err := verifyClone("SnapshotDir", snapshotClone); err != nil {
		return fmt.Errorf("probe snapshot reflink extent accounting: %w", err)
	}
	return nil
}

func allocatedFileBytes(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512, nil
	}
	return info.Size(), nil
}

func exclusivePathsBytes(paths ...string) (int64, error) {
	seen := make(map[string]struct{}, len(paths))
	var total int64
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		key := filepath.Clean(path)
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			key = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		owned, err := exclusiveFileBytes(path)
		if err != nil {
			return 0, err
		}
		if owned > math.MaxInt64-total {
			return 0, errors.New("source writable byte count overflow")
		}
		total += owned
	}
	return total, nil
}

func logicalPathsBytes(paths ...string) (int64, error) {
	seen := make(map[string]struct{}, len(paths))
	var total int64
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		key := filepath.Clean(path)
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			key = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if info.Size() > math.MaxInt64-total {
			return 0, errors.New("writable layer logical byte count overflow")
		}
		total += info.Size()
	}
	return total, nil
}

// SandboxWritableLayerUsage measures the currently persisted sandbox-owned
// generation. It is called after pause for shadow reconciliation; immutable
// bases are either omitted explicitly or excluded by FIEMAP's SHARED flag.
func (m *Manager) SandboxWritableLayerUsage(vmID string) (logical, exclusive int64, err error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return 0, 0, status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	inst, err := m.getInstance(vmID)
	if err != nil {
		return 0, 0, err
	}
	inst.mu.RLock()
	paths := []string{inst.DiskPath, inst.SnapshotPath}
	if inst.MemFilePath != inst.BaseMemPath {
		paths = append(paths, inst.MemFilePath)
		if inst.MemFilePath != "" {
			for _, sidecar := range []string{presence.SidecarPath(inst.MemFilePath), inst.MemFilePath + ".base"} {
				if fileExists(sidecar) {
					paths = append(paths, sidecar)
				}
			}
		}
	}
	inst.mu.RUnlock()
	logical, err = logicalPathsBytes(paths...)
	if err != nil {
		return 0, 0, savedSnapshotArtifactIOError("measure writable layer logical bytes", err)
	}
	exclusive, err = exclusivePathsBytes(paths...)
	if err != nil {
		return 0, 0, savedSnapshotArtifactIOError("measure writable layer exclusive bytes", err)
	}
	return logical, exclusive, nil
}

func createSparseFile(path string, size int64) (retErr error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); retErr == nil && closeErr != nil {
			retErr = closeErr
		}
		if retErr != nil {
			_ = os.Remove(path)
		}
	}()
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Sync()
}

// applySparseFileContext overwrites only src's allocated extents in an
// existing same-sized branch. It is used to fold a fresh Firecracker dirty
// delta into a reflink without materializing clean pages.
func applySparseFileContext(ctx context.Context, src, dst string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	dstInfo, err := dstFile.Stat()
	if err != nil {
		return err
	}
	if srcInfo.Size() != dstInfo.Size() {
		return fmt.Errorf("memory delta size %d does not match branch size %d", srcInfo.Size(), dstInfo.Size())
	}
	for offset := int64(0); offset < srcInfo.Size(); {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, seekErr := unix.Seek(int(srcFile.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(seekErr, syscall.ENXIO) {
			break
		}
		if seekErr != nil {
			return seekErr
		}
		hole, seekErr := unix.Seek(int(srcFile.Fd()), data, unix.SEEK_HOLE)
		if seekErr != nil {
			return seekErr
		}
		if hole > srcInfo.Size() {
			hole = srcInfo.Size()
		}
		if hole <= data {
			return fmt.Errorf("invalid sparse extent [%d,%d) in %s", data, hole, src)
		}
		if _, err := dstFile.Seek(data, io.SeekStart); err != nil {
			return err
		}
		if err := copyNWithContext(ctx, dstFile, io.NewSectionReader(srcFile, data, hole-data), hole-data); err != nil {
			return err
		}
		offset = hole
	}
	return dstFile.Sync()
}

// copySparseFile copies data extents into newly allocated blocks. It never
// reflinks: the destination is an independently owned immutable artifact, so
// its st_blocks value is a meaningful V1 exclusive-byte measurement.
func copySparseFile(src, dst string) (retErr error) {
	return copySparseFileContext(context.Background(), src, dst)
}

func copySparseFileContext(ctx context.Context, src, dst string) (retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lstat, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !lstat.Mode().IsRegular() || lstat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source is not a regular non-symlink file: %s", src)
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	info, err := srcFile.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dstFile.Close(); retErr == nil && closeErr != nil {
			retErr = closeErr
		}
		if retErr != nil {
			_ = os.Remove(dst)
		}
	}()
	if err := dstFile.Truncate(info.Size()); err != nil {
		return err
	}
	if info.Size() == 0 {
		return dstFile.Sync()
	}

	copyDense := func() error {
		if _, err := srcFile.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := dstFile.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return copyNWithContext(ctx, dstFile, srcFile, info.Size())
	}

	offset := int64(0)
	for offset < info.Size() {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, seekErr := unix.Seek(int(srcFile.Fd()), offset, unix.SEEK_DATA)
		if seekErr != nil {
			if errors.Is(seekErr, syscall.ENXIO) {
				break
			}
			if errors.Is(seekErr, syscall.EINVAL) || errors.Is(seekErr, syscall.ENOTSUP) {
				if err := copyDense(); err != nil {
					return err
				}
				return dstFile.Sync()
			}
			return seekErr
		}
		hole, seekErr := unix.Seek(int(srcFile.Fd()), data, unix.SEEK_HOLE)
		if seekErr != nil {
			return seekErr
		}
		if hole > info.Size() {
			hole = info.Size()
		}
		if hole <= data {
			return fmt.Errorf("invalid sparse extent [%d,%d) in %s", data, hole, src)
		}
		if _, err := dstFile.Seek(data, io.SeekStart); err != nil {
			return err
		}
		if err := copyNWithContext(ctx, dstFile, io.NewSectionReader(srcFile, data, hole-data), hole-data); err != nil {
			return err
		}
		offset = hole
	}
	return dstFile.Sync()
}

func copyNWithContext(ctx context.Context, dst io.Writer, src io.Reader, n int64) error {
	buf := make([]byte, 1<<20)
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := int64(len(buf))
		if n < chunk {
			chunk = n
		}
		written, err := io.CopyN(dst, src, chunk)
		n -= written
		if err != nil {
			return err
		}
	}
	return nil
}
