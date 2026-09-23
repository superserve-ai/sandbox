package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/presence"
)

// Saved snapshots are the customer captures a new sandbox can be created from.
// They live under <SnapshotDir>/saved/<snapshot_id>/, outside the source's own
// directory, so they outlive it. Files are staged beside it and the rename commits.
const (
	SavedSnapshotsDirName     = "saved"
	savedSnapshotManifestName = "manifest.json"
	savedSnapshotVersion      = 1
	defaultSavedCaptures      = 2
	savedCaptureHeadroom      = 256 << 20
	savedUnpauseAttempts      = 3
)

// SavedSnapshotKind is what a saved snapshot holds: the disk alone, or the
// disk with the memory image a warm restore needs.
type SavedSnapshotKind string

const (
	SavedSnapshotFS    SavedSnapshotKind = "fs"
	SavedSnapshotMemFS SavedSnapshotKind = "mem+fs"
)

// SavedSnapshotManifest is the commit record of one saved snapshot. Every
// path it owns lies inside its directory; base paths belong to the template.
type SavedSnapshotManifest struct {
	Version           int               `json:"version"`
	SnapshotID        string            `json:"snapshot_id"`
	SourceVMID        string            `json:"source_vm_id"`
	Kind              SavedSnapshotKind `json:"kind"`
	CreatedAt         time.Time         `json:"created_at"`
	VCPU              uint32            `json:"vcpu"`
	MemoryMiB         uint32            `json:"memory_mib"`
	DiskSizeMiB       uint32            `json:"disk_size_mib"`
	BasePath          string            `json:"base_path,omitempty"`
	DiskPath          string            `json:"disk_path"`
	SnapshotPath      string            `json:"snapshot_path,omitempty"`
	MemPath           string            `json:"mem_path,omitempty"`
	BaseMemPath       string            `json:"base_mem_path,omitempty"`
	KernelPath        string            `json:"kernel_path"`
	FirecrackerSHA256 string            `json:"firecracker_sha256,omitempty"`
	// SizeBytes is the allocated size of the files this snapshot owns.
	SizeBytes int64 `json:"size_bytes"`
}

func (m *Manager) savedSnapshotDir(snapshotID string) (string, error) {
	if m.cfg.SnapshotDir == "" || !filepath.IsAbs(m.cfg.SnapshotDir) {
		return "", status.Error(codes.FailedPrecondition, "snapshot_dir must be configured as an absolute path")
	}
	if id, err := uuid.Parse(snapshotID); err != nil || id.String() != snapshotID {
		return "", status.Error(codes.InvalidArgument, "snapshot_id must be a canonical UUID")
	}
	return filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, snapshotID), nil
}

// CreateSavedSnapshot captures vmID into a saved snapshot. Idempotent on
// snapshotID: a retry waits on the source's lifecycle lock, then returns the
// committed manifest. A running source is paused only while its image is
// written and always released; a paused one is copied where it lies. Nothing
// here flushes the guest's file cache: the caller syncs a running guest first.
func (m *Manager) CreateSavedSnapshot(ctx context.Context, vmID, snapshotID string, kind SavedSnapshotKind) (*SavedSnapshotManifest, error) {
	if kind != SavedSnapshotFS && kind != SavedSnapshotMemFS {
		return nil, status.Errorf(codes.InvalidArgument, "kind must be %q or %q", SavedSnapshotFS, SavedSnapshotMemFS)
	}
	dir, err := m.savedSnapshotDir(snapshotID)
	if err != nil {
		return nil, err
	}
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	log := m.log.With().Str("vm_id", vmID).Str("snapshot_id", snapshotID).Logger()

	if man, err := m.committedSavedSnapshot(dir, vmID); man != nil || err != nil {
		return man, err
	}
	release, err := m.acquireSavedCapture(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// The id lock serializes this capture with a delete or a retry for the
	// same id; it is taken before the VM lock everywhere, so the order holds.
	unlockID, err := m.lockSavedSnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	defer unlockID()
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// The attempt this one waited on may have committed.
	if man, err := m.committedSavedSnapshot(dir, vmID); man != nil || err != nil {
		return man, err
	}

	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	st := inst.Status
	cfg := inst.Config
	inst.mu.RUnlock()
	if st != StatusRunning && st != StatusPaused {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s is %v; a saved snapshot needs a running or paused VM", vmID, st)
	}
	diskPath := m.instanceDiskPath(inst)
	if err := m.savedCaptureHeadroom(kind, st, inst, diskPath); err != nil {
		return nil, err
	}

	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("create saved snapshot root: %w", err)
	}
	// A crash leaves staging behind; the lock held here makes it nobody's.
	removeSavedStaging(parent, snapshotID)
	tmp := filepath.Join(parent, "."+snapshotID+".tmp-"+uuid.NewString())
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return nil, fmt.Errorf("create saved snapshot staging: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	man := &SavedSnapshotManifest{
		Version:           savedSnapshotVersion,
		SnapshotID:        snapshotID,
		SourceVMID:        vmID,
		Kind:              kind,
		CreatedAt:         time.Now().UTC(),
		VCPU:              cfg.VCPU,
		MemoryMiB:         cfg.MemoryMiB,
		DiskSizeMiB:       cfg.DiskSizeMiB,
		BasePath:          cfg.BasePath,
		KernelPath:        m.cfg.KernelPath,
		FirecrackerSHA256: m.firecrackerSHA(),
	}
	if st == StatusRunning {
		err = m.captureRunningSaved(ctx, inst, tmp, dir, diskPath, kind, man, log)
	} else {
		err = m.capturePausedSaved(ctx, inst, tmp, dir, diskPath, kind, man)
	}
	if err != nil {
		return nil, err
	}
	man.SizeBytes = allocatedTreeBytes(tmp)
	if err := writeSavedSnapshotManifest(tmp, man); err != nil {
		return nil, err
	}
	if err := fsyncTree(tmp); err != nil {
		return nil, fmt.Errorf("fsync saved snapshot: %w", err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return nil, fmt.Errorf("commit saved snapshot: %w", err)
	}
	committed = true
	if err := fsyncDir(parent); err != nil {
		return nil, fmt.Errorf("fsync saved snapshot root: %w", err)
	}
	log.Info().Str("kind", string(kind)).Int64("size_bytes", man.SizeBytes).Msg("saved snapshot committed")
	return man, nil
}

// DeleteSavedSnapshot removes a saved snapshot and any staging left for it.
// Idempotent. Forks hold private copies, so nothing depends on the files.
func (m *Manager) DeleteSavedSnapshot(ctx context.Context, snapshotID string) error {
	dir, err := m.savedSnapshotDir(snapshotID)
	if err != nil {
		return err
	}
	unlock, err := m.lockSavedSnapshot(ctx, snapshotID)
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove saved snapshot: %w", err)
	}
	removeSavedStaging(filepath.Dir(dir), snapshotID)
	if err := fsyncDir(filepath.Dir(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("fsync saved snapshot root: %w", err)
	}
	return nil
}

// captureRunningSaved images a running source the way a pause does, then
// releases it. Past the freeze, the source is always released or, when it
// cannot be, recorded as unservable.
func (m *Manager) captureRunningSaved(ctx context.Context, inst *VMInstance, tmp, final, diskPath string, kind SavedSnapshotKind, man *SavedSnapshotManifest, log zerolog.Logger) error {
	vmID := inst.ID
	inst.mu.RLock()
	socket, ip := inst.SocketPath, inst.IP
	memFile, baseMem := inst.MemFilePath, inst.BaseMemPath
	dirtyTracked, sessionID := inst.DirtyTracked, inst.DirtyTrackingSessionID
	recordedCorrects, recordedArtifact := inst.CorrectsWallClock, inst.ArtifactID
	inst.mu.RUnlock()

	if err := m.resolveOutstandingFreeze(ctx, vmID, socket, ip, recordedArtifact, log); err != nil {
		return err
	}
	corrects := recordedCorrects != nil && *recordedCorrects
	if recordedCorrects == nil {
		corrects = guestCorrectsWallClock(memFile, baseMem)
	}
	willFreeze := kind == SavedSnapshotMemFS && corrects && m.cfg.GuestClockFreezeEnabled &&
		m.clockRealtimeCapable.Load() && !m.guestClockUnready.Load()
	token, artifact := "", ""
	sourceDir := filepath.Join(m.cfg.SnapshotDir, vmID)
	intentWritten := false
	if willFreeze {
		token, artifact = NewFreezeToken(), NewArtifactID()
		if err := m.ensureWakeFloorTimed("saved-snapshot"); err != nil {
			return fmt.Errorf("record the rollback floor before freezing: %w", err)
		}
		if err := os.MkdirAll(sourceDir, 0o755); err != nil {
			return fmt.Errorf("create source snapshot dir: %w", err)
		}
		// Durable before the freeze: a crash must find the token, or the
		// guest stays frozen with nobody able to release it.
		if err := writePauseIntent(sourceDir, pauseIntent{VMID: vmID, FreezeToken: token, ArtifactID: artifact}); err != nil {
			return fmt.Errorf("record capture intent: %w", err)
		}
		intentWritten = true
	}
	frozen := false
	if willFreeze {
		var ferr error
		frozen, ferr = m.freezeGuestForPause(ctx, ip, token, log)
		if ferr != nil {
			m.markUnservable(inst, log)
			return ferr
		}
	}

	tFrozen := time.Now()
	var captureErr error
	if kind == SavedSnapshotMemFS {
		captureErr = m.captureRunningMemory(ctx, tmp, final, socket, memFile, baseMem, dirtyTracked, sessionID, man, log)
	} else {
		captureErr = fcPauseVMContext(ctx, socket)
	}
	if captureErr == nil {
		captureErr = m.captureSavedDisk(ctx, diskPath, man.BasePath, tmp, final, man)
	}
	// A memory capture spends the dirty baseline (diff) or resets it (full),
	// and after a failure it is unknown: the source's next pause is a full one.
	if kind == SavedSnapshotMemFS {
		m.abandonDirtyBaseline(inst)
	}
	if captureErr == nil && kind == SavedSnapshotMemFS && corrects {
		if artifact == "" {
			artifact = NewArtifactID()
		}
		wm := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: artifact, WorkloadFrozen: frozen, GuestCorrectsClock: true}
		if frozen {
			wm.FreezeToken = token
		}
		captureErr = WriteWallClockManifest(filepath.Join(tmp, filepath.Base(man.MemPath)), wm)
	}
	frozenFor := time.Since(tFrozen)

	var releaseErr error
	if frozen {
		releaseErr = m.releaseFrozenGuest(ctx, socket, ip, token)
	} else {
		releaseErr = unpauseSourceWithProbe(ctx, socket)
	}
	if releaseErr != nil {
		// The intent, if any, keeps the token for recovery.
		m.markUnservable(inst, log)
		return status.Errorf(codes.Unavailable, "source could not be resumed after capture: %v", errors.Join(captureErr, releaseErr))
	}
	if intentWritten {
		if err := clearPauseIntent(sourceDir); err != nil {
			return fmt.Errorf("clear capture intent: %w", err)
		}
	}
	if captureErr != nil {
		return captureErr
	}
	m.recordPhases("saved_snapshot", string(kind), map[string]time.Duration{"frozen": frozenFor})
	log.Info().Dur("frozen", frozenFor).Bool("workload_frozen", frozen).Msg("saved snapshot: source captured and released")
	return nil
}

// captureRunningMemory writes the source's memory image into tmp. With the
// dirty baseline armed it takes a guarded diff and folds it into a branch of
// the image the source resumed from, so the result is complete against its
// base; a rejected guard or an unarmed source gets a full image.
func (m *Manager) captureRunningMemory(ctx context.Context, tmp, final, socket, memFile, baseMem string, dirtyTracked bool, sessionID string, man *SavedSnapshotManifest, log zerolog.Logger) error {
	vmstate := filepath.Join(tmp, "vmstate.snap")
	man.SnapshotPath = filepath.Join(final, "vmstate.snap")
	if m.cfg.IncrementalSnapshotEnabled && dirtyTracked && memFile != "" && fileExists(memFile) {
		raw := filepath.Join(tmp, "mem.capture.diff")
		err := CreateDiffSnapshot(socket, vmstate, raw, sessionID)
		switch {
		case err == nil:
			return accumulateSavedMemory(ctx, tmp, final, memFile, baseMem, raw, man)
		case errors.Is(err, ErrDirtyTrackingMismatch) || m.sessionRejectedAtPause(err):
			// Rejected before the bitmap was touched; the vCPUs are already
			// paused and the full path's pause is idempotent.
			log.Warn().Err(err).Msg("saved snapshot: guarded diff rejected; taking a full image")
		default:
			return fmt.Errorf("create diff snapshot: %w", err)
		}
	}
	if err := CreateSnapshot(socket, vmstate, filepath.Join(tmp, "mem.snap"), "", SnapshotNormal); err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}
	man.MemPath = filepath.Join(final, "mem.snap")
	return nil
}

// accumulateSavedMemory folds a diff of pages dirtied since the source
// resumed into a branch of the image it resumed from. Against a template
// base the result is a layered overlay whose presence map is the union of
// the branch's and the diff's; against a standalone image it is a full image.
func accumulateSavedMemory(ctx context.Context, tmp, final, memFile, baseMem, raw string, man *SavedSnapshotManifest) error {
	delta, err := presence.Read(raw)
	if err != nil {
		return status.Errorf(codes.DataLoss, "memory diff has no presence map: %v", err)
	}
	// A source resumed straight from a template image has memFile == baseMem
	// and no overlay yet; one resumed from its own overlay accumulates on it;
	// anything else is a standalone image and its own base.
	firstPass := baseMem != "" && memFile == baseMem
	if !firstPass {
		if isOverlayMemFile(memFile) {
			if baseMem == "" {
				if recorded, ok := readLayeredBase(memFile); ok {
					baseMem = recorded
				}
			}
			if baseMem == "" {
				return status.Error(codes.FailedPrecondition, "source memory overlay has no base")
			}
		} else {
			baseMem = ""
		}
	}
	name := "mem.snap"
	if baseMem != "" {
		name = "mem.diff"
	}
	target := filepath.Join(tmp, name)
	var prior *presence.Bitmap
	switch {
	case baseMem == "":
		if err := cloneOrCopyFile(ctx, memFile, target); err != nil {
			return fmt.Errorf("branch source memory image: %w", err)
		}
	case firstPass:
		info, err := os.Stat(baseMem)
		if err != nil {
			return fmt.Errorf("stat memory base: %w", err)
		}
		if err := createSparseFile(target, info.Size()); err != nil {
			return fmt.Errorf("create memory overlay: %w", err)
		}
	default:
		if err := cloneOrCopyFile(ctx, memFile, target); err != nil {
			return fmt.Errorf("branch source memory overlay: %w", err)
		}
		p, err := presence.Read(memFile)
		if err != nil {
			return status.Errorf(codes.DataLoss, "source memory overlay has no presence map: %v", err)
		}
		prior = &p
	}
	if err := applyPresentPages(ctx, raw, delta, target); err != nil {
		return fmt.Errorf("apply memory diff: %w", err)
	}
	if baseMem != "" {
		bits := append([]uint64(nil), delta.Bits...)
		if prior != nil {
			if prior.PageSize != delta.PageSize || prior.NPages != delta.NPages || len(prior.Bits) != len(bits) {
				return status.Error(codes.DataLoss, "memory presence maps have different shapes")
			}
			for i := range bits {
				bits[i] |= prior.Bits[i]
			}
		}
		if err := presence.Write(target, delta.PageSize, delta.NPages, bits); err != nil {
			return fmt.Errorf("write memory presence map: %w", err)
		}
		if err := os.WriteFile(layeredBaseSidecarPath(target), []byte(baseMem), 0o644); err != nil {
			return fmt.Errorf("write memory base record: %w", err)
		}
	}
	_ = os.Remove(raw)
	_ = os.Remove(presence.SidecarPath(raw))
	man.MemPath = filepath.Join(final, name)
	man.BaseMemPath = baseMem
	return nil
}

// capturePausedSaved copies a paused source's resume image and disk once its
// Firecracker is proven gone.
func (m *Manager) capturePausedSaved(ctx context.Context, inst *VMInstance, tmp, final, diskPath string, kind SavedSnapshotKind, man *SavedSnapshotManifest) error {
	inst.mu.RLock()
	snapshotPath, memFile, baseMem := inst.SnapshotPath, inst.MemFilePath, inst.BaseMemPath
	inst.mu.RUnlock()
	// The same at-rest proof backups gate on: Paused alone does not say the
	// process is gone, and a deactivating one may still flush guest writes.
	if !m.vmConfirmedAtRest(ctx, inst.ID) {
		return status.Error(codes.Unavailable, "paused source is not confirmed at rest; retry once its stop completes")
	}
	if kind == SavedSnapshotMemFS {
		if snapshotPath == "" || memFile == "" {
			return status.Error(codes.FailedPrecondition, "paused source has no resume image")
		}
		if err := cloneOrCopyFile(ctx, snapshotPath, filepath.Join(tmp, "vmstate.snap")); err != nil {
			return fmt.Errorf("copy vmstate: %w", err)
		}
		if sidecar := snapshotPath + ".overlay"; fileExists(sidecar) {
			if err := cloneOrCopyFile(ctx, sidecar, filepath.Join(tmp, "vmstate.snap.overlay")); err != nil {
				return fmt.Errorf("copy block overlay sidecar: %w", err)
			}
		}
		name := "mem.snap"
		if isOverlayMemFile(memFile) {
			name = "mem.diff"
			if baseMem == "" {
				if recorded, ok := readLayeredBase(memFile); ok {
					baseMem = recorded
				}
			}
			if baseMem == "" {
				return status.Error(codes.FailedPrecondition, "paused source memory overlay has no base")
			}
		} else {
			baseMem = ""
		}
		target := filepath.Join(tmp, name)
		if err := cloneOrCopyFile(ctx, memFile, target); err != nil {
			return fmt.Errorf("copy memory image: %w", err)
		}
		if p := presence.SidecarPath(memFile); fileExists(p) {
			if err := cloneOrCopyFile(ctx, p, presence.SidecarPath(target)); err != nil {
				return fmt.Errorf("copy memory presence map: %w", err)
			}
		} else if baseMem != "" {
			return status.Error(codes.DataLoss, "paused source memory overlay has no presence map")
		}
		if baseMem != "" {
			if err := os.WriteFile(layeredBaseSidecarPath(target), []byte(baseMem), 0o644); err != nil {
				return fmt.Errorf("write memory base record: %w", err)
			}
		}
		// The image's wake contract travels with it: a fork restored from a
		// frozen image must wake under the same token.
		if wm := WallClockMarkerPath(memFile); fileExists(wm) {
			if err := cloneOrCopyFile(ctx, wm, WallClockMarkerPath(target)); err != nil {
				return fmt.Errorf("copy wall-clock manifest: %w", err)
			}
		}
		man.SnapshotPath = filepath.Join(final, "vmstate.snap")
		man.MemPath = filepath.Join(final, name)
		man.BaseMemPath = baseMem
	}
	return m.captureSavedDisk(ctx, diskPath, man.BasePath, tmp, final, man)
}

// captureSavedDisk clones the source's disk. An overlay's holes mean "read
// the base", and a filesystem may turn written zeros into holes, so an overlay
// is reflinked extent-exact or the capture is refused; a standalone rootfs
// may be copied.
func (m *Manager) captureSavedDisk(ctx context.Context, diskPath, basePath, tmp, final string, man *SavedSnapshotManifest) error {
	name := "rootfs.ext4"
	copy := cloneOrCopyFile
	if basePath != "" {
		name = "overlay.ext4"
		copy = reflinkFileExact
		if m.reflinkOverlay != nil {
			copy = m.reflinkOverlay
		}
	}
	if err := copy(ctx, diskPath, filepath.Join(tmp, name)); err != nil {
		if basePath != "" && errors.Is(err, errNoReflink) {
			return status.Errorf(codes.FailedPrecondition, "overlay copies need a reflink filesystem under %s: %v", m.cfg.SnapshotDir, err)
		}
		return fmt.Errorf("copy disk: %w", err)
	}
	man.DiskPath = filepath.Join(final, name)
	man.BasePath = basePath
	return nil
}

var errNoReflink = errors.New("filesystem cannot reflink")

// reflinkFileExact clones src into dst with no fallback.
func reflinkFileExact(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := cloneFileFD(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("%w: %v", errNoReflink, err)
	}
	return out.Close()
}

// instanceDiskPath resolves the VM's writable disk the way resume does.
func (m *Manager) instanceDiskPath(inst *VMInstance) string {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.DiskPath != "" {
		return inst.DiskPath
	}
	key := inst.RunDirID
	if key == "" {
		key = inst.ID
	}
	name := "rootfs.ext4"
	if inst.Config.BasePath != "" {
		name = "overlay.ext4"
	}
	return filepath.Join(m.cfg.RunDir, key, name)
}

func (m *Manager) committedSavedSnapshot(dir, vmID string) (*SavedSnapshotManifest, error) {
	man, err := readSavedSnapshotManifest(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.DataLoss, "saved snapshot %s: %v", filepath.Base(dir), err)
	}
	if man.SourceVMID != vmID {
		return nil, status.Errorf(codes.AlreadyExists, "saved snapshot %s belongs to vm %s", man.SnapshotID, man.SourceVMID)
	}
	return man, nil
}

func readSavedSnapshotManifest(dir string) (*SavedSnapshotManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, savedSnapshotManifestName))
	if err != nil {
		return nil, err
	}
	var man SavedSnapshotManifest
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if man.Version != savedSnapshotVersion || man.SnapshotID == "" {
		return nil, fmt.Errorf("manifest version %d is not %d", man.Version, savedSnapshotVersion)
	}
	return &man, nil
}

func writeSavedSnapshotManifest(dir string, man *SavedSnapshotManifest) error {
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, savedSnapshotManifestName)
	f, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func removeSavedStaging(parent, snapshotID string) {
	stale, _ := filepath.Glob(filepath.Join(parent, "."+snapshotID+".tmp-*"))
	for _, d := range stale {
		_ = os.RemoveAll(d)
	}
}

// savedIDLock is one snapshot id's lock; the entry lives while a holder or a
// waiter references it, so the map does not grow with every id ever seen.
type savedIDLock struct {
	ch   chan struct{}
	refs int
}

// lockSavedSnapshot serializes create and delete for one snapshot id.
func (m *Manager) lockSavedSnapshot(ctx context.Context, snapshotID string) (func(), error) {
	m.savedIDMu.Lock()
	if m.savedIDLocks == nil {
		m.savedIDLocks = map[string]*savedIDLock{}
	}
	l := m.savedIDLocks[snapshotID]
	if l == nil {
		l = &savedIDLock{ch: make(chan struct{}, 1)}
		m.savedIDLocks[snapshotID] = l
	}
	l.refs++
	m.savedIDMu.Unlock()
	release := func() {
		m.savedIDMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(m.savedIDLocks, snapshotID)
		}
		m.savedIDMu.Unlock()
	}
	select {
	case l.ch <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.ch
			release()
			return nil, err
		}
		return func() { <-l.ch; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// acquireSavedCapture bounds concurrent captures per host: each one holds a
// source frozen and copies a disk, and a burst must not stall the host.
func (m *Manager) acquireSavedCapture(ctx context.Context) (func(), error) {
	m.savedCapturesOnce.Do(func() {
		n := m.cfg.SavedSnapshotConcurrency
		if n <= 0 {
			n = defaultSavedCaptures
		}
		m.savedCaptures = make(chan struct{}, n)
	})
	select {
	case m.savedCaptures <- struct{}{}:
		return func() { <-m.savedCaptures }, nil
	case <-ctx.Done():
		return nil, status.Errorf(codes.Unavailable, "waiting for a capture slot: %v", ctx.Err())
	}
}

// savedCaptureHeadroom refuses a capture the snapshot filesystem cannot hold:
// a running full memory image is written in full, and a copy may not reflink
// on this filesystem.
func (m *Manager) savedCaptureHeadroom(kind SavedSnapshotKind, st VMStatus, inst *VMInstance, diskPath string) error {
	diskBytes, _ := allocatedBytes(diskPath)
	need := int64(savedCaptureHeadroom) + diskBytes
	if kind == SavedSnapshotMemFS {
		inst.mu.RLock()
		memoryMiB, memFile, snapshotPath := inst.Config.MemoryMiB, inst.MemFilePath, inst.SnapshotPath
		inst.mu.RUnlock()
		if st == StatusRunning {
			need += int64(memoryMiB) << 20
		} else {
			memBytes, _ := allocatedBytes(memFile)
			stateBytes, _ := allocatedBytes(snapshotPath)
			need += memBytes + stateBytes
		}
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(m.cfg.SnapshotDir, &fs); err != nil {
		return fmt.Errorf("statfs snapshot dir: %w", err)
	}
	free := int64(fs.Bavail) * int64(fs.Bsize)
	if free < need {
		return status.Errorf(codes.ResourceExhausted, "snapshot filesystem has %d bytes free; capture needs %d", free, need)
	}
	return nil
}

func (m *Manager) firecrackerSHA() string {
	m.fcSHAOnce.Do(func() {
		f, err := os.Open(m.cfg.FirecrackerBin)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		m.fcSHA = hex.EncodeToString(h.Sum(nil))
	})
	return m.fcSHA
}

// fcPauseVMContext pauses the vCPUs over a bare request, like UnpauseVMContext.
func fcPauseVMContext(ctx context.Context, socketPath string) error {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, "http://localhost/vm", strings.NewReader(`{"state":"Paused"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return fmt.Errorf("pause VM: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pause VM: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// unpauseSourceWithProbe resumes the vCPUs, reading the VM state when the
// response is lost: PATCH /vm is not a receipt.
func unpauseSourceWithProbe(ctx context.Context, socketPath string) error {
	base := context.WithoutCancel(ctx)
	var errs []error
	for attempt := 0; attempt < savedUnpauseAttempts; attempt++ {
		uctx, cancel := context.WithTimeout(base, 5*time.Second)
		err := UnpauseVMContext(uctx, socketPath)
		cancel()
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		pctx, pcancel := context.WithTimeout(base, 5*time.Second)
		state, perr := VMState(pctx, socketPath)
		pcancel()
		if perr == nil && state == "Running" {
			return nil
		}
		if perr != nil {
			errs = append(errs, perr)
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return errors.Join(errs...)
}

// cloneOrCopyFile makes dst an independent copy of src: a reflink where the
// filesystem offers one, else a copy that keeps holes.
func cloneOrCopyFile(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := cloneFileFD(out, in); err == nil {
		return out.Close()
	}
	if err := out.Truncate(info.Size()); err != nil {
		out.Close()
		return err
	}
	if err := copyDataExtents(ctx, in, out, info.Size()); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// applyPresentPages writes every page the diff's presence map names into dst
// at the same offset, zero pages included: the map, not the extent layout,
// says which pages the diff provides.
func applyPresentPages(ctx context.Context, src string, present presence.Bitmap, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer out.Close()
	dinfo, err := out.Stat()
	if err != nil {
		return err
	}
	page := int64(present.PageSize)
	if page <= 0 || int64(present.NPages)*page > dinfo.Size() {
		return fmt.Errorf("presence map (%d pages of %d) exceeds image size %d", present.NPages, page, dinfo.Size())
	}
	for i := 0; i < int(present.NPages); {
		if !present.IsSet(i) {
			i++
			continue
		}
		j := i
		for j < int(present.NPages) && present.IsSet(j) {
			j++
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		off, n := int64(i)*page, int64(j-i)*page
		if _, err := out.Seek(off, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(out, io.NewSectionReader(in, off, n), n); err != nil {
			return err
		}
		i = j
	}
	return out.Sync()
}

// copyDataExtents copies in's data extents into out at their offsets, or the
// whole file where the filesystem cannot report holes.
func copyDataExtents(ctx context.Context, in, out *os.File, size int64) error {
	fd := int(in.Fd())
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, syscall.ENXIO) {
			return nil
		}
		if err != nil {
			if off == 0 {
				_, cerr := io.Copy(out, io.NewSectionReader(in, 0, size))
				return cerr
			}
			return err
		}
		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if hole > size {
			hole = size
		}
		if hole <= data {
			return fmt.Errorf("invalid extent [%d,%d)", data, hole)
		}
		if _, err := out.Seek(data, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(out, io.NewSectionReader(in, data, hole-data), hole-data); err != nil {
			return err
		}
		off = hole
	}
	return nil
}

func createSparseFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func allocatedTreeBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			n, _ := allocatedBytes(p)
			total += n
		}
		return nil
	})
	return total
}

func fsyncTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		serr := f.Sync()
		f.Close()
		return serr
	})
}

func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
