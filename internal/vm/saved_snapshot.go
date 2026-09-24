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
	// A capture's budget: a base for the request itself, plus the time a
	// full memory image takes at the slowest write rate the capture waits
	// for before it treats Firecracker as stuck.
	savedCaptureBaseBudget     = 60 * time.Second
	savedCaptureFloorMiBPerSec = 64
)

// savedCaptureBudget bounds the Firecracker snapshot request. A memory
// capture may write all of guest memory, so its budget grows with the memory
// size; an fs capture writes none.
func savedCaptureBudget(kind SavedSnapshotKind, memoryMiB uint32) time.Duration {
	if kind != SavedSnapshotMemFS {
		return savedCaptureBaseBudget
	}
	return savedCaptureBaseBudget + time.Duration(memoryMiB/savedCaptureFloorMiBPerSec)*time.Second
}

// awaitFirecracker waits for a Firecracker whose last request was abandoned
// mid-way to answer its API again, in short bounded probes: an image it was
// asked for keeps being written after the request is gone, and the vCPUs
// stay paused until it is done.
func awaitFirecracker(ctx context.Context, socketPath string, wait time.Duration) error {
	base := context.WithoutCancel(ctx)
	deadline := time.Now().Add(wait)
	for {
		pctx, cancel := context.WithTimeout(base, 5*time.Second)
		_, err := VMState(pctx, socketPath)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("firecracker api not answering %s after the capture budget: %w", wait, err)
		}
		time.Sleep(time.Second)
	}
}

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
	Version      int               `json:"version"`
	SnapshotID   string            `json:"snapshot_id"`
	SourceVMID   string            `json:"source_vm_id"`
	Kind         SavedSnapshotKind `json:"kind"`
	CreatedAt    time.Time         `json:"created_at"`
	VCPU         uint32            `json:"vcpu"`
	MemoryMiB    uint32            `json:"memory_mib"`
	DiskSizeMiB  uint32            `json:"disk_size_mib"`
	BasePath     string            `json:"base_path,omitempty"`
	DiskPath     string            `json:"disk_path"`
	SnapshotPath string            `json:"snapshot_path,omitempty"`
	MemPath      string            `json:"mem_path,omitempty"`
	BaseMemPath  string            `json:"base_mem_path,omitempty"`
	// FirecrackerSHA256 identifies the process that wrote the memory image;
	// empty when unknown, as for a paused source.
	FirecrackerSHA256 string `json:"firecracker_sha256,omitempty"`
	// SizeBytes is the allocated size of the files this snapshot owns.
	SizeBytes int64 `json:"size_bytes"`
}

// savedCaptureAdmissible answers a retry for a committed id and refuses a
// source that cannot be captured, under the source's lock and the id's, in
// that order. It holds neither afterwards.
func (m *Manager) savedCaptureAdmissible(ctx context.Context, vmID, snapshotID string, kind SavedSnapshotKind, dir string) (*SavedSnapshotManifest, error) {
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	unlockID, err := m.lockSavedSnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	defer unlockID()
	if man, err := m.committedSavedSnapshot(dir, vmID, kind); man != nil || err != nil {
		return man, err
	}
	_, _, _, err = m.savedCaptureSource(vmID)
	return nil, err
}

// savedCaptureSource loads the source and requires it running or paused.
func (m *Manager) savedCaptureSource(vmID string) (*VMInstance, VMStatus, VMConfig, error) {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, 0, VMConfig{}, err
	}
	inst.mu.RLock()
	st, cfg := inst.Status, inst.Config
	inst.mu.RUnlock()
	if st != StatusRunning && st != StatusPaused {
		return nil, 0, VMConfig{}, status.Errorf(codes.FailedPrecondition, "vm %s is %v; a saved snapshot needs a running or paused VM", vmID, st)
	}
	return inst, st, cfg, nil
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

	// Admission first, under the source's lock: a request for a busy source
	// waits there holding nothing, and a retry or a bad request is answered
	// without a slot. The slot is then waited for with no lock held, so a
	// resume of this sandbox never queues behind another sandbox's capture.
	// The locks are taken again for the capture itself, and the source
	// checked again, since it may have moved meanwhile.
	if man, err := m.savedCaptureAdmissible(ctx, vmID, snapshotID, kind, dir); man != nil || err != nil {
		return man, err
	}
	release, err := m.acquireSavedCapture(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// The VM lock comes first, as it does for a restore that creates a VM
	// from a snapshot, so the two never wait on each other's locks in
	// opposite orders. The id lock then serializes this call with a delete
	// or a retry for the same id, the committed check included.
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	unlockID, err := m.lockSavedSnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	defer unlockID()
	if man, err := m.committedSavedSnapshot(dir, vmID, kind); man != nil || err != nil {
		return man, err
	}
	inst, st, cfg, err := m.savedCaptureSource(vmID)
	if err != nil {
		return nil, err
	}
	diskPath := m.instanceDiskPath(inst)
	unreserve, err := m.savedCaptureHeadroom(kind, st, inst)
	if err != nil {
		return nil, err
	}
	defer unreserve()

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

	// The block device is the file, and a reattached VM's config no longer
	// says how big it was asked to be.
	diskMiB, err := diskSizeMiB(diskPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "source disk: %v", err)
	}
	man := &SavedSnapshotManifest{
		Version:     savedSnapshotVersion,
		SnapshotID:  snapshotID,
		SourceVMID:  vmID,
		Kind:        kind,
		CreatedAt:   time.Now().UTC(),
		VCPU:        cfg.VCPU,
		MemoryMiB:   cfg.MemoryMiB,
		DiskSizeMiB: diskMiB,
		BasePath:    cfg.BasePath,
	}
	if st == StatusRunning {
		// The image is written by the live process, which may predate the
		// binary on disk; a paused image's producer went unrecorded.
		man.FirecrackerSHA256 = firecrackerExeSHA(inst)
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
	// The disk alone is an fs snapshot, so what the guest has written but
	// not yet flushed has to reach it first. A memory image carries the page
	// cache itself.
	if kind == SavedSnapshotFS && ip != "" {
		if err := syncGuestFilesystems(ctx, ip); err != nil {
			return status.Errorf(codes.FailedPrecondition, "guest did not flush its filesystems before the capture: %v", err)
		}
	}
	corrects := recordedCorrects != nil && *recordedCorrects
	if recordedCorrects == nil {
		corrects = guestCorrectsWallClock(memFile, baseMem)
	}
	willFreeze := kind == SavedSnapshotMemFS && corrects && m.cfg.GuestClockFreezeEnabled &&
		m.clockRealtimeCapable.Load() && !m.guestClockUnready.Load()
	token, artifact := "", NewArtifactID()
	if willFreeze {
		token = NewFreezeToken()
	}
	// Every running capture pauses the vCPUs, so every one is journalled
	// first: a vmd that dies before the release finds the intent on reattach
	// and resumes the guest, with the token when it was frozen. The floor is
	// what makes reattach look for intents at all.
	sourceDir := filepath.Join(m.cfg.SnapshotDir, vmID)
	if err := m.ensureWakeFloorTimed("saved-snapshot"); err != nil {
		return fmt.Errorf("record the rollback floor before pausing: %w", err)
	}
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return fmt.Errorf("create source snapshot dir: %w", err)
	}
	if err := writeStagedIntent(sourceDir, pauseIntent{VMID: vmID, FreezeToken: token, ArtifactID: artifact}); err != nil {
		return fmt.Errorf("record capture intent: %w", err)
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
	// Bounded on its own: the RPC deadline may be long, and a Firecracker that
	// stops answering must not hold the source paused past this.
	budget := savedCaptureBudget(kind, man.MemoryMiB)
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var captureErr error
	if kind == SavedSnapshotMemFS {
		captureErr = m.captureRunningMemory(cctx, tmp, final, socket, memFile, baseMem, dirtyTracked, sessionID, man, log)
	} else {
		captureErr = fcPauseVMContext(cctx, socket)
	}
	if captureErr == nil {
		captureErr = m.captureSavedDisk(cctx, diskPath, man.BasePath, tmp, final, man)
	}
	// A memory capture spends the dirty baseline (diff) or resets it (full),
	// and after a failure it is unknown: the source's next pause is a full one.
	if kind == SavedSnapshotMemFS {
		m.abandonDirtyBaseline(inst)
	}
	if captureErr == nil && kind == SavedSnapshotMemFS && corrects {
		wm := WallClockManifest{Version: WallClockManifestVersion, ArtifactID: artifact, WorkloadFrozen: frozen, GuestCorrectsClock: true}
		if frozen {
			wm.FreezeToken = token
		}
		captureErr = WriteWallClockManifest(filepath.Join(tmp, filepath.Base(man.MemPath)), wm)
	}
	frozenFor := time.Since(tFrozen)

	// Releasing the guest while Firecracker still writes the abandoned image
	// would only time out and write the source off; wait for the API first.
	if captureErr != nil && cctx.Err() != nil {
		log.Warn().Dur("budget", budget).Msg("saved snapshot: capture exceeded its budget; waiting for Firecracker before releasing the source")
		if werr := awaitFirecracker(ctx, socket, budget); werr != nil {
			log.Error().Err(werr).Msg("saved snapshot: Firecracker did not come back")
		}
	}
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
	if err := clearPauseIntent(sourceDir); err != nil {
		return fmt.Errorf("clear capture intent: %w", err)
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
		err := CreateDiffSnapshotContext(ctx, socket, vmstate, raw, sessionID)
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
	if err := CreateSnapshotContext(ctx, socket, vmstate, filepath.Join(tmp, "mem.snap"), "", SnapshotNormal); err != nil {
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
		if err := m.cloneSavedFile(ctx, snapshotPath, filepath.Join(tmp, "vmstate.snap")); err != nil {
			return err
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
		if err := m.cloneSavedFile(ctx, memFile, target); err != nil {
			return err
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

// captureSavedDisk clones the source's disk, reflinked or refused: an
// overlay's holes mean "read the base" and a copy may not keep them, and a
// restore reflinks the saved disk back the same way, so a disk that could
// only be copied here would publish a snapshot this host cannot restore.
func (m *Manager) captureSavedDisk(ctx context.Context, diskPath, basePath, tmp, final string, man *SavedSnapshotManifest) error {
	name := "rootfs.ext4"
	if basePath != "" {
		name = "overlay.ext4"
	}
	clone := reflinkFileExact
	if m.reflinkFile != nil {
		clone = m.reflinkFile
	}
	if err := clone(ctx, diskPath, filepath.Join(tmp, name)); err != nil {
		if errors.Is(err, errNoReflink) {
			return status.Errorf(codes.FailedPrecondition, "saved disks need a reflink filesystem under %s: %v", m.cfg.SnapshotDir, err)
		}
		return fmt.Errorf("clone disk: %w", err)
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

func (m *Manager) committedSavedSnapshot(dir, vmID string, kind SavedSnapshotKind) (*SavedSnapshotManifest, error) {
	man, err := readSavedSnapshotManifest(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.DataLoss, "saved snapshot %s: %v", filepath.Base(dir), err)
	}
	if man.SourceVMID != vmID || man.Kind != kind {
		return nil, status.Errorf(codes.AlreadyExists, "saved snapshot %s is a %s snapshot of vm %s", man.SnapshotID, man.Kind, man.SourceVMID)
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

// SweepSavedSnapshotStaging reclaims staging directories a previous process
// died in. The saved directory grows with the snapshots on the host, so the
// listing runs in the background along with the removals. Each candidate is
// removed under its snapshot id lock, which a live capture holds for its whole
// duration, so an in-flight staging dir is never touched. The returned channel
// closes when the sweep is done.
func (m *Manager) SweepSavedSnapshotStaging(log zerolog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if m.cfg.SnapshotDir == "" {
			return
		}
		start := time.Now()
		stale, _ := filepath.Glob(filepath.Join(m.cfg.SnapshotDir, SavedSnapshotsDirName, ".*.tmp-*"))
		n := 0
		for _, d := range stale {
			id, _, _ := strings.Cut(strings.TrimPrefix(filepath.Base(d), "."), ".tmp-")
			unlock, err := m.lockSavedSnapshot(context.Background(), id)
			if err != nil {
				return
			}
			err = os.RemoveAll(d)
			unlock()
			if err != nil {
				log.Warn().Err(err).Str("dir", d).Msg("saved snapshot staging could not be removed")
				continue
			}
			n++
		}
		if n > 0 {
			log.Info().Int("removed", n).Dur("took", time.Since(start)).Msg("swept abandoned saved snapshot staging")
		}
	}()
	return done
}

// forkSource resolves the snapshot a VM is created from and fixes the paths
// the VM will own, before any lock: a retried request then names the same
// files as the attempt it repeats.
func (m *Manager) forkSource(childID string, cfg *VMConfig, snapshotPath, memPath string) (*SavedSnapshotManifest, string, string, error) {
	if snapshotPath != "" || memPath != "" {
		return nil, "", "", status.Error(codes.InvalidArgument, "a saved snapshot names its own files; snapshot_path and mem_file_path must be empty")
	}
	dir, err := m.savedSnapshotDir(cfg.SavedSnapshotID)
	if err != nil {
		return nil, "", "", err
	}
	man, err := readSavedSnapshotManifest(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", "", status.Errorf(codes.NotFound, "saved snapshot %s does not exist", cfg.SavedSnapshotID)
	}
	if err != nil {
		return nil, "", "", status.Errorf(codes.DataLoss, "saved snapshot %s: %v", cfg.SavedSnapshotID, err)
	}
	if man.SnapshotPath == "" {
		return nil, "", "", status.Errorf(codes.FailedPrecondition, "saved snapshot %s holds no memory image; a VM is created from it by cold boot", cfg.SavedSnapshotID)
	}
	if cfg.BasePath != "" && cfg.BasePath != man.BasePath {
		return nil, "", "", status.Errorf(codes.InvalidArgument, "base_path %q is not saved snapshot %s's base %q", cfg.BasePath, cfg.SavedSnapshotID, man.BasePath)
	}
	// The image fixes the machine's shape, and the host's capacity accounting
	// charges what the config says, so the two must agree.
	if cfg.VCPU != 0 && cfg.VCPU != man.VCPU {
		return nil, "", "", status.Errorf(codes.InvalidArgument, "vcpu %d is not saved snapshot %s's %d", cfg.VCPU, cfg.SavedSnapshotID, man.VCPU)
	}
	if cfg.MemoryMiB != 0 && cfg.MemoryMiB != man.MemoryMiB {
		return nil, "", "", status.Errorf(codes.InvalidArgument, "memory %d MiB is not saved snapshot %s's %d", cfg.MemoryMiB, cfg.SavedSnapshotID, man.MemoryMiB)
	}
	cfg.BasePath = man.BasePath
	cfg.VCPU, cfg.MemoryMiB, cfg.DiskSizeMiB = man.VCPU, man.MemoryMiB, man.DiskSizeMiB
	own := filepath.Join(m.cfg.SnapshotDir, childID)
	return man, filepath.Join(own, "vmstate.snap"), filepath.Join(own, filepath.Base(man.MemPath)), nil
}

// retriedForkTarget is retriedLaunchTarget for a create from a snapshot: the
// request names no files, so the child is matched by the snapshot it came
// from and by owning its artifacts, never by files that may since be gone.
func (m *Manager) retriedForkTarget(vmID, snapshotID string) (*VMInstance, bool) {
	m.mu.RLock()
	existing := m.vms[vmID]
	m.mu.RUnlock()
	if existing == nil {
		return nil, false
	}
	existing.mu.RLock()
	source, snap, mem := existing.SourceSnapshotID, existing.SnapshotPath, existing.MemFilePath
	existing.mu.RUnlock()
	own := filepath.Join(m.cfg.SnapshotDir, vmID)
	if source != snapshotID || snap != filepath.Join(own, "vmstate.snap") || filepath.Dir(mem) != own {
		return nil, false
	}
	return m.retriedLaunchTarget(vmID, snap, mem)
}

// savedSnapshotCommitted reports whether the snapshot man describes is still
// on disk. man was read before the caller took the snapshot's lock, and the
// id could have been deleted and captured again meanwhile, so the manifest
// is read again under the lock and must be the same snapshot; the answer
// then holds until the lock is released.
func savedSnapshotCommitted(man *SavedSnapshotManifest) error {
	now, err := readSavedSnapshotManifest(filepath.Dir(man.DiskPath))
	if errors.Is(err, os.ErrNotExist) {
		return status.Errorf(codes.NotFound, "saved snapshot %s was deleted", man.SnapshotID)
	}
	if err != nil {
		return fmt.Errorf("read saved snapshot: %w", err)
	}
	if !now.sameSnapshot(man) {
		return status.Errorf(codes.NotFound, "saved snapshot %s was replaced since it was read", man.SnapshotID)
	}
	return nil
}

// sameSnapshot reports whether two manifests describe one capture: the
// same source, kind, files and moment.
func (a *SavedSnapshotManifest) sameSnapshot(b *SavedSnapshotManifest) bool {
	return a.SnapshotID == b.SnapshotID && a.SourceVMID == b.SourceVMID && a.Kind == b.Kind &&
		a.BasePath == b.BasePath && a.DiskPath == b.DiskPath && a.SnapshotPath == b.SnapshotPath &&
		a.MemPath == b.MemPath && a.BaseMemPath == b.BaseMemPath &&
		a.VCPU == b.VCPU && a.MemoryMiB == b.MemoryMiB && a.DiskSizeMiB == b.DiskSizeMiB &&
		a.CreatedAt.Equal(b.CreatedAt)
}

// materializeFork gives the VM its own copy of every file the snapshot owns,
// under the snapshot id lock: a delete either finishes first and is answered
// not-found, or waits until the VM holds everything it needs. Returns the
// VM's disk.
func (m *Manager) materializeFork(ctx context.Context, childID string, man *SavedSnapshotManifest) (string, error) {
	unlock, err := m.lockSavedSnapshot(ctx, man.SnapshotID)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := savedSnapshotCommitted(man); err != nil {
		return "", err
	}
	return m.materializeForkLocked(ctx, childID, man)
}

// materializeForkLocked is materializeFork for a caller that holds the
// snapshot's lock and has checked it is committed.
func (m *Manager) materializeForkLocked(ctx context.Context, childID string, man *SavedSnapshotManifest) (string, error) {
	own := filepath.Join(m.cfg.SnapshotDir, childID)
	if err := os.MkdirAll(own, 0o755); err != nil {
		return "", fmt.Errorf("create vm snapshot dir: %w", err)
	}
	vmstate := filepath.Join(own, "vmstate.snap")
	memDst := filepath.Join(own, filepath.Base(man.MemPath))
	files := [][2]string{{man.SnapshotPath, vmstate}, {man.MemPath, memDst}}
	for _, side := range [][2]string{
		{man.SnapshotPath + ".overlay", vmstate + ".overlay"},
		{presence.SidecarPath(man.MemPath), presence.SidecarPath(memDst)},
		{layeredBaseSidecarPath(man.MemPath), layeredBaseSidecarPath(memDst)},
		{WallClockMarkerPath(man.MemPath), WallClockMarkerPath(memDst)},
	} {
		if _, err := os.Stat(side[0]); err == nil {
			files = append(files, side)
		}
	}
	clone := m.fileClone()
	for _, f := range files {
		if err := clone(ctx, f[0], f[1]); err != nil {
			if errors.Is(err, errNoReflink) {
				return "", status.Errorf(codes.FailedPrecondition, "saved snapshot %s needs a reflink filesystem shared with %s: %v", man.SnapshotID, m.cfg.SnapshotDir, err)
			}
			return "", fmt.Errorf("clone %s: %w", filepath.Base(f[0]), err)
		}
	}
	return m.cloneSavedDisk(ctx, childID, man.DiskPath, man.BasePath)
}

// stopLeftoverLife stops whatever may still run for an id that has a run
// dir but no record, under either supervision; each stop is a no-op when
// nothing is there.
func (m *Manager) stopLeftoverLife(ctx context.Context, vmID string) error {
	if err := m.stopVM(ctx, vmID, SupervisionUnit); err != nil {
		return err
	}
	if m.cgroups != nil {
		return m.stopVM(ctx, vmID, SupervisionCgroup)
	}
	return nil
}

// cleanupForkCopies removes the snapshot-dir copies a failed fork made.
func (m *Manager) cleanupForkCopies(childID string) {
	if !isLeafName(childID) || isReservedRunDirName(childID) {
		return
	}
	_ = os.RemoveAll(filepath.Join(m.cfg.SnapshotDir, childID))
}

// fileClone is the exact clone for every file a VM takes from a saved
// snapshot; tests stand in for it on filesystems that cannot reflink.
func (m *Manager) fileClone() func(context.Context, string, string) error {
	if m.reflinkFile != nil {
		return m.reflinkFile
	}
	return reflinkFileExact
}

// syncGuestFilesystems runs sync inside the guest through boxd, bounded.
// Only a whole reply that says sync exited 0 counts: a reply cut short, or
// one with no exit code, is not a flush.
func syncGuestFilesystems(ctx context.Context, vmIP string) error {
	body, _ := json.Marshal(struct {
		Command  string `json:"command"`
		TimeoutS int    `json:"timeout_s"`
	}{Command: "sync", TimeoutS: 20})
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	reply, err := postBoxd(sctx, vmIP, "/exec", body)
	if err != nil {
		return err
	}
	var res struct {
		ExitCode *int32 `json:"exit_code"`
		Stderr   string `json:"stderr"`
	}
	if err := json.Unmarshal(reply, &res); err != nil {
		return fmt.Errorf("sync: reply: %w", err)
	}
	if res.ExitCode == nil {
		return errors.New("sync: reply carries no exit code")
	}
	if *res.ExitCode != 0 {
		return fmt.Errorf("sync exited %d: %s", *res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func diskSizeMiB(path string) (uint32, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return uint32((fi.Size() + (1 << 20) - 1) >> 20), nil
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

// savedFreeBytes reports the snapshot filesystem's free space.
var savedFreeBytes = func(dir string) (int64, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return 0, err
	}
	return int64(fs.Bavail) * int64(fs.Bsize), nil
}

// cloneSavedFile reflinks a paused source's image into the staging
// directory or refuses: the image is taken as it is, never copied, so the
// space check reserves nothing for it.
func (m *Manager) cloneSavedFile(ctx context.Context, src, dst string) error {
	if err := m.fileClone()(ctx, src, dst); err != nil {
		if errors.Is(err, errNoReflink) {
			return status.Errorf(codes.FailedPrecondition, "saved images need a reflink filesystem under %s: %v", m.cfg.SnapshotDir, err)
		}
		return fmt.Errorf("clone %s: %w", filepath.Base(src), err)
	}
	return nil
}

// savedCaptureHeadroom refuses a capture the snapshot filesystem cannot hold.
// Disk and paused images are reflinked, never copied, so the fixed headroom
// covers them; only a running memory capture writes bytes. The need stays
// reserved until the returned release runs, so concurrent captures cannot
// each be admitted against the same free space.
func (m *Manager) savedCaptureHeadroom(kind SavedSnapshotKind, st VMStatus, inst *VMInstance) (func(), error) {
	need := int64(savedCaptureHeadroom)
	if kind == SavedSnapshotMemFS && st == StatusRunning {
		inst.mu.RLock()
		memoryMiB := inst.Config.MemoryMiB
		inst.mu.RUnlock()
		// A diff is written raw and then applied onto the image it joins,
		// so two guest-sized files can exist until the raw one is removed.
		need += 2 * int64(memoryMiB) << 20
	}
	free, err := savedFreeBytes(m.cfg.SnapshotDir)
	if err != nil {
		return nil, fmt.Errorf("statfs snapshot dir: %w", err)
	}
	release := func() { m.savedReserved.Add(-need) }
	if reserved := m.savedReserved.Add(need); free < reserved {
		release()
		return nil, status.Errorf(codes.ResourceExhausted, "snapshot filesystem has %d bytes free and captures in flight hold %d; this one needs %d", free, reserved-need, need)
	}
	return release, nil
}

// firecrackerExeSHA hashes the running VM's Firecracker through its exe
// link, which names the binary the process runs even after the file on disk
// was replaced. Empty when it cannot be read.
func firecrackerExeSHA(inst *VMInstance) string {
	inst.mu.RLock()
	pid := inst.PID
	inst.mu.RUnlock()
	if pid <= 0 {
		return ""
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
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
		if err := copyRange(ctx, out, in, int64(i)*page, int64(j-i)*page); err != nil {
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
				return copyRange(ctx, out, in, 0, size)
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
		if err := copyRange(ctx, out, in, data, hole-data); err != nil {
			return err
		}
		off = hole
	}
	return nil
}

// copyRange copies n bytes at off from in to out in bounded pieces, honoring
// ctx between them: a large extent must not outlive the caller's budget.
func copyRange(ctx context.Context, out, in *os.File, off, n int64) error {
	const piece = 32 << 20
	for done := int64(0); done < n; {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := min(int64(piece), n-done)
		if _, err := out.Seek(off+done, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(out, io.NewSectionReader(in, off+done, chunk), chunk); err != nil {
			return err
		}
		done += chunk
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
