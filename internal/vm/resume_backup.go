package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// pausedDiskPath is the disk a paused record boots from: recorded, or
// inferred from the run directory exactly as resume infers it.
func pausedDiskPath(runDir, vmID, diskPath, runDirID, basePath string) string {
	if diskPath != "" {
		return diskPath
	}
	key := vmID
	if runDirID != "" {
		key = runDirID
	}
	name := "rootfs.ext4"
	if basePath != "" {
		name = "overlay.ext4"
	}
	return filepath.Join(runDir, key, name)
}

// pauseArtifactsPresent reports whether every file a resume needs still
// exists; the memory base and the disk base only count when recorded.
func pauseArtifactsPresent(snap, mem, baseMem, disk, base string) bool {
	return statRegularFile(snap) && mem != "" && statRegularFile(mem) &&
		(baseMem == "" || statRegularFile(baseMem)) &&
		statRegularFile(disk) && (base == "" || statRegularFile(base))
}

// pauseArtifactsMissing is true for a paused record whose resume would
// fail on a file the host no longer has. Omitted request paths resolve
// from the record, as the resume itself resolves them.
func (m *Manager) pauseArtifactsMissing(vmID, snapshotPath, memPath string) bool {
	inst, err := m.getInstance(vmID)
	if err != nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != StatusPaused {
		return false
	}
	if snapshotPath == "" {
		snapshotPath = inst.SnapshotPath
	}
	if memPath == "" {
		memPath = inst.MemFilePath
	}
	disk := pausedDiskPath(m.cfg.RunDir, vmID, inst.DiskPath, inst.RunDirID, inst.Config.BasePath)
	return !pauseArtifactsPresent(snapshotPath, memPath, inst.BaseMemPath, disk, inst.Config.BasePath)
}

// pauseArtifactsMissingErr tells the control plane the pause artifacts are
// gone from this host, so it can name the backup generation covering the
// pause and try again.
func pauseArtifactsMissingErr(vmID string) error {
	st := status.Newf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host; retry with the recorded backup generation", vmID)
	if withInfo, err := st.WithDetails(&errdetails.ErrorInfo{Reason: vmdclient.PauseArtifactsMissingReason, Domain: "vmd"}); err == nil {
		return withInfo.Err()
	}
	return st.Err()
}

// backupRevivedTarget returns the live VM a backup-backed resume already
// booted, so a retry of that request adopts it instead of failing on
// artifacts the cold boot never had. needsGeneration is set when such a VM
// exists but the request did not name its generation: the caller must look
// it up and come back, or the VM stays unrecognized while its row stays
// paused.
func (m *Manager) backupRevivedTarget(vmID, generation string) (target *VMInstance, needsGeneration bool) {
	existing, err := m.getInstance(vmID)
	if err != nil {
		return nil, false
	}
	existing.mu.RLock()
	revived := existing.Status == StatusRunning && !existing.Unverified && existing.BackupGeneration != ""
	match := revived && existing.BackupGeneration == generation
	existing.mu.RUnlock()
	if !revived || vmDeadForRetry(m, vmID) {
		return nil, false
	}
	if generation == "" {
		return nil, true
	}
	if !match {
		return nil, false
	}
	return existing, false
}

// backupFlight is one fetch of a sandbox's backup, shared by every resume
// attempt for the same generation and detached from the RPC deadlines
// that observe it, so a retry picks the download up where it stands. Its
// state moves under the flights lock only: a finished fetch is either
// claimed by exactly one resume, which then owns the staging, or dropped
// by the cap or expiry, never both.
type backupFlight struct {
	generation string
	done       chan struct{}
	dropped    chan struct{}
	restored   backup.Restored
	err        error

	// Guarded by Manager.backupFlightsMu.
	state       flightState
	completedAt time.Time
}

type flightState int

const (
	flightFetching flightState = iota
	flightUnclaimed
	flightClaimed
	flightDropped
)

func (m *Manager) backupBaseDir() string { return filepath.Join(m.backupRestoreRoot, ".base-cache") }

func (m *Manager) restoreStagingRoot() string { return filepath.Join(m.backupRestoreRoot, "staging") }

func (m *Manager) restoreStagingDir(vmID string) string {
	return filepath.Join(m.restoreStagingRoot(), vmID)
}

// backupFlightFor joins the flight already fetching the generation or
// starts one, refusing outright when the host already carries as many
// flights as it will queue.
func (m *Manager) backupFlightFor(vmID, generation string) (*backupFlight, error) {
	m.backupFlightsMu.Lock()
	defer m.backupFlightsMu.Unlock()
	if f := m.backupFlights[vmID]; f != nil {
		if f.generation != generation {
			return nil, status.Errorf(codes.Aborted, "vm %s: a restore of a different backup is in flight", vmID)
		}
		return f, nil
	}
	if len(m.backupFlights) >= m.backupRestore.MaxFlights {
		return nil, status.Errorf(codes.ResourceExhausted, "vm %s: the host is restoring as many backups as it queues; retry later", vmID)
	}
	f := &backupFlight{generation: generation, done: make(chan struct{}), dropped: make(chan struct{})}
	m.backupFlights[vmID] = f
	go m.runBackupFlight(vmID, f)
	return f, nil
}

// fetchBackupGeneration is the fetch a flight runs; tests stand in for it.
var fetchBackupGeneration = backup.FetchGeneration

func (m *Manager) runBackupFlight(vmID string, f *backupFlight) {
	defer sentrylog.Recover("backup-fetch")
	dest := m.restoreStagingDir(vmID)
	func() {
		// The flight is claimable before done is closed, so a woken waiter
		// never finds it still fetching.
		defer close(f.done)
		defer m.publishFlight(f)
		ctx, cancel := context.WithTimeout(context.Background(), m.backupRestore.FetchBudget)
		defer cancel()
		select {
		case m.backupFetchSem <- struct{}{}:
			defer func() { <-m.backupFetchSem }()
		case <-ctx.Done():
			f.err = ctx.Err()
			return
		}
		log := m.log.With().Str("vm_id", vmID).Logger()
		// Readers hold the cache lock shared; the prune below takes it
		// exclusively, so nothing is deleted between discovery and open.
		m.backupCacheMu.RLock()
		f.restored, f.err = fetchBackupGeneration(ctx, m.backupBaseReader, vmID, f.generation, dest, func(format string, args ...any) {
			log.Debug().Msgf(format, args...)
		})
		if f.err == nil {
			f.err = m.promoteBase(&f.restored, dest)
		}
		m.backupCacheMu.RUnlock()
		// Published before any sweep runs, so the base this fetch holds
		// counts as in use from here on.
		m.publishFlight(f)
	}()
	m.dropUnclaimedBeyondCap()
	// Cache maintenance waits for every other download to finish; the
	// waiter has its result already, so that wait costs it nothing.
	if m.backupRestore.CacheBytes > 0 {
		m.backupCacheMu.Lock()
		if _, perr := backup.PruneBaseCache(m.backupBaseDir(), m.backupRestore.CacheBytes); perr != nil {
			m.log.Warn().Err(perr).Str("vm_id", vmID).Msg("backup base cache prune")
		}
		m.sweepPromotedBases()
		m.backupCacheMu.Unlock()
	}
	select {
	case <-f.dropped:
	case <-time.After(m.backupRestore.AbandonAfter):
		m.dropFlights(func(id string, g *backupFlight) bool { return g == f })
	}
}

// publishFlight makes a finished fetch claimable; the result fields are
// complete before this and read only by states past it.
func (m *Manager) publishFlight(f *backupFlight) {
	m.backupFlightsMu.Lock()
	if f.state == flightFetching {
		f.state, f.completedAt = flightUnclaimed, time.Now()
	}
	m.backupFlightsMu.Unlock()
}

// claimFlight hands the finished fetch to exactly one resume; false means
// the cap or expiry dropped it first and the caller must start over. A
// claimed flight stays registered, holding its base in use, until the
// resume that claimed it releases it.
func (m *Manager) claimFlight(vmID string, f *backupFlight) bool {
	m.backupFlightsMu.Lock()
	defer m.backupFlightsMu.Unlock()
	if f.state != flightUnclaimed {
		return false
	}
	f.state = flightClaimed
	f.drop()
	return true
}

func (m *Manager) releaseFlight(vmID string, f *backupFlight) {
	m.backupFlightsMu.Lock()
	if m.backupFlights[vmID] == f {
		delete(m.backupFlights, vmID)
	}
	m.backupFlightsMu.Unlock()
}

func (f *backupFlight) drop() {
	select {
	case <-f.dropped:
	default:
		close(f.dropped)
	}
}

// dropFlights marks every unclaimed flight victim selects as dropped under
// the lock and retires its staging there too, so a retry that registers
// the moment the lock is released writes to a path nothing else deletes.
// The retired directories are removed outside the lock.
func (m *Manager) dropFlights(victim func(vmID string, f *backupFlight) bool) {
	var retired []string
	m.backupFlightsMu.Lock()
	for vmID, f := range m.backupFlights {
		if f.state != flightUnclaimed || !victim(vmID, f) {
			continue
		}
		f.state = flightDropped
		delete(m.backupFlights, vmID)
		f.drop()
		if aside, ok := m.retireStagingLocked(vmID); ok {
			retired = append(retired, aside)
		}
	}
	m.backupFlightsMu.Unlock()
	for _, d := range retired {
		_ = os.RemoveAll(d)
	}
}

// retireStagingLocked renames a VM's staging aside in one step, under the
// flights lock, and reports the new path to delete.
func (m *Manager) retireStagingLocked(vmID string) (string, bool) {
	dir := m.restoreStagingDir(vmID)
	if _, err := os.Stat(dir); err != nil {
		return "", false
	}
	aside := dir + ".dropped-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(dir, aside); err != nil {
		m.log.Warn().Err(err).Str("vm_id", vmID).Msg("restore staging could not be retired")
		return "", false
	}
	return aside, true
}

// dropUnclaimedBeyondCap keeps completed fetches waiting for a retry within
// the configured count, oldest out first, so a recovery wave cannot hold a
// full sandbox disk per stalled request until each expires.
func (m *Manager) dropUnclaimedBeyondCap() {
	m.backupFlightsMu.Lock()
	var pending []*backupFlight
	for _, f := range m.backupFlights {
		if f.state == flightUnclaimed {
			pending = append(pending, f)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].completedAt.Before(pending[j].completedAt) })
	excess := map[*backupFlight]bool{}
	for len(pending) > m.backupRestore.MaxUnclaimed {
		excess[pending[0]] = true
		pending = pending[1:]
	}
	m.backupFlightsMu.Unlock()
	if len(excess) > 0 {
		m.dropFlights(func(_ string, f *backupFlight) bool { return excess[f] })
	}
}

// restorePausedAnchor makes memory follow the durable record after a
// failed backup boot: revival puts the paused record back, but memory
// holds either the failed instance in the error state or, after a
// completed teardown, nothing at all, and either way the next resume
// would no longer see a paused VM to recover. A destroy in progress
// wins, and a failure whose teardown is unconfirmed keeps its error
// record durably and is left alone.
func (m *Manager) restorePausedAnchor(vmID string) {
	if m.state == nil {
		return
	}
	// Destroy bypasses the lifecycle lock this resume holds; the record
	// owner lock is what it does take, so holding it across the read and
	// the publication keeps a destroyed record from coming back.
	unlockOwner := m.lockRecordOwner(vmID)
	defer unlockOwner()
	if _, destroying := m.destroying.Load(vmID); destroying {
		return
	}
	rec, err := m.state.Get(vmID)
	if err != nil || rec == nil || rec.Status != StatusPaused {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst := m.vms[vmID]; inst != nil {
		inst.mu.RLock()
		failed := inst.Status == StatusError
		inst.mu.RUnlock()
		if !failed {
			return
		}
	}
	// Folded back here rather than through the on-demand loader: a record
	// with a revival pending is parked by that loader while this resume's
	// own lock is held.
	restored := toInstance(*rec)
	m.vms[vmID] = restored
	m.indexVM(vmID, restored)
}

// retainStagingForRetry keeps a finished restore for the retry that follows
// a deadline, and drops it once the retention passes with no flight around
// to use it.
func (m *Manager) retainStagingForRetry(vmID string) {
	time.AfterFunc(m.backupRestore.AbandonAfter, func() {
		m.backupFlightsMu.Lock()
		_, inFlight := m.backupFlights[vmID]
		aside, retired := "", false
		if !inFlight {
			aside, retired = m.retireStagingLocked(vmID)
		}
		m.backupFlightsMu.Unlock()
		if retired {
			_ = os.RemoveAll(aside)
		}
	})
}

// cleanupRestoreStaging drops whatever a backup-backed resume left for the
// VM once the VM itself is gone.
func (m *Manager) cleanupRestoreStaging(vmID string) {
	if m.backupRestoreRoot == "" || !isLeafName(vmID) {
		return
	}
	_ = os.RemoveAll(m.restoreStagingDir(vmID))
}

// promoteBase moves a base materialized inside the staging dir to a path
// that outlives it: the revived VM keeps reading the base for its whole
// life, and a later pause or resume must reopen it.
func (m *Manager) promoteBase(r *backup.Restored, dest string) error {
	if r.Base == "" || !strings.HasPrefix(r.Base, dest+string(filepath.Separator)) {
		return nil
	}
	if err := os.MkdirAll(m.backupBaseDir(), 0o700); err != nil {
		return err
	}
	stable := filepath.Join(m.backupBaseDir(), filepath.Base(r.Base))
	if _, err := os.Stat(stable); err != nil {
		if err := os.Rename(r.Base, stable); err != nil {
			return err
		}
	}
	r.Base = stable
	return nil
}

// basesInUse is every promoted base a tracked VM reads plus every one a
// flight still holds for the resume that will claim it.
func (m *Manager) basesInUse() map[string]bool {
	inUse := map[string]bool{}
	m.mu.RLock()
	for _, inst := range m.vms {
		inst.mu.RLock()
		inUse[inst.Config.BasePath] = true
		inst.mu.RUnlock()
	}
	m.mu.RUnlock()
	m.backupFlightsMu.Lock()
	for _, f := range m.backupFlights {
		// A fetching flight is still writing its result; the states past
		// it were published under this lock.
		if (f.state == flightUnclaimed || f.state == flightClaimed) && f.restored.Base != "" {
			inUse[f.restored.Base] = true
		}
	}
	m.backupFlightsMu.Unlock()
	return inUse
}

// promotedBaseGrace keeps a freshly promoted base out of the sweep until
// the resume that fetched it has attached it to its VM.
const promotedBaseGrace = time.Hour

// sweepPromotedBases drops promoted bases no tracked VM reads any more.
// Nothing is swept until reattach has finished: before that a VM from the
// previous run may hold a base without yet being in m.vms, and dropping
// that base would strand its next pause and resume.
func (m *Manager) sweepPromotedBases() {
	if !m.reattachComplete.Load() {
		return
	}
	entries, err := os.ReadDir(m.backupBaseDir())
	if err != nil {
		return
	}
	inUse := m.basesInUse()
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "base-") || !strings.HasSuffix(e.Name(), ".ext4") {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < promotedBaseGrace {
			continue
		}
		if path := filepath.Join(m.backupBaseDir(), e.Name()); !inUse[path] {
			_ = os.Remove(path)
		}
	}
}

// resumeFromBackupLocked brings a paused sandbox back from the backup
// generation the control plane recorded as covering the pause, when the
// pause artifacts are gone from the host. Backups hold the disk and not
// the memory, so the sandbox boots cold with its files intact. The fetch
// runs on its own budget; a caller whose deadline expires first gets
// Unavailable and its retry joins the same fetch.
func (m *Manager) resumeFromBackupLocked(ctx context.Context, vmID, generation string, rules *sandboxNetworkRules) (*VMInstance, error) {
	if generation == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host and no backup is recorded for the pause", vmID)
	}
	inst, err := m.getInstance(vmID)
	if err != nil {
		return nil, err
	}
	inst.mu.RLock()
	teamID, ownerID, vcpu, memMiB := inst.TeamID, inst.OwnerID, inst.Config.VCPU, inst.Config.MemoryMiB
	inst.mu.RUnlock()
	if err := os.MkdirAll(m.restoreStagingRoot(), 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "restore staging: %v", err)
	}
	tFetch := time.Now()
	flight, err := m.backupFlightFor(vmID, generation)
	if err != nil {
		return nil, err
	}
	select {
	case <-flight.done:
	case <-ctx.Done():
		return nil, status.Errorf(codes.Unavailable, "vm %s: backup restore in progress; retry", vmID)
	}
	if !m.claimFlight(vmID, flight) {
		return nil, status.Errorf(codes.Unavailable, "vm %s: the restored backup was dropped before this resume claimed it; retry", vmID)
	}
	defer m.releaseFlight(vmID, flight)
	m.recordPhases("resume", "backup", map[string]time.Duration{"backup_fetch": time.Since(tFetch)})
	if flight.err != nil {
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		if errors.Is(flight.err, backup.ErrNoMatchingBackup) {
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s: pause artifacts missing on host and the recorded backup is not in the bucket", vmID)
		}
		return nil, status.Errorf(codes.Unavailable, "vm %s: fetch backup: %v", vmID, flight.err)
	}
	r := flight.restored
	log := m.log.With().Str("vm_id", vmID).Logger()
	log.Info().Str("generation", generation).Dur("fetch", time.Since(tFetch)).
		Msg("resume: pause artifacts missing on host; reviving from backup")
	tBoot := time.Now()
	revived, err := m.reviveVMLocked(ctx, vmID, r.Disk, r.Base, r.Standalone, false, teamID, ownerID, vcpu, memMiB, rules, generation)
	m.recordPhases("resume", "backup", map[string]time.Duration{"backup_boot": time.Since(tBoot)})
	if err != nil {
		m.restorePausedAnchor(vmID)
		if ctx.Err() != nil {
			// The download is done and the caller's retry is imminent;
			// starting it over would only run out of time again.
			m.retainStagingForRetry(vmID)
			return nil, err
		}
		_ = os.RemoveAll(m.restoreStagingDir(vmID))
		return nil, err
	}
	_ = os.RemoveAll(m.restoreStagingDir(vmID))
	return revived, nil
}
