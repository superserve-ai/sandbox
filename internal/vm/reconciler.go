package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"errors"

	"github.com/rs/zerolog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	fcmodels "github.com/superserve-ai/sandbox/internal/vm/fc/models"
)

// trashDirName is the per-root quarantine directory. Orphan dirs are moved to
// <root>/<trashDirName>/<date>/<uuid> before being removed after the retention
// soak. It is not a UUID, so the orphan scan never enumerates it.
const trashDirName = ".trash"

// buildVMIDPrefix marks VMs owned by the template build pipeline. Their
// lifecycle is managed by buildTemplateWorker, not the reconciler — they
// have no sandbox row by design, so the reconciler skips them.
const buildVMIDPrefix = "build-"

func isBuildVM(id string) bool { return strings.HasPrefix(id, buildVMIDPrefix) }

// ReconcilerConfig controls the periodic reconciler.
type ReconcilerConfig struct {
	// Interval is how often the reconciler runs.
	Interval time.Duration
	// GracePeriod is the minimum time a drift must persist before the
	// reconciler takes destructive action. Prevents races where VMD has
	// just started a VM and systemd hasn't fully registered it yet.
	GracePeriod time.Duration
	// MaxAutoFailPerHour caps destructive actions per host to bound the
	// blast radius of a reconciler bug. If exceeded, the reconciler
	// logs a paging alert and stops taking destructive action until
	// the counter resets.
	MaxAutoFailPerHour int
	// HostID is this host's identifier in the `host` table. The reconciler
	// only operates on sandboxes with this host_id.
	HostID string
	// DB is optional. When set, the reconciler does three-way drift
	// detection (BoltDB ↔ systemd ↔ DB) and writes audit log entries.
	// When nil, it only compares BoltDB and systemd.
	DB *db.Queries
	// DiskScanEnabled turns on the detect-only disk-orphan pass: it scans
	// RunDir/SnapshotDir for per-sandbox dirs with no live row and logs what
	// it would reclaim. It never deletes.
	DiskScanEnabled bool
	// DiskGracePeriod keeps a sandbox's dirs out of the orphan set for this
	// long after destroyed_at, so an in-flight in-band delete isn't raced.
	DiskGracePeriod time.Duration
	// DiskScanEvery runs the disk pass once every Nth reconcile tick so a
	// filesystem walk doesn't ride the fast liveness loop. Values < 1 mean
	// every tick.
	DiskScanEvery int
	// DiskReclaimEnabled turns the disk pass from detect-only into reclamation:
	// orphan dirs are quarantine-moved to <root>/.trash/<date>/ (reversible)
	// and trash older than DiskTrashRetention is removed. Default false — the
	// detect-only numbers must be validated on prod before this is flipped on.
	DiskReclaimEnabled bool
	// DiskDeleteBudget bounds how many orphan sandboxes one pass quarantines so
	// a keep-set bug can't move everything at once. Deferred work runs next pass.
	DiskDeleteBudget int
	// DiskTrashRetention is how long a quarantined dir soaks under .trash before
	// it is permanently removed — the window to spot and reverse a bad reclaim.
	DiskTrashRetention time.Duration
	// UnverifiedOrphanGrace is how long a crash-window orphan (a Running but
	// unverified record behind a live unit) is left alone before the
	// reconciler stops it. Deliberately far longer than the default grace:
	// a retry ADOPTS such a VM and keeps the guest's work, so the reaper must
	// lose that race — it exists only for orphans nobody ever comes back for.
	UnverifiedOrphanGrace time.Duration
}

// DefaultReconcilerConfig returns sensible defaults from the design doc.
func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		Interval:           30 * time.Second,
		GracePeriod:        60 * time.Second,
		MaxAutoFailPerHour: 5,
		DiskScanEnabled:    true,
		DiskGracePeriod:    24 * time.Hour,
		DiskScanEvery:      4,
		DiskReclaimEnabled: false,
		DiskDeleteBudget:   50,
		DiskTrashRetention: 72 * time.Hour,
		// An hour outlasts any live retry loop (the control plane's own
		// retries are seconds), so adoption always gets first claim.
		UnverifiedOrphanGrace: time.Hour,
	}
}

// Reconciler detects and fixes drift between three sources of truth:
//
//   - systemd: which firecracker@ units are actually running
//     (authoritative for liveness)
//   - Control plane DB: the sandbox rows scheduled on this host
//     (authoritative for intent)
//   - BoltDB: VMD's own fast-path cache (authoritative for nothing)
//
// The DB source is optional — if the reconciler is constructed without a
// DB, it falls back to a BoltDB ↔ systemd comparison only. Destructive
// actions are rate-limited via MaxAutoFailPerHour and require the drift
// to persist across at least two consecutive runs (GracePeriod).
type Reconciler struct {
	mgr *Manager
	cfg ReconcilerConfig

	// driftSeen tracks the first-seen timestamp for each drifted VM so
	// we can enforce the grace period. Keyed by vmID.
	mu          sync.Mutex
	driftSeen   map[string]time.Time
	autoFailLog []time.Time // timestamps of recent auto-fail actions

	// passCount counts completed reconcile passes, used to run the disk
	// scan on a slower sub-cadence. Only touched from the single Run loop.
	passCount uint64
	// prevKeptLive is the prior disk pass's protected live-sandbox count, used
	// to detect a keep-set collapse. -1 until the first pass. Run loop only.
	prevKeptLive int
	// lastVmsWeight is the CPU/IO weight last applied to the direct-spawn
	// service, so a pass that finds the same live direct-VM count skips the
	// set-property. 0 until the first adjustment. Run loop only.
	lastVmsWeight int

	// markFailed flips a sandbox row to failed; a field so rule tests can
	// capture the flip without a control-plane DB. Defaults to markFailedInDB.
	markFailed func(ctx context.Context, vmID string, observed db.SandboxStatus) bool

	// stopVM stops a VM by supervision mode; a field so rule tests can
	// exercise the reap rules without a live systemd or a real kill (the
	// cgroup arm's kill-and-wait budget is seconds). Defaults to mgr.stopVM.
	stopVM func(ctx context.Context, vmID string, supervision Supervision) error
}

// NewReconciler creates a reconciler bound to a Manager.
func NewReconciler(mgr *Manager, cfg ReconcilerConfig) *Reconciler {
	r := &Reconciler{
		mgr:          mgr,
		cfg:          cfg,
		driftSeen:    make(map[string]time.Time),
		prevKeptLive: -1,
	}
	r.markFailed = r.markFailedInDB
	r.stopVM = mgr.stopVM
	return r
}

// vmFullyDown is the mode-aware terminal proof a record release requires: a
// unit VM's unit in a TERMINAL state, a cgroup VM's group conclusively empty.
// The wrong-mode oracle answers vacuously (no unit exists for a cgroup VM),
// so only this claim may precede markStale.
func (r *Reconciler) vmFullyDown(ctx context.Context, vmID string, supervision Supervision) bool {
	if cgroupSupervised(supervision) {
		return r.mgr.cgroupDefinitelyDead(vmID)
	}
	return unitFullyDown(ctx, systemdUnitName(vmID))
}

// runTimeout bounds each reconciliation pass so a slow DB or stuck
// systemctl call cannot wedge the loop.
const runTimeout = 25 * time.Second

// Run launches the reconciler loop. Blocks until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context) {
	log := r.mgr.log.With().Str("component", "reconciler").Logger()
	log.Info().
		Dur("interval", r.cfg.Interval).
		Dur("grace_period", r.cfg.GracePeriod).
		Int("max_autofail_per_hour", r.cfg.MaxAutoFailPerHour).
		Msg("reconciler started")

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	// Run once immediately so startup is observable.
	r.runWithTimeout(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("reconciler exiting")
			return
		case <-ticker.C:
			r.runWithTimeout(ctx)
		}
	}
}

// runWithTimeout bounds a single reconciliation pass. Runs deadlines
// below the tick interval so two consecutive runs cannot overlap.
func (r *Reconciler) runWithTimeout(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()
	r.runOnce(ctx)
}

// runOnce performs a single reconciliation pass. Each pass:
//  1. Queries BoltDB, systemd, and (optionally) the control plane DB.
//  2. Compares the three sets.
//  3. Records a "first seen" timestamp for every drift so we can enforce
//     the grace period (rule C7).
//  4. Applies fixes that have persisted past the grace period, rate-limited
//     by MaxAutoFailPerHour (rule C6).
func (r *Reconciler) runOnce(ctx context.Context) {
	log := r.mgr.log.With().Str("component", "reconciler").Logger()

	if r.mgr.state == nil {
		log.Debug().Msg("no state store — skipping run")
		return
	}

	// Pass timestamp; the disk scan derives its grace cutoff from it (rows
	// destroyed within, and dirs touched within, DiskGracePeriod are kept).
	snapshotTime := time.Now()

	// Source B: running VMs, as a fail-closed UNION of both supervision
	// modes — active systemd units and populated per-VM cgroups. This set
	// gates every destructive drift rule and the presence sweep, so a live
	// VM missing from it would be marked failed and have its netns freed
	// under a running Firecracker. If EITHER source errors, abort the whole
	// pass: a partial set presents that source's VMs as dead. supervisionOf
	// records which source listed each ID so the stop path can pick the
	// right mechanism when the DB row (and its Supervision) is absent.
	unitIDs, err := listActiveFirecrackerUnits(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to list systemd units")
		return
	}
	active := make(map[string]bool)
	supervisionOf := make(map[string]Supervision)
	for _, id := range unitIDs {
		if isBuildVM(id) {
			continue
		}
		active[id] = true
		supervisionOf[id] = SupervisionUnit
	}
	if r.mgr.cgroups != nil {
		cgIDs, cerr := r.mgr.cgroups.scanVMCgroups()
		if cerr != nil {
			log.Error().Err(cerr).Msg("failed to scan vm cgroups")
			return
		}
		for _, id := range cgIDs {
			if isBuildVM(id) {
				continue
			}
			pop, perr := r.mgr.cgroups.vmCgroupPopulated(id)
			if perr != nil {
				log.Error().Err(perr).Str("vm_id", id).Msg("failed to read vm cgroup state")
				return
			}
			if pop {
				active[id] = true
				supervisionOf[id] = SupervisionCgroup
			}
		}
	}

	// Keep the direct-spawn service's scheduling weight proportional to how
	// many direct VMs actually compete, now that both populations are known.
	r.adjustDirectSpawnWeight(ctx, active, supervisionOf)

	// Presence convergence rides the reconcile tick: give every quiesced legacy
	// overlay its side-car, then persist the converged marker. No-op (one
	// atomic load) once the host has converged.
	r.mgr.sweepPresenceSidecars(active)

	// Source C: DB sandbox rows for this host (optional), with their
	// linked snapshot path joined in so Drift 4 can stat the snapshot
	// without a per-row lookup. A short per-query deadline keeps a slow
	// DB from stalling the whole run.
	var dbSandboxes map[string]db.ListSandboxesByHostRow
	if r.cfg.DB != nil && r.cfg.HostID != "" {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		rows, dbErr := r.cfg.DB.ListSandboxesByHost(qctx, r.cfg.HostID)
		cancel()
		if dbErr != nil {
			log.Error().Err(dbErr).Msg("failed to list sandboxes from DB")
		} else {
			dbSandboxes = make(map[string]db.ListSandboxesByHostRow, len(rows))
			for _, row := range rows {
				dbSandboxes[row.Sandbox.ID.String()] = row
			}
		}
	}

	// Source A: BoltDB records. Full records are only needed on the
	// DB-down fallback path (Drift 2) or for actual orphan cleanup — the
	// common path uses ID-only iteration.
	var bolted map[string]VMRecord
	var boltedIDs map[string]struct{}
	if dbSandboxes == nil {
		records, allErr := r.mgr.state.All()
		if allErr != nil {
			log.Error().Err(allErr).Msg("failed to read state store")
			return
		}
		bolted = make(map[string]VMRecord, len(records))
		for _, rec := range records {
			if isBuildVM(rec.ID) {
				continue
			}
			bolted[rec.ID] = rec
		}
	} else {
		idSet, idsErr := r.mgr.state.IDs()
		if idsErr != nil {
			log.Error().Err(idsErr).Msg("failed to list state store IDs")
			return
		}
		boltedIDs = make(map[string]struct{}, len(idSet))
		for id := range idSet {
			if isBuildVM(id) {
				continue
			}
			boltedIDs[id] = struct{}{}
		}
	}

	now := time.Now()

	// errorRecord reports whether id's record reads Error. The tracked
	// in-memory instance is authoritative when present: reattach can park an
	// Error instance whose durable write failed (row still Running), and that
	// VM must still be owned by the error rules. Statuses are fetched per
	// candidate id so the common DB-mode pass stays ID-only.
	errorRecord := func(id string) bool {
		r.mgr.mu.RLock()
		inst := r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if inst != nil {
			inst.mu.RLock()
			st := inst.Status
			inst.mu.RUnlock()
			return st == StatusError
		}
		if bolted != nil {
			rec, ok := bolted[id]
			return ok && rec.Status == StatusError
		}
		if _, ok := boltedIDs[id]; !ok {
			return false
		}
		rec, err := r.mgr.state.Get(id)
		return err == nil && rec != nil && rec.Status == StatusError
	}

	// Drift 0: recordless cgroup survivor. A cgroup in the running-set with
	// no BoltDB record and no in-memory instance is a VM vmd cannot service —
	// a crash between direct-spawn and the first persist. Drift 1/3 miss it
	// (the DB row may still read creating/running, and those rules key off
	// the record or skip nonterminal rows). Stop it after grace, under the op
	// lock, re-checking that it's still recordless so an in-flight launch
	// that just made the cgroup is never killed.
	for id := range active {
		if supervisionOf[id] != SupervisionCgroup {
			continue
		}
		inBolt := false
		if dbSandboxes == nil {
			_, inBolt = bolted[id]
		} else {
			_, inBolt = boltedIDs[id]
		}
		if inBolt {
			continue
		}
		r.mgr.mu.RLock()
		_, hasInst := r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if hasInst {
			continue
		}
		if !r.gracePeriodElapsed("cgrouporphan:"+id, now) {
			continue
		}
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			continue // a launch/op holds the lock; re-evaluate next tick
		}
		// Re-check under the lock: a launch may have persisted the record or
		// published the instance since the snapshot at the top of the pass. A
		// read error reads as recorded (fail-closed) — a transient Has failure
		// must not classify a freshly recorded live VM as recordless and kill it.
		if has, herr := r.mgr.state.Has(id); herr != nil || has {
			unlockOp()
			r.clearDrift("cgrouporphan:" + id)
			continue
		}
		r.mgr.mu.RLock()
		_, hasInst = r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if hasInst {
			unlockOp()
			continue
		}
		if !r.consumeAutoFailBudget(id) {
			unlockOp()
			r.writeAudit(ctx, id, "budget_exhausted", "recordless cgroup stop suppressed by rate limit", "cgroup_orphan_no_record")
			continue
		}
		log.Warn().Str("vm_id", id).Str("drift", "cgroup_orphan_no_record").
			Msg("recordless cgroup survivor — stopping")
		// Recover the netns from the live process BEFORE the kill, or the
		// slot/veth/ns leaks: an untracked VM has no device record, so
		// CleanupVMOrNamespace can only reclaim it given the namespace name.
		// A protected survivor whose process just exited has no pid to read —
		// fall back to the mapping the startup reap preserved.
		nsName := r.mgr.netMgr.NamespaceForPID(r.mgr.cgroups.firstPID(id))
		if nsName == "" {
			if v, ok := r.mgr.survivorNS.Load(id); ok {
				nsName = v.(string)
			}
		}
		if err := r.mgr.stopVM(ctx, id, SupervisionCgroup); err != nil {
			// If only the rmdir failed, the emptied group drops out of the
			// populated active-set next pass and this drift never revisits it —
			// stranding the netns/slot AND leaving the empty dir to block
			// drain-check until restart. Once death is confirmed (empty), reclaim
			// the netns and retry the rmdir; a clean removal fully reclaims the
			// survivor. Skip on an inconclusive read so a live FC keeps its tap.
			if pop, perr := r.mgr.cgroups.vmCgroupPopulated(id); perr == nil && !pop {
				r.mgr.netMgr.CleanupVMOrNamespace(id, nsName)
				r.mgr.survivorNS.Delete(id)
				if rerr := r.mgr.cgroups.removeVMCgroup(ctx, id); rerr == nil {
					unlockOp()
					r.writeAudit(ctx, id, "orphan_stop", "recordless cgroup survivor (rmdir retried)", "cgroup_orphan_no_record")
					r.clearDrift("cgrouporphan:" + id)
					continue
				}
			}
			log.Error().Err(err).Str("vm_id", id).Msg("failed to stop recordless cgroup — leaving for retry")
			unlockOp()
			continue
		}
		r.mgr.netMgr.CleanupVMOrNamespace(id, nsName)
		r.mgr.survivorNS.Delete(id)
		unlockOp()
		r.writeAudit(ctx, id, "orphan_stop", "recordless cgroup survivor", "cgroup_orphan_no_record")
		r.clearDrift("cgrouporphan:" + id)
	}

	// Drift 0b: empty cgroup directory no record owns. A per-VM group whose FC
	// has exited but that was never removed (a recordless survivor whose
	// process left on its own, an rmdir that failed transiently, or a verify
	// throwaway's leftover behind a unit-mode record) stays OUT of the
	// populated active-set, so Drift 0 never revisits it — and it keeps
	// counting against drain-check until a restart. Reap the leftover
	// directory, after grace + op-lock, re-checking it is still empty and
	// unowned so an in-flight launch's fresh group is never removed.
	// Non-destructive (an empty group has no process to kill), so it doesn't
	// consume the auto-fail budget.
	cgroupOwnedByRecord := func(id string) bool {
		if dbSandboxes == nil {
			rec, ok := bolted[id]
			return ok && cgroupSupervised(rec.Supervision)
		}
		if _, ok := boltedIDs[id]; !ok {
			return false
		}
		rec, err := r.mgr.state.Get(id)
		if err != nil {
			return true // unreadable: conservative, treat as owned
		}
		return rec != nil && cgroupSupervised(rec.Supervision)
	}
	if r.mgr.cgroups != nil {
		if cgDirs, cgErr := r.mgr.cgroups.scanVMCgroups(); cgErr == nil {
			for _, id := range cgDirs {
				if active[id] {
					continue // populated (Drift 0 handles it)
				}
				// Build cgroups are NOT skipped here: the build-VM exclusion
				// belongs on the liveness drifts (don't kill an in-flight build),
				// not on janitorial removal of an already-empty dir. An in-flight
				// build is populated (caught below) or holds the op-lock; only an
				// empty leftover is reaped, and rmdir is non-destructive.
				//
				// The dir is owned only if the record OR the tracked instance
				// CLAIMS cgroup supervision. A unit-mode record/instance over an
				// empty group (a verify throwaway's rmdir that failed on a paused
				// legacy VM) is rubble no other rule reaps, yet it counts against
				// drain-check forever — a live unit instance does NOT own it.
				// Unreadable record reads as owned (conservative); the op-lock and
				// the populated re-check below guard an in-flight cgroup launch.
				if cgroupOwnedByRecord(id) || r.mgr.instanceClaimsCgroup(id) {
					continue
				}
				if !r.gracePeriodElapsed("cgroupempty:"+id, now) {
					continue
				}
				unlockOp, ok := r.mgr.tryLockVMOp(id)
				if !ok {
					continue // a launch/op holds the lock
				}
				// Re-check under the lock: an in-flight launch may have persisted
				// a record, published an instance, or forked FC into the group.
				if cgroupOwnedByRecord(id) || r.mgr.instanceClaimsCgroup(id) {
					unlockOp()
					r.clearDrift("cgroupempty:" + id)
					continue
				}
				if pop, perr := r.mgr.cgroups.vmCgroupPopulated(id); perr != nil || pop {
					unlockOp()
					continue // became populated or unreadable — not ours to remove
				}
				if err := r.mgr.cgroups.removeVMCgroup(ctx, id); err != nil {
					log.Warn().Err(err).Str("vm_id", id).Msg("failed to reap empty recordless cgroup — retrying next pass")
					unlockOp()
					continue
				}
				// A protected survivor's process is gone, so the mapping
				// preserved at startup is the only route left to its reserved
				// slot and veth; spend it or they stay held until restart.
				if ns, ok := r.mgr.survivorNS.LoadAndDelete(id); ok {
					r.mgr.netMgr.CleanupVMOrNamespace(id, ns.(string))
				}
				unlockOp()
				r.writeAudit(ctx, id, "orphan_reap", "empty recordless cgroup directory", "cgroup_empty_no_record")
				r.clearDrift("cgroupempty:" + id)
			}
		}
	}

	// Drift 1: DB says active, systemd/socket says dead.
	r.reapDeadActiveVMs(ctx, log, dbSandboxes, active, errorRecord, now)

	r.failEmptyShells(ctx, log, dbSandboxes, active, supervisionOf, now)

	// Drift 2: BoltDB says running but VM is actually dead, and DB is
	// unavailable (reconciler running in BoltDB-only mode). Fall back to
	// the old behavior: just clean up the stale BoltDB entry.
	if dbSandboxes == nil {
		for id, rec := range bolted {
			if rec.Status != StatusRunning {
				continue
			}
			if active[id] {
				r.clearDrift(id)
				continue
			}
			// Error records are Drift 8's (see Drift 1). errorRecord, not
			// rec.Status: a parked Error whose durable write failed still
			// reads Running here.
			if errorRecord(id) {
				continue
			}
			if !r.gracePeriodElapsed(id, now) {
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "boltdb_running_unit_missing").
				Msg("dead Firecracker detected (no DB context)")
			r.markStale(id)
			r.writeAudit(ctx, id, "stale_cleanup", "VM dead, DB unavailable", "boltdb_running_unit_missing")
		}
	}

	// Drift 3: systemd unit active, DB says deleted/failed/missing.
	// `failed` catches restores whose forward-path cleanup didn't run
	// (e.g., gRPC ctx fired mid-LoadSnapshot and our work continued
	// after the caller gave up).
	if dbSandboxes != nil {
		for id := range active {
			sb, known := dbSandboxes[id]
			deleted := known && sb.Sandbox.Status == db.SandboxStatusDeleted
			failed := known && sb.Sandbox.Status == db.SandboxStatusFailed
			if known && !deleted && !failed {
				continue
			}
			// A recordless cgroup id is Drift 0's: it recovers the netns from
			// the live pid before killing, under the op lock — this branch's
			// markStale would read no record and leak the slot, and both
			// rules would spend auto-fail budget on the same VM.
			if supervisionOf[id] == SupervisionCgroup {
				if _, ok := boltedIDs[id]; !ok {
					continue
				}
			}
			// Error records are Drift 8's (see Drift 1): its halves gate
			// every record release on the terminal unit state, which this
			// branch's stop does not.
			if errorRecord(id) {
				continue
			}
			if !r.gracePeriodElapsed("orphan:"+id, now) {
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				r.writeAudit(ctx, id, "budget_exhausted", "orphan_stop suppressed by rate limit", "systemd_active_db_missing")
				continue
			}
			reason := "systemd unit with no DB row"
			kind := "systemd_active_db_missing"
			if deleted {
				reason = "systemd unit for soft-deleted sandbox"
				kind = "systemd_active_db_deleted"
			} else if failed {
				reason = "systemd unit for failed sandbox"
				kind = "systemd_active_db_failed"
			}
			log.Warn().Str("vm_id", id).Str("drift", kind).Msg("orphan systemd unit — stopping")
			if err := r.mgr.stopVM(ctx, id, supervisionOf[id]); err != nil {
				log.Error().Err(err).Str("vm_id", id).Msg("failed to stop orphan VM")
				continue
			}
			removeUnitDropIn(id)
			r.markStale(id)
			r.writeAudit(ctx, id, "orphan_stop", reason, kind)
			r.clearDrift("orphan:" + id)
		}
	}

	// Drift 8: BoltDB record in Error but its systemd unit is still active.
	// Reattach parks an unmanageable VM this way (unit alive, API socket
	// gone, stop unconfirmed) so no request path adopts it; no other rule
	// stops the unit, which otherwise burns CPU/RAM until a user-driven
	// relaunch or destroy. Keyed on BoltDB + systemd only, so it runs in
	// both DB modes.
	for id := range active {
		if !errorRecord(id) {
			r.clearDrift("errunit:" + id)
			continue
		}
		if !r.gracePeriodElapsed("errunit:"+id, now) {
			continue
		}
		// Drift 7's discipline: lock before spending budget, then recheck
		// the AUTHORITATIVE in-memory record — a relaunch can complete
		// mid-pass (flip the record to Running, own the unit name, release
		// the lock), and stopping then would kill the fresh VM.
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			continue
		}
		if r.mgr.instanceRunning(id) {
			unlockOp()
			r.clearDrift("errunit:" + id)
			continue
		}
		if !r.consumeAutoFailBudget(id) {
			unlockOp()
			r.writeAudit(ctx, id, "budget_exhausted", "error_unit_stop suppressed by rate limit", "boltdb_error_unit_active")
			continue
		}
		log.Warn().Str("vm_id", id).Str("drift", "boltdb_error_unit_active").
			Msg("error-status VM with live unit — stopping")
		if err := r.stopVM(ctx, id, supervisionOf[id]); err != nil {
			unlockOp()
			log.Error().Err(err).Str("vm_id", id).Msg("failed to stop error-status VM")
			continue
		}
		// A nil stop can still mean a deactivating unit (the expired-wait
		// settle reports those complete); release needs the mode-aware
		// terminal claim (vmFullyDown). Not yet down → the record stays for
		// the dead half to retry once it is.
		if !r.vmFullyDown(ctx, id, supervisionOf[id]) {
			unlockOp()
			continue
		}
		removeUnitDropIn(id)
		staleErr := r.markStale(id)
		unlockOp()
		// Flip the DB row with the already-grace-qualified reap: Drift 1
		// cleared its marker while the unit was active, so leaving the row
		// Active would advertise a dead sandbox for another full grace.
		// Compare-and-set: a relaunch queued on the lock (or a resume the
		// control plane already started) owns the row now, not this pass's
		// snapshot. Not gated on the release: the unit is proven down either
		// way, and the flip frees no resource (same reasoning as the wedge
		// branch below).
		if dbSandboxes != nil {
			if sb, known := dbSandboxes[id]; known && sb.Sandbox.Status == db.SandboxStatusActive {
				r.markFailedInDB(ctx, id, db.SandboxStatusActive)
			}
		}
		r.finalizeErrorReap(ctx, id, "errunit:"+id, "error_unit_stop",
			"live unit for error-status record", "boltdb_error_unit_active", staleErr)
	}

	// The dead-unit half of Drift 8: an Error record whose unit is gone —
	// parked by an error path that stopped the unit, or left when the reap
	// above stopped the unit but the record deletion failed. No other rule
	// owns it (Drifts 1/3 key on other unit states, Drift 2 on Running,
	// Drift 5 on missing DB rows). Grace gives the control plane's own
	// destroy first claim on the record.
	reapDeadError := func(id string) {
		if active[id] {
			r.clearDrift("errdead:" + id)
			return
		}
		// The unit is gone, so the active half no longer visits this id —
		// its grace marker retires here, or a recurrence would inherit the
		// old timestamp and skip the grace period.
		r.clearDrift("errunit:" + id)
		if !errorRecord(id) {
			r.clearDrift("errdead:" + id)
			return
		}
		if !r.gracePeriodElapsed("errdead:"+id, now) {
			return
		}
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			return
		}
		if r.mgr.instanceRunning(id) {
			unlockOp()
			r.clearDrift("errdead:" + id)
			return
		}
		// Absence from the active-only snapshot is not terminal — an
		// activating or deactivating unit still has a process, and markStale
		// releases the record and namespace. Probe before spending budget.
		// cgroupStillLive mirrors DestroyVM's mode-agnostic gate: a cgroup
		// VM's absence from the snapshot already implies an empty group (the
		// scan fails the pass closed), but release deserves the local proof,
		// not one derived from the scan, the gate, and the lock together.
		if !unitFullyDown(ctx, systemdUnitName(id)) || r.mgr.cgroupStillLive(id) {
			// The record and namespace stay held until terminal, but the row
			// must not keep billing and routing through a long wedge — a
			// parked VM serves nothing, and flipping the row frees no
			// resource, so the terminal gate doesn't apply. Fires once per
			// wedge: the next pass's snapshot reads 'failed'.
			if dbSandboxes != nil {
				if sb, known := dbSandboxes[id]; known && sb.Sandbox.Status == db.SandboxStatusActive && r.consumeAutoFailBudget(id) {
					if r.markFailedInDB(ctx, id, db.SandboxStatusActive) {
						r.writeAudit(ctx, id, "mark_failed", "wedged error VM: row flipped while awaiting terminal unit", "boltdb_error_unit_wedged")
					}
				}
			}
			unlockOp()
			return
		}
		if !r.consumeAutoFailBudget(id) {
			unlockOp()
			return
		}
		staleErr := r.markStale(id)
		unlockOp()
		// Drift 1 skips Error records, so the row flip lands here (still
		// compare-and-set: a relaunch may own the row by now).
		if dbSandboxes != nil {
			if sb, known := dbSandboxes[id]; known && sb.Sandbox.Status == db.SandboxStatusActive {
				r.markFailedInDB(ctx, id, db.SandboxStatusActive)
			}
		}
		r.finalizeErrorReap(ctx, id, "errdead:"+id, "stale_cleanup",
			"error record with no unit", "boltdb_error_unit_missing", staleErr)
	}
	if bolted != nil {
		for id := range bolted {
			reapDeadError(id)
		}
	} else {
		for id := range boltedIDs {
			reapDeadError(id)
		}
	}

	// Drift 7: systemd unit active, DB says paused — an interrupted pause
	// stop left the old firecracker pinning guest RAM; stop it. DB rows
	// only: a mid-resume sandbox reads 'resuming' there, clearing the
	// drift, while its BoltDB record stays Paused until the resume
	// persists — keying off records could kill a just-launched resume.
	if dbSandboxes != nil {
		for id := range active {
			sb, known := dbSandboxes[id]
			if !known || sb.Sandbox.Status != db.SandboxStatusPaused {
				r.clearDrift("pausedunit:" + id)
				continue
			}
			if !r.gracePeriodElapsed("pausedunit:"+id, now) {
				continue
			}
			// Take the lock BEFORE spending budget: if a launch/pause is in
			// flight for this vmID (DB snapshot is from the top of the pass;
			// a resume may have claimed and relaunched this unit since),
			// TryLock fails and we skip — without burning an auto-fail slot
			// on a stop we won't perform. A genuinely stale unit is
			// reclaimed next tick.
			unlockOp, ok := r.mgr.tryLockVMOp(id)
			if !ok {
				continue
			}
			// Re-check liveness under the lock against the AUTHORITATIVE
			// in-memory record, not the top-of-pass DB snapshot: a resume
			// can complete mid-pass (relaunch the unit, set Running, release
			// the lock) so tryLock succeeds while the snapshot still says
			// paused. Stopping then would kill the freshly-resumed VM. A
			// genuine stale unit has a Paused/absent record, not Running.
			if r.mgr.instanceRunning(id) {
				unlockOp()
				r.clearDrift("pausedunit:" + id)
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				unlockOp()
				r.writeAudit(ctx, id, "budget_exhausted", "orphan_stop suppressed by rate limit", "systemd_active_db_paused")
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "systemd_active_db_paused").
				Msg("live unit for paused sandbox — stopping")
			err := r.mgr.stopVM(ctx, id, supervisionOf[id])
			unlockOp()
			if err != nil {
				log.Error().Err(err).Str("vm_id", id).Msg("failed to stop paused sandbox's unit")
				continue
			}
			// Reuse the orphan_stop action (both stop a unit that shouldn't
			// run); the drift_kind column carries the paused-specific detail.
			r.writeAudit(ctx, id, "orphan_stop", "unit still running for paused sandbox", "systemd_active_db_paused")
			r.clearDrift("pausedunit:" + id)
		}
	}

	r.reapUnverifiedOrphans(ctx, log, dbSandboxes, active, supervisionOf, now)

	// Rollback drain: with direct spawn disarmed, paused cgroup records are
	// demoted back to unit supervision so the fleet converges to a state an
	// older binary can manage (see demotePausedCgroupRecords).
	if r.mgr.cgroups != nil && !r.mgr.directSpawnArmed.Load() {
		r.demotePausedCgroupRecords(ctx, log)
	}

	// Drift 4: DB says paused, snapshot file missing on disk → mark failed.
	r.failMissingSnapshots(ctx, log, dbSandboxes, now)

	// Drift 5: BoltDB record exists but DB has no corresponding sandbox
	// row (either never written or soft-deleted). Clean up the BoltDB
	// entry. If the VM is still live, we ALSO need to stop it — leaving
	// a systemd unit running for a sandbox the control plane forgot about
	// is a resource leak and a security risk.
	if dbSandboxes != nil {
		// Fetch the full record only for the few IDs that look orphaned,
		// not for every bolted entry.
		for id := range boltedIDs {
			if _, ok := dbSandboxes[id]; ok {
				continue
			}
			if !r.gracePeriodElapsed("bolt-orphan:"+id, now) {
				continue
			}
			rec, getErr := r.mgr.state.Get(id)
			if getErr != nil || rec == nil {
				r.clearDrift("bolt-orphan:" + id)
				continue
			}
			// Error records are Drift 8's (see Drift 1): its halves gate
			// every record release on the terminal unit state, and a
			// transitional unit — absent from the active snapshot — would
			// reach the markStale below with its process still alive.
			if errorRecord(id) {
				continue
			}
			// Only stopping a live unit is destructive; charge the budget there.
			// Gate on the fail-closed `active` snapshot (the pass bailed if systemctl
			// couldn't be listed) so an inconclusive check never frees a live VM's slot.
			if active[id] {
				if !r.consumeAutoFailBudget(id) {
					r.writeAudit(ctx, id, "budget_exhausted", "orphan_stop suppressed by rate limit", "boltdb_present_db_missing")
					continue
				}
				log.Warn().Str("vm_id", id).Str("drift", "boltdb_present_db_missing").
					Msg("live orphan systemd unit with no DB row — stopping")
				if err := r.mgr.stopVM(ctx, id, supervisionOf[id]); err != nil {
					log.Error().Err(err).Str("vm_id", id).Msg("failed to stop orphan VM from BoltDB — leaving for retry")
					continue
				}
				removeUnitDropIn(id)
			}
			r.markStale(id)
			r.writeAudit(ctx, id, "stale_cleanup", "BoltDB entry with no DB row", "boltdb_present_db_missing")
			r.clearDrift("bolt-orphan:" + id)
		}
	}

	// Drift 6 (detect-only): per-sandbox dirs on disk with no live row. Runs
	// on a slower sub-cadence so the filesystem walk doesn't ride every tick.
	r.passCount++
	every := r.cfg.DiskScanEvery
	if every < 1 {
		every = 1
	}
	if r.cfg.DiskScanEnabled && r.passCount%uint64(every) == 0 {
		r.detectDiskOrphans(ctx, snapshotTime, dbSandboxes, active)
	}
}

// sandboxDirInfo is one sandbox's on-disk footprint: every dir found for its
// UUID and the newest mtime across them.
type sandboxDirInfo struct {
	mtime time.Time
	paths []string
}

// detectDiskOrphans implements Drift 6: it logs the per-sandbox dirs with no
// live row and, when DiskReclaimEnabled, quarantine-moves them (bounded by
// DiskDeleteBudget) and sweeps expired quarantine. Fail-closed: without a DB
// keep-set it does nothing.
func (r *Reconciler) detectDiskOrphans(ctx context.Context, snapshotTime time.Time, dbSandboxes map[string]db.ListSandboxesByHostRow, active map[string]bool) {
	log := r.mgr.log.With().Str("component", "reconciler").Str("pass", "disk_scan").Logger()

	if r.cfg.DB == nil || r.cfg.HostID == "" || dbSandboxes == nil {
		log.Debug().Msg("disk scan skipped — no DB keep-set (fail-closed)")
		return
	}

	// Source D: per-sandbox dirs. A name that parses as a UUID excludes the
	// template mount target, the build tree, and build-* VMs by construction.
	onDisk := scanSandboxDirs(r.mgr.cfg.RunDir, r.mgr.cfg.SnapshotDir)

	cutoff := snapshotTime.Add(-r.cfg.DiskGracePeriod)
	qctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	recent, err := r.cfg.DB.ListRecentlyDestroyedSandboxIDsByHost(qctx, db.ListRecentlyDestroyedSandboxIDsByHostParams{
		HostID:         r.cfg.HostID,
		DestroyedAfter: pgtype.Timestamptz{Time: cutoff, Valid: true},
	})
	cancel()
	if err != nil {
		log.Error().Err(err).Msg("disk scan: recently-destroyed query failed — skipping (fail-closed)")
		return
	}
	keep := diskKeepSet(dbSandboxes, recent, active)

	// Protected live sandboxes — used by the collapse guard and the audit log.
	var keptActive, keptPaused int
	for _, row := range dbSandboxes {
		switch row.Sandbox.Status {
		case db.SandboxStatusActive:
			keptActive++
		case db.SandboxStatusPaused:
			keptPaused++
		}
	}
	keptLive := keptActive + keptPaused

	if len(keep) == 0 {
		// An empty keep-set is almost always a query bug, not an empty host;
		// reclamation aborts (detect-only just reports).
		if r.cfg.DiskReclaimEnabled {
			log.Error().Int("on_disk", len(onDisk)).Msg("disk reclaim suppressed: empty keep-set")
			return
		}
		log.Warn().Int("on_disk", len(onDisk)).
			Msg("disk scan: empty keep-set — reporting all on-disk dirs as orphans (verify before enabling reclamation)")
	}

	if r.cfg.DiskReclaimEnabled {
		if r.cfg.DiskTrashRetention <= 0 || r.cfg.DiskDeleteBudget <= 0 {
			log.Error().Dur("retention", r.cfg.DiskTrashRetention).Int("budget", r.cfg.DiskDeleteBudget).
				Msg("disk reclaim suppressed: retention and budget must be > 0")
			return
		}
		// keep-set and tripwire both read dbSandboxes, so a query returning too
		// few live rows evades both; a sharp drop vs the prior pass is the
		// independent signal. Keep the baseline so a sustained drop stays suppressed.
		if keepSetCollapsed(r.prevKeptLive, keptLive) {
			log.Error().Int("kept_live", keptLive).Int("prev_kept_live", r.prevKeptLive).
				Msg("disk reclaim suppressed: live keep-set collapsed since last pass")
			return
		}
		r.prevKeptLive = keptLive
		// Sweep only after the keep-set is validated, so a fail-closed pass does
		// nothing destructive. Registered before the empty-disk return below so a
		// drained host (dirs already quarantined, only .trash left) still sweeps.
		defer r.sweepTrash(snapshotTime)
	}

	if len(onDisk) == 0 {
		return
	}

	orphans := selectOrphanDirs(onDisk, keep, cutoff)
	if len(orphans) == 0 {
		log.Info().Int("on_disk", len(onDisk)).Msg("disk scan: no orphan dirs")
		return
	}

	var dirCount int
	var bytes int64
	for _, id := range orphans {
		info := onDisk[id]
		dirCount += len(info.paths)
		bytes += dirSize(ctx, info.paths)
	}

	sample := orphans
	if len(sample) > 20 {
		sample = sample[:20]
	}
	log.Warn().
		Int("orphan_sandboxes", len(orphans)).
		Int("orphan_dirs", dirCount).
		Int64("orphan_bytes", bytes).
		Int("kept_total", len(keep)).
		Int("kept_active", keptActive).
		Int("kept_paused", keptPaused).
		Strs("sample", sample).
		Bool("reclaim", r.cfg.DiskReclaimEnabled).
		Msg("disk scan: orphan per-sandbox dirs detected")

	if r.cfg.DiskReclaimEnabled {
		r.reclaimDiskOrphans(ctx, snapshotTime, orphans, onDisk, dbSandboxes)
	}
}

// reclaimDiskOrphans quarantine-moves orphan dirs to <root>/.trash/<date>/<uuid>
// (reversible), bounded by DiskDeleteBudget. Space is freed later by sweepTrash
// once the retention soak elapses. The caller guarantees a non-empty keep-set.
func (r *Reconciler) reclaimDiskOrphans(ctx context.Context, snapshotTime time.Time, orphans []string, onDisk map[string]sandboxDirInfo, dbSandboxes map[string]db.ListSandboxesByHostRow) {
	log := r.mgr.log.With().Str("component", "reconciler").Str("pass", "disk_reclaim").Logger()
	date := snapshotTime.UTC().Format("2006-01-02")

	var moved, dirCount int
	var bytes int64
	for _, id := range orphans {
		// Tripwire: dbSandboxes is non-destroyed rows only, so a hit means a live
		// sandbox slipped past the keep-set — alarm and skip, never move it.
		if _, live := dbSandboxes[id]; live {
			log.Error().Str("vm_id", id).Msg("disk reclaim: refusing to quarantine a live sandbox dir (keep-set regression)")
			continue
		}
		if moved >= r.cfg.DiskDeleteBudget {
			log.Warn().Int("budget", r.cfg.DiskDeleteBudget).Int("deferred", len(orphans)-moved).
				Msg("disk reclaim: budget reached, deferring rest to next pass")
			break
		}
		info := onDisk[id]
		sz := dirSize(ctx, info.paths)
		// Re-check right before the move: dirSize can run long, and a cancelled
		// pass (runTimeout/shutdown) must stop before mutating disk.
		if ctx.Err() != nil {
			return
		}
		any := false
		for _, p := range info.paths {
			if err := quarantineDir(p, date); err != nil {
				log.Error().Err(err).Str("path", p).Msg("disk reclaim: quarantine failed")
				continue
			}
			dirCount++
			any = true
		}
		if any {
			moved++
			bytes += sz
		}
	}
	if moved > 0 {
		log.Warn().Int("quarantined_sandboxes", moved).Int("quarantined_dirs", dirCount).Int64("bytes", bytes).
			Msg("disk reclaim: orphan dirs quarantined to .trash")
	}
}

// quarantineDir moves a per-sandbox dir (<root>/<uuid>) to
// <root>/.trash/<date>/<uuid>. The dir name must parse as a UUID (so a stray
// path can't be moved) and the move stays within the same root (same
// filesystem → atomic rename).
func quarantineDir(path, date string) error {
	root := filepath.Dir(path)
	name := filepath.Base(path)
	if _, err := uuid.Parse(name); err != nil {
		return fmt.Errorf("refusing to quarantine non-uuid dir %q", name)
	}
	trashDir := filepath.Join(root, trashDirName, date)
	if err := os.MkdirAll(trashDir, 0o755); err != nil {
		return fmt.Errorf("mkdir trash: %w", err)
	}
	return os.Rename(path, filepath.Join(trashDir, name))
}

// sweepTrash permanently removes quarantine buckets soaked past
// DiskTrashRetention. Age is the bucket's mtime, not its date label, so a bucket
// always soaks at least the full retention (never the rounded-down midnight).
func (r *Reconciler) sweepTrash(now time.Time) {
	log := r.mgr.log.With().Str("component", "reconciler").Str("pass", "trash_sweep").Logger()
	cutoff := now.Add(-r.cfg.DiskTrashRetention)
	for _, root := range []string{r.mgr.cfg.RunDir, r.mgr.cfg.SnapshotDir} {
		if root == "" {
			continue
		}
		trash := filepath.Join(root, trashDirName)
		entries, err := os.ReadDir(trash)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			info, ierr := e.Info()
			if ierr != nil || !info.ModTime().Before(cutoff) {
				continue
			}
			p := filepath.Join(trash, e.Name())
			if err := os.RemoveAll(p); err != nil {
				log.Warn().Err(err).Str("path", p).Msg("trash sweep: remove failed")
			} else {
				log.Info().Str("path", p).Msg("trash sweep: removed expired quarantine")
			}
		}
	}
}

// diskKeepSet is every sandbox UUID whose on-disk dirs must NOT be reclaimed:
// non-destroyed DB rows, rows destroyed within grace, and active systemd units.
// Failed rows are kept too — a failed sandbox retains billed disk (storage
// interval open until delete), so it is reclaimed only once destroyed.
func diskKeepSet(dbSandboxes map[string]db.ListSandboxesByHostRow, recent []uuid.UUID, active map[string]bool) map[string]struct{} {
	keep := make(map[string]struct{}, len(dbSandboxes)+len(recent)+len(active))
	for id := range dbSandboxes {
		keep[id] = struct{}{}
	}
	for _, id := range recent {
		keep[id.String()] = struct{}{}
	}
	for id := range active {
		keep[id] = struct{}{}
	}
	return keep
}

// keepSetCollapsed reports whether the protected live-sandbox count dropped by
// more than half between disk passes — a sign the keep-set query regressed. A
// prev of < 1 (no prior pass, or an already-drained host) never trips.
func keepSetCollapsed(prev, cur int) bool {
	return prev > 0 && cur*2 < prev
}

// selectOrphanDirs returns the sandbox UUIDs whose on-disk dirs have no live or
// within-grace row AND whose newest mtime is older than cutoff. The mtime age
// grace keeps an in-flight create — whose rundir exists before its DB INSERT
// commits, so it has no visible row yet — from being flagged as an orphan.
// Pure: no DB or filesystem access.
func selectOrphanDirs(onDisk map[string]sandboxDirInfo, keep map[string]struct{}, cutoff time.Time) []string {
	var orphans []string
	for id, info := range onDisk {
		if _, live := keep[id]; live {
			continue
		}
		if info.mtime.After(cutoff) {
			continue
		}
		orphans = append(orphans, id)
	}
	return orphans
}

// scanSandboxDirs enumerates direct children of each root whose name parses as
// a UUID — the per-sandbox dirs. Non-UUID entries (template, templates,
// build-*) and unreadable roots/entries are skipped. A sandbox's dirs across
// roots are merged, keeping the newest mtime.
func scanSandboxDirs(roots ...string) map[string]sandboxDirInfo {
	out := make(map[string]sandboxDirInfo)
	for _, root := range roots {
		if root == "" {
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			id, err := uuid.Parse(e.Name())
			if err != nil {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			key := id.String()
			cur := out[key]
			cur.paths = append(cur.paths, filepath.Join(root, e.Name()))
			if fi.ModTime().After(cur.mtime) {
				cur.mtime = fi.ModTime()
			}
			out[key] = cur
		}
	}
	return out
}

// dirSize sums the size of every regular file under the given paths. Errors are
// swallowed so one unreadable entry can't abort the measurement, and the walk
// stops early if ctx is cancelled so the pass stays within its deadline.
func dirSize(ctx context.Context, paths []string) int64 {
	var total int64
	for _, p := range paths {
		_ = filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil || d.IsDir() {
				return nil
			}
			fi, e := d.Info()
			if e != nil {
				return nil
			}
			// Count allocated blocks (du-style), not apparent length: overlay
			// images are sparse (createOverlay truncates to the base size), so
			// fi.Size() would massively overstate the disk a delete frees.
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				total += st.Blocks * 512 // st_blocks is in 512-byte units
			}
			return nil
		})
	}
	return total
}

// legacyUnitWeight is a legacy firecracker@ unit's default CPU/IO weight;
// the direct-spawn service carries it per live direct VM (see below).
const legacyUnitWeight = 100

// maxUnitWeight is cgroup v2's cpu.weight/io.weight ceiling. Capping here past
// ~100 live direct VMs only under-weights direct VMs — the safe direction,
// never starving legacy.
const maxUnitWeight = 10000

// adjustDirectSpawnWeight keeps the direct-spawn service's scheduling weight
// proportional to the number of direct VMs that actually compete (populated
// cgroups in the running set). At legacyUnitWeight per live VM, each direct
// VM weighs exactly one legacy peer, so the two populations share the slice
// fairly at ANY mix — the property a static weight cannot hold, since it is
// correct only at one population size (and over-weights direct VMs, starving
// legacy under contention, precisely when direct VMs are few — early
// migration). Runs each pass; set-property only fires when the count changed.
func (r *Reconciler) adjustDirectSpawnWeight(ctx context.Context, active map[string]bool, supervisionOf map[string]Supervision) {
	if r.mgr.cgroups == nil {
		return // not managing cgroup VMs — the service holds only the idle keeper
	}
	live := 0
	for id := range active {
		if supervisionOf[id] == SupervisionCgroup {
			live++
		}
	}
	weight := live * legacyUnitWeight
	if weight < legacyUnitWeight {
		weight = legacyUnitWeight // an empty population still weighs one idle peer
	}
	if weight > maxUnitWeight {
		weight = maxUnitWeight
	}
	if weight == r.lastVmsWeight {
		return
	}
	if err := setUnitWeight(ctx, vmsUnitName, weight); err != nil {
		// Left unrecorded so the next pass retries; the boot-time unit file
		// value holds until it succeeds.
		r.mgr.log.Warn().Err(err).Int("weight", weight).Int("live_direct", live).
			Msg("reconciler: failed to set direct-spawn service weight")
		return
	}
	r.mgr.log.Info().Int("weight", weight).Int("live_direct", live).
		Msg("reconciler: adjusted direct-spawn service scheduling weight")
	r.lastVmsWeight = weight
}

// gracePeriodElapsed records the first-seen timestamp for a drifted ID and
// returns true once the configured grace period has passed. Used to absorb
// transient states (e.g. VMD just started a VM and systemd hasn't fully
// registered it yet).
func (r *Reconciler) gracePeriodElapsed(key string, now time.Time) bool {
	return r.graceElapsed(key, now, r.cfg.GracePeriod)
}

// graceElapsed is gracePeriodElapsed with an explicit window, for drifts whose
// safe wait differs from the default (see UnverifiedOrphanGrace).
func (r *Reconciler) graceElapsed(key string, now time.Time, window time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	firstSeen, ok := r.driftSeen[key]
	if !ok {
		r.driftSeen[key] = now
		return false
	}
	return now.Sub(firstSeen) >= window
}

// statPauseArtifact classifies a pause artifact for the missing-snapshot rule:
// present (healed, or a new generation at the same path), confirmedMissing
// (the only verdict that may flip the row), or neither — EACCES, I/O errors
// and a spent ctx say nothing about the file, and marking a sandbox failed on
// a non-answer would fail healthy generations.
var statPauseArtifact = func(path string) (present, confirmedMissing bool) {
	_, err := os.Stat(path)
	if err == nil {
		return true, false
	}
	return false, errors.Is(err, os.ErrNotExist)
}

// clearDrift removes a drift marker once the VM returns to a healthy state.
func (r *Reconciler) clearDrift(key string) {
	r.mu.Lock()
	delete(r.driftSeen, key)
	r.mu.Unlock()
}

// dbQueryTimeout is the per-query deadline for short reconciler writes
// and single-row reads. Kept below runTimeout so a single slow query
// can't consume the whole run's budget.
const dbQueryTimeout = 5 * time.Second

// markFailedInDB writes status=failed for the given sandbox ID,
// version-guarded on the pass-start observation: the row flips only if
// untouched since (every lifecycle transition bumps updated_at), so a stale
// snapshot cannot overwrite a concurrent relaunch's row — even one that is
// 'active' again. The underlying query's CTE also closes any open
// sandbox_active_interval row atomically, so a crash/timeout between the
// two writes is unreachable. No-op if the DB is not configured.
// markFailedInDB flips a sandbox row to failed, reporting whether it moved.
// A refusal means a resume took the row since the pass snapshot, so callers
// must not audit the transition or clear their drift on it.
// unitFullyDownProbe is Drift 1's terminal-unit oracle; a var for tests.
var unitFullyDownProbe = unitFullyDown

func (r *Reconciler) markFailedInDB(ctx context.Context, vmID string, observed db.SandboxStatus) bool {
	if r.cfg.DB == nil {
		return true
	}
	id, err := uuid.Parse(vmID)
	if err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: invalid vm_id for DB mark-failed")
		return false
	}
	qctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	flipped, err := r.cfg.DB.MarkSandboxFailed(qctx, db.MarkSandboxFailedParams{ID: id, ObservedStatus: observed})
	if err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to mark sandbox failed in DB")
		return false
	}
	if flipped == 0 {
		r.mgr.log.Info().Str("vm_id", vmID).Msg("reconciler: sandbox no longer active; mark-failed skipped")
	}
	return flipped > 0
}

// writeAudit appends a row to the reconciler_log table. No-op if the DB
// is not configured. Rule C8: every reconciler action produces an audit
// record.
func (r *Reconciler) writeAudit(ctx context.Context, vmID, action, reason, driftKind string) {
	if r.cfg.DB == nil {
		return
	}
	var sandboxID pgtype.UUID
	if id, err := uuid.Parse(vmID); err == nil {
		sandboxID = pgtype.UUID{Bytes: id, Valid: true}
	}
	kind := driftKind
	qctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	if err := r.cfg.DB.InsertReconcilerLog(qctx, db.InsertReconcilerLogParams{
		HostID:    r.cfg.HostID,
		SandboxID: sandboxID,
		Action:    action,
		Reason:    reason,
		DriftKind: &kind,
	}); err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to write audit log")
	}
}

// consumeAutoFailBudget enforces crash safety rule C6: bounded-blast-radius
// auto-failure. Returns false (and does not consume the budget) when the
// reconciler has already marked MaxAutoFailPerHour VMs stale in the last
// rolling hour. Mass drift is almost always a reconciler bug, not 50
// simultaneous VM crashes.
func (r *Reconciler) consumeAutoFailBudget(vmID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Hour)
	kept := r.autoFailLog[:0]
	for _, t := range r.autoFailLog {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.autoFailLog = kept

	if len(r.autoFailLog) >= r.cfg.MaxAutoFailPerHour {
		r.mgr.log.Error().
			Str("component", "reconciler").
			Str("vm_id", vmID).
			Int("budget", r.cfg.MaxAutoFailPerHour).
			Msg("auto-fail budget exhausted — halting destructive actions until budget resets")
		return false
	}

	r.autoFailLog = append(r.autoFailLog, now)
	return true
}

// fcProbeShell probes the Firecracker API on sock. Only a healthy API
// affirmatively answering counts either way: empty reports an explicit
// "Not started" (a shell with no microVM), and a non-nil error means the
// probe produced no evidence at all — callers must neither act on it nor
// clear the drift, so a wedged or slow API can only delay this rule, never
// steer it.
func fcProbeShell(ctx context.Context, sock string) (empty bool, err error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	state, err := VMState(probeCtx, sock)
	if err != nil {
		return false, err
	}
	return state == fcmodels.InstanceInfoStateNotStarted, nil
}

// refundAutoFailSlot returns the most recently consumed auto-fail slot,
// for when the reserved destructive action did not happen (a failed unit
// stop): the budget bounds performed actions, so transient failures must
// not exhaust it. Drift rules run sequentially in the single reconcile
// pass, so the newest entry is the caller's own reservation.
func (r *Reconciler) refundAutoFailSlot() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.autoFailLog); n > 0 {
		r.autoFailLog = r.autoFailLog[:n-1]
	}
}

// finalizeErrorReap records the outcome of a Drift 8 release. A failed delete
// leaves the record, its instance and its network slot held, so the marker
// survives rather than retiring on a cleanup that did not happen.
//
// That also keeps the dead-unit half's retry on the very next pass, its grace
// already elapsed. The active half gets no such benefit: its marker is retired
// when the unit leaves the active set, so its retry waits out one more grace.
func (r *Reconciler) finalizeErrorReap(ctx context.Context, vmID, marker, action, reason, driftKind string, staleErr error) {
	if staleErr != nil {
		r.writeAudit(ctx, vmID, "stale_cleanup_failed", reason+"; record not deleted", driftKind)
		return
	}
	r.writeAudit(ctx, vmID, action, reason, driftKind)
	r.clearDrift(marker)
}

// markStale deletes the stale BoltDB entry and drops the VM from the
// in-memory map. The VM is already gone in reality; this just cleans up
// VMD's cache.
//
// A non-nil error means nothing was cleaned up. Rules that stop the unit
// before calling this must not report success on one: stopping the unit
// retires the very condition their next pass matches on, so the record is
// left for the startup reattach sweep rather than another pass.
func (r *Reconciler) markStale(vmID string) error {
	// Capture the namespace before deleting the record: a VM whose teardown
	// didn't run (e.g. a vmd timeout mid-DELETE) would otherwise leak its slot.
	var namespace string
	var supervision Supervision
	if rec, err := r.mgr.state.Get(vmID); err == nil && rec != nil {
		namespace = rec.Namespace
		supervision = rec.Supervision
	}
	// The release chokepoint refuses unknown modes: every reconciler rule
	// proves death via the unit and cgroup oracles, and a mode this binary
	// predates may supervise a live FC neither can see. Only a deliberate
	// destroy may release such a record.
	if !knownSupervision(supervision) {
		r.mgr.log.Error().Str("vm_id", vmID).Str("supervision", string(supervision)).
			Msg("reconciler: unknown supervision mode — refusing release")
		return fmt.Errorf("unknown supervision mode %q for vm %s: refusing release", supervision, vmID)
	}
	// Remove a direct-spawned VM's cgroup dir too, or an emptied group lingers
	// as an unbounded fleet-size artifact.
	if cgroupSupervised(supervision) && r.mgr.cgroups != nil {
		// markStale has no ctx; the rmdir must complete (a lingering empty group
		// is an unbounded artifact), so give it a background context.
		_ = r.mgr.cgroups.removeVMCgroup(context.Background(), vmID)
	}

	// Delete from BoltDB first. Deleting from the map before BoltDB would
	// cause ReattachAll to resurrect the stale record on next restart, so a
	// failure here abandons the whole cleanup rather than half-applying it.
	if err := r.mgr.state.Delete(vmID); err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to delete stale state")
		return err
	}

	r.mgr.mu.Lock()
	delete(r.mgr.vms, vmID)
	r.mgr.mu.Unlock()

	// Free the slot too. netMgr is always set in prod; the nil check is defensive.
	if r.mgr.netMgr != nil {
		r.mgr.netMgr.CleanupVMOrNamespace(vmID, namespace)
	}

	r.mu.Lock()
	delete(r.driftSeen, vmID)
	r.mu.Unlock()

	r.mgr.log.Warn().Str("component", "reconciler").Str("vm_id", vmID).
		Str("action", "mark_stale").Msg("reconciler: cleaned up stale VM record")
	return nil
}

// reapDeadActiveVMs is Drift 1's body: DB says active, systemd says the unit
// is gone. Extracted so the stale-Running regression stays testable — the
// rule must reap on unit evidence even while the in-memory record still
// claims Running.
// failEmptyShells is Drift 1b, extracted for direct rule tests.
func (r *Reconciler) failEmptyShells(ctx context.Context, log zerolog.Logger, dbSandboxes map[string]db.ListSandboxesByHostRow, active map[string]bool, supervisionOf map[string]Supervision, now time.Time) {
	// Drift 1b: the unit is active but the Firecracker inside is an empty
	// shell holding no microVM (see fcReportsEmptyShell) — e.g. the unit
	// was restarted outside vmd, which destroys the guest; the replacement
	// only becomes a VM again through vmd's own restore path. A mid-launch
	// VM is briefly "Not started" between unit start and boot; the grace
	// period (drift must persist across passes) plus the op-lock check and
	// a re-probe under the lock filter that window.
	if dbSandboxes != nil {
		// Probe candidates concurrently under a stage budget: a wedged API
		// burns its full timeout, and sequential probing would let a few
		// wedged sockets starve every rule after this one. Budget-cutoff
		// probes yield errors (non-evidence) and re-examine next pass.
		var candidates []string
		for id, sb := range dbSandboxes {
			if sb.Sandbox.Status != db.SandboxStatusActive || !active[id] {
				r.clearDrift("fcempty:" + id)
				continue
			}
			candidates = append(candidates, id)
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 6*time.Second)
		type probeResult struct {
			empty bool
			err   error
		}
		probes := make(map[string]probeResult, len(candidates))
		var probeMu sync.Mutex
		var probeWG sync.WaitGroup
		probeSem := make(chan struct{}, 16)
		for _, id := range candidates {
			probeWG.Add(1)
			go func(id string) {
				defer probeWG.Done()
				probeSem <- struct{}{}
				defer func() { <-probeSem }()
				empty, perr := fcProbeShell(probeCtx, filepath.Join(r.mgr.cfg.RunDir, id, "firecracker.sock"))
				probeMu.Lock()
				probes[id] = probeResult{empty: empty, err: perr}
				probeMu.Unlock()
			}(id)
		}
		probeWG.Wait()
		probeCancel()

		for _, id := range candidates {
			res := probes[id]
			if res.err != nil {
				continue // no evidence either way; drift state untouched
			}
			if !res.empty {
				r.clearDrift("fcempty:" + id)
				continue
			}
			if !r.gracePeriodElapsed("fcempty:"+id, now) {
				continue
			}
			unlockOp, ok := r.mgr.tryLockVMOp(id)
			if !ok {
				continue
			}
			// Re-probe under the lock: a restore may have loaded a microVM
			// into this process since the pass began.
			empty, perr := fcProbeShell(ctx, filepath.Join(r.mgr.cfg.RunDir, id, "firecracker.sock"))
			if perr != nil || !empty {
				unlockOp()
				if perr == nil {
					r.clearDrift("fcempty:" + id)
				}
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				unlockOp()
				r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "fc_empty_shell")
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "fc_empty_shell").
				Msg("unit active but Firecracker holds no microVM — stopping the shell and marking failed")
			err := r.stopVM(ctx, id, supervisionOf[id])
			if err != nil {
				unlockOp()
				// Leave the row untouched (a failed row behind a live
				// unit would strand it). Refund the budget slot only when
				// the stop provably never happened; an accepted-but-
				// unconfirmed job may still terminate the unit, and
				// refunding those would let slow stops evade the budget.
				if errors.Is(err, errStopNotEnqueued) {
					r.refundAutoFailSlot()
					r.writeAudit(ctx, id, "stop_failed", "empty-shell stop not enqueued; slot refunded, retrying next pass", "fc_empty_shell")
				} else {
					r.writeAudit(ctx, id, "stop_failed", "empty-shell stop unconfirmed; slot retained, retrying next pass", "fc_empty_shell")
				}
				log.Error().Err(err).Str("vm_id", id).Msg("failed to stop empty-shell VM")
				continue
			}
			// The row flip and release need the mode-aware terminal proof
			// (vmFullyDown); not yet down → retry next pass.
			if !r.vmFullyDown(ctx, id, supervisionOf[id]) {
				unlockOp()
				r.writeAudit(ctx, id, "stop_failed", "empty-shell stop not terminal; retrying next pass", "fc_empty_shell")
				continue
			}
			unlockOp()
			// The stop is committed; the DB transition must not be lost to
			// the pass deadline expiring mid-rule (a stranded active row
			// behind a dead unit costs another grace+budget cycle via the
			// dead-VM rule). Detach from the pass context, bounded.
			persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			flipped := r.markFailedInDB(persistCtx, id, db.SandboxStatusActive)
			r.markStale(id)
			if flipped {
				r.writeAudit(persistCtx, id, "mark_failed", "empty Firecracker shell while DB said active", "fc_empty_shell")
			}
			persistCancel()
		}
	}
}

// reapUnverifiedOrphans is Drift 7b, extracted for direct rule tests.
func (r *Reconciler) reapUnverifiedOrphans(ctx context.Context, log zerolog.Logger, dbSandboxes map[string]db.ListSandboxesByHostRow, active map[string]bool, supervisionOf map[string]Supervision, now time.Time) {
	// Drift 7b: a crash-window orphan nobody came back for. A restore that
	// died between its optimistic persist and the verified one leaves a
	// Running-but-unverified record behind a live unit; the control plane
	// reverts its row to paused, and Drift 7 then defers forever because the
	// record says Running. Unverified is what makes that deference wrong:
	// readiness was never proven, so Running is a claim, not evidence.
	//
	// Runs on UnverifiedOrphanGrace, not the default — see that field for why
	// this rule must lose the race with adoption. The sandbox row and its
	// snapshot are untouched: only the orphaned process and its slot go, so a
	// later resume still restores cleanly.
	if dbSandboxes != nil {
		for id := range active {
			sb, known := dbSandboxes[id]
			if !known || sb.Sandbox.Status != db.SandboxStatusPaused || !r.mgr.instanceUnverifiedRunning(id) {
				r.clearDrift("unverifiedorphan:" + id)
				continue
			}
			if !r.graceElapsed("unverifiedorphan:"+id, now, r.cfg.UnverifiedOrphanGrace) {
				continue
			}
			// Same discipline as Drift 7: lock before spending budget, then
			// re-check under it — an adoption completing mid-pass clears the
			// marker, and stopping then would kill a healed VM.
			unlockOp, ok := r.mgr.tryLockVMOp(id)
			if !ok {
				continue
			}
			if !r.mgr.instanceUnverifiedRunning(id) {
				unlockOp()
				r.clearDrift("unverifiedorphan:" + id)
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				unlockOp()
				r.writeAudit(ctx, id, "budget_exhausted", "unverified_orphan_stop suppressed by rate limit", "unverified_orphan_abandoned")
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "unverified_orphan_abandoned").
				Msg("abandoned crash-window VM — stopping")
			err := r.stopVM(ctx, id, supervisionOf[id])
			if err != nil {
				unlockOp()
				log.Error().Err(err).Str("vm_id", id).Msg("failed to stop abandoned crash-window VM")
				continue
			}
			// Release needs the mode-aware terminal proof (vmFullyDown);
			// not yet down → retry next pass.
			if !r.vmFullyDown(ctx, id, supervisionOf[id]) {
				unlockOp()
				continue
			}
			removeUnitDropIn(id)
			staleErr := r.markStale(id)
			unlockOp()
			if staleErr != nil {
				// The unit is stopped but the record, its map entry and its slot
				// survive, and no rule matches an inactive unit. Report the
				// partial cleanup rather than an orphan_stop that did not happen.
				r.writeAudit(ctx, id, "stale_cleanup_failed", "unit stopped but record not deleted", "unverified_orphan_abandoned")
				continue
			}
			r.writeAudit(ctx, id, "orphan_stop", "crash-window VM never adopted", "unverified_orphan_abandoned")
			r.clearDrift("unverifiedorphan:" + id)
		}
	}
}

// demotePausedCgroupRecords is the rollback drain. A paused cgroup sandbox
// has no live process, so its supervision value only matters at the next
// launch — but a cgroup record always relaunches cgroup, and sandboxes never
// expire, so with direct spawn disarmed the fleet would otherwise hold
// cgroup records (and block the downgrade guard) forever. With the flag off,
// rewrite paused records to unit supervision — under the vm-op lock, re-read,
// and only with the group conclusively empty — and remove the leftover group
// dir. Re-arming simply re-promotes on the next launch, so a transient
// flag-off loses nothing. Non-destructive: no process is touched and no
// auto-fail budget is spent.
func (r *Reconciler) demotePausedCgroupRecords(ctx context.Context, log zerolog.Logger) {
	recs, err := r.mgr.state.All()
	if err != nil {
		log.Error().Err(err).Msg("demotion scan: cannot read state store")
		return
	}
	for _, rec := range recs {
		if ctx.Err() != nil {
			return
		}
		if rec.Status != StatusPaused || !cgroupSupervised(rec.Supervision) || rec.Unverified {
			continue
		}
		id := rec.ID
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			continue // a resume/destroy is in flight; next pass
		}
		// Re-read under the lock: a resume may have relaunched (Running) or a
		// destroy deleted the record since the scan.
		cur, gerr := r.mgr.state.Get(id)
		if gerr != nil || cur == nil || cur.Status != StatusPaused || !cgroupSupervised(cur.Supervision) || cur.Unverified {
			unlockOp()
			continue
		}
		// Only a conclusively empty group proves no process depends on the
		// cgroup mode; unreadable or populated defers to the drift rules.
		if !r.mgr.cgroupDefinitelyDead(id) {
			unlockOp()
			continue
		}
		// A tracked instance that is not paused vetoes the demotion.
		r.mgr.mu.RLock()
		inst := r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if inst != nil {
			inst.mu.RLock()
			stillPaused := inst.Status == StatusPaused
			inst.mu.RUnlock()
			if !stillPaused {
				unlockOp()
				continue
			}
		}
		// Disk first, then memory, all under the vm-op lock. Reattach
		// publishes instances lock-free, so one may appear between the read
		// above and the write: the memory pass below catches an instance
		// published before it, and reattach's own post-publish re-read of
		// the durable mode catches one published after — between them every
		// interleaving converges.
		cur.Supervision = SupervisionUnit
		if wrote, perr := r.mgr.state.PutIfPresent(*cur); perr != nil || !wrote {
			unlockOp()
			continue
		}
		r.mgr.mu.RLock()
		inst = r.mgr.vms[id]
		r.mgr.mu.RUnlock()
		if inst != nil {
			inst.mu.Lock()
			if inst.Status == StatusPaused {
				inst.Supervision = SupervisionUnit
			}
			inst.mu.Unlock()
		}
		// The empty group dir would otherwise linger and keep counting
		// against the drain guard until restart.
		_ = r.mgr.cgroups.removeVMCgroup(context.WithoutCancel(ctx), id)
		unlockOp()
		log.Info().Str("vm_id", id).Msg("demoted paused cgroup record to unit supervision for rollback drain")
		r.writeAudit(ctx, id, "supervision_demoted", "paused cgroup record demoted for rollback drain", "cgroup_drain_demotion")
	}
}

func (r *Reconciler) reapDeadActiveVMs(ctx context.Context, log zerolog.Logger, dbSandboxes map[string]db.ListSandboxesByHostRow, active map[string]bool, errorRecord func(string) bool, now time.Time) {
	for id, sb := range dbSandboxes {
		if sb.Sandbox.Status != db.SandboxStatusActive {
			continue
		}
		if active[id] {
			r.clearDrift(id)
			continue
		}
		// Error records are Drift 8's: its halves gate every record
		// release on the terminal unit state, which this branch does not
		// probe — a deactivating unit is absent from the active snapshot
		// while its process may live on.
		if errorRecord(id) {
			continue
		}
		if !r.gracePeriodElapsed(id, now) {
			continue
		}
		// Lock before spending budget, then re-probe the UNIT under it —
		// never instanceRunning: nothing updates the in-memory record when
		// firecracker dies out from under vmd, so a stale Running instance
		// is the very state this rule cleans up. A resume that relaunched
		// mid-pass owns a live unit again, which this probe sees; an
		// inconclusive probe defers to the next pass.
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			continue
		}
		if !unitFullyDownProbe(ctx, systemdUnitName(id)) {
			// Pass ctx, not a background budget: N wedged probes must
			// exhaust the pass deadline, not stack past it — an expired
			// ctx fails the probe and defers, which is the safe verdict.
			unlockOp()
			continue
		}
		if !r.consumeAutoFailBudget(id) {
			unlockOp()
			r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "db_active_systemd_missing")
			continue
		}
		log.Warn().Str("vm_id", id).Str("drift", "db_active_systemd_missing").
			Msg("DB says active but VM is dead — marking failed")
		flipped := r.markFailed(ctx, id, db.SandboxStatusActive)
		staleErr := r.markStale(id)
		unlockOp()
		if staleErr != nil {
			// The row is failed but the record and slot are still held, and
			// no rule rematches that shape (this one needs an active row).
			// The release retry is record-keyed and lives outside this
			// rule; until then the leak is bounded by the next reattach —
			// but it must be recorded, not silent.
			r.writeAudit(ctx, id, "stale_cleanup_failed", "row failed but record not deleted", "db_active_systemd_missing")
		}
		if !flipped {
			continue
		}
		r.writeAudit(ctx, id, "mark_failed", "VM dead while DB said active", "db_active_systemd_missing")
	}
}

// failMissingSnapshots is Drift 4's body: a paused row whose snapshot artifact
// is provably gone. Extracted for the same reason as reapDeadActiveVMs — the
// lock-window race (a new pause writing the artifact while this rule waits on
// the lifecycle lock) is only testable with the pass data injectable.
func (r *Reconciler) failMissingSnapshots(ctx context.Context, log zerolog.Logger, dbSandboxes map[string]db.ListSandboxesByHostRow, now time.Time) {
	for id, sb := range dbSandboxes {
		if sb.Sandbox.Status != db.SandboxStatusPaused || !sb.Sandbox.SnapshotID.Valid {
			continue
		}
		// snapshot_path is joined in by ListSandboxesByHost, so this
		// is a cheap struct field read instead of a per-row DB call.
		// Skip when the snapshot row has been deleted (rare race).
		if sb.SnapshotPath == nil || *sb.SnapshotPath == "" {
			continue
		}
		snapPath := *sb.SnapshotPath
		if _, statErr := os.Stat(snapPath); statErr == nil {
			r.clearDrift("paused:" + id)
			continue
		}
		if !r.gracePeriodElapsed("paused:"+id, now) {
			continue
		}
		// Re-stat under the lifecycle lock before spending budget: a
		// resume + re-pause since the pass snapshot writes NEW artifacts
		// at this same path before the row returns to paused, so the row
		// alone cannot tell the generations apart — the file can. The
		// lock excludes an in-flight transition.
		unlockOp, ok := r.mgr.tryLockVMOp(id)
		if !ok {
			continue
		}
		present, confirmedMissing := statPauseArtifact(snapPath)
		if present {
			unlockOp()
			r.clearDrift("paused:" + id)
			continue
		}
		if !confirmedMissing {
			unlockOp()
			continue
		}
		if !r.consumeAutoFailBudget(id) {
			unlockOp()
			r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "paused_snapshot_missing")
			continue
		}
		log.Warn().Str("vm_id", id).Str("snapshot_path", snapPath).
			Str("drift", "paused_snapshot_missing").
			Msg("paused sandbox snapshot file missing — marking failed")
		// Paused is the state this rule matched on, so that is what the
		// flip asserts. A row that resumed since the pass snapshot refuses
		// it, and keeping the marker lets the next pass re-evaluate rather
		// than retiring a transition that never happened.
		flipped := r.markFailed(ctx, id, db.SandboxStatusPaused)
		unlockOp()
		if !flipped {
			continue
		}
		r.writeAudit(ctx, id, "mark_failed", "snapshot file missing", "paused_snapshot_missing")
		r.clearDrift("paused:" + id)
	}
}
