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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
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
}

// NewReconciler creates a reconciler bound to a Manager.
func NewReconciler(mgr *Manager, cfg ReconcilerConfig) *Reconciler {
	return &Reconciler{
		mgr:          mgr,
		cfg:          cfg,
		driftSeen:    make(map[string]time.Time),
		prevKeptLive: -1,
	}
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

	// Source B: active systemd units.
	ids, err := listActiveFirecrackerUnits(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to list systemd units")
		return
	}
	active := make(map[string]bool, len(ids))
	for _, id := range ids {
		if isBuildVM(id) {
			continue
		}
		active[id] = true
	}

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

	// Drift 1: DB says active, systemd/socket says dead.
	// Action: mark sandbox failed in DB + clean up BoltDB + in-memory.
	if dbSandboxes != nil {
		for id, sb := range dbSandboxes {
			if sb.Sandbox.Status != db.SandboxStatusActive {
				continue
			}
			if active[id] {
				r.clearDrift(id)
				continue
			}
			if !r.gracePeriodElapsed(id, now) {
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "db_active_systemd_missing")
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "db_active_systemd_missing").
				Msg("DB says active but VM is dead — marking failed")
			r.markFailedInDB(ctx, id)
			r.markStale(id)
			r.writeAudit(ctx, id, "mark_failed", "VM dead while DB said active", "db_active_systemd_missing")
		}
	}

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
			if err := stopUnit(ctx, systemdUnitName(id)); err != nil {
				log.Error().Err(err).Str("vm_id", id).Msg("failed to stop orphan unit")
				continue
			}
			removeUnitDropIn(id)
			r.markStale(id)
			r.writeAudit(ctx, id, "orphan_stop", reason, kind)
			r.clearDrift("orphan:" + id)
		}
	}

	// Drift 4: DB says paused, snapshot file missing on disk → mark failed.
	if dbSandboxes != nil {
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
			if !r.consumeAutoFailBudget(id) {
				r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "paused_snapshot_missing")
				continue
			}
			log.Warn().Str("vm_id", id).Str("snapshot_path", snapPath).
				Str("drift", "paused_snapshot_missing").
				Msg("paused sandbox snapshot file missing — marking failed")
			r.markFailedInDB(ctx, id)
			r.writeAudit(ctx, id, "mark_failed", "snapshot file missing", "paused_snapshot_missing")
			r.clearDrift("paused:" + id)
		}
	}

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
				if err := stopUnit(ctx, systemdUnitName(id)); err != nil {
					log.Error().Err(err).Str("vm_id", id).Msg("failed to stop orphan unit from BoltDB — leaving for retry")
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

// gracePeriodElapsed records the first-seen timestamp for a drifted ID and
// returns true once the configured grace period has passed. Used to absorb
// transient states (e.g. VMD just started a VM and systemd hasn't fully
// registered it yet).
func (r *Reconciler) gracePeriodElapsed(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	firstSeen, ok := r.driftSeen[key]
	if !ok {
		r.driftSeen[key] = now
		return false
	}
	return now.Sub(firstSeen) >= r.cfg.GracePeriod
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

// markFailedInDB writes status=failed for the given sandbox ID. The
// underlying MarkSandboxFailed query is a CTE that also closes any open
// sandbox_active_interval row atomically, so a crash/timeout between the
// two writes is unreachable. No-op if the DB is not configured.
func (r *Reconciler) markFailedInDB(ctx context.Context, vmID string) {
	if r.cfg.DB == nil {
		return
	}
	id, err := uuid.Parse(vmID)
	if err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: invalid vm_id for DB mark-failed")
		return
	}
	qctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	if err := r.cfg.DB.MarkSandboxFailed(qctx, id); err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to mark sandbox failed in DB")
	}
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

// markStale deletes the stale BoltDB entry and drops the VM from the
// in-memory map. The VM is already gone in reality; this just cleans up
// VMD's cache.
func (r *Reconciler) markStale(vmID string) {
	// Capture the namespace before deleting the record: a VM whose teardown
	// didn't run (e.g. a vmd timeout mid-DELETE) would otherwise leak its slot.
	var namespace string
	if rec, err := r.mgr.state.Get(vmID); err == nil && rec != nil {
		namespace = rec.Namespace
	}

	// Delete from BoltDB first. If this fails, keep the in-memory entry
	// so the state stays consistent — the reconciler will retry on the
	// next run. Deleting from the map before BoltDB would cause
	// ReattachAll to resurrect the stale record on next restart.
	if err := r.mgr.state.Delete(vmID); err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to delete stale state, will retry")
		return
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
}
