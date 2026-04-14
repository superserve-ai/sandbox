package vm

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

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
}

// DefaultReconcilerConfig returns sensible defaults from the design doc.
func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		Interval:           30 * time.Second,
		GracePeriod:        60 * time.Second,
		MaxAutoFailPerHour: 5,
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
}

// NewReconciler creates a reconciler bound to a Manager.
func NewReconciler(mgr *Manager, cfg ReconcilerConfig) *Reconciler {
	return &Reconciler{
		mgr:       mgr,
		cfg:       cfg,
		driftSeen: make(map[string]time.Time),
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

	// Source A: BoltDB records.
	records, err := r.mgr.state.All()
	if err != nil {
		log.Error().Err(err).Msg("failed to read state store")
		return
	}
	bolted := make(map[string]VMRecord, len(records))
	for _, rec := range records {
		bolted[rec.ID] = rec
	}

	// Source B: active systemd units.
	ids, err := listActiveFirecrackerUnits(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to list systemd units")
		return
	}
	active := make(map[string]bool, len(ids))
	for _, id := range ids {
		active[id] = true
	}

	// Source C: DB sandbox rows for this host (optional). A short
	// per-query deadline keeps a slow DB from stalling the whole run.
	var dbSandboxes map[string]db.Sandbox
	if r.cfg.DB != nil && r.cfg.HostID != "" {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		rows, dbErr := r.cfg.DB.ListSandboxesByHost(qctx, r.cfg.HostID)
		cancel()
		if dbErr != nil {
			log.Error().Err(dbErr).Msg("failed to list sandboxes from DB")
		} else {
			dbSandboxes = make(map[string]db.Sandbox, len(rows))
			for _, s := range rows {
				dbSandboxes[s.ID.String()] = s
			}
		}
	}

	now := time.Now()

	// Drift 1: DB says active, systemd/socket says dead.
	// Action: mark sandbox failed in DB + clean up BoltDB + in-memory.
	if dbSandboxes != nil {
		for id, sb := range dbSandboxes {
			if sb.Status != db.SandboxStatusActive {
				continue
			}
			if r.isAlive(ctx, id, bolted) {
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
			if r.isAlive(ctx, id, bolted) {
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

	// Drift 3: systemd has a unit, DB says the sandbox is deleted or has
	// no row at all. This is an orphan — stop the unit + clean up.
	if dbSandboxes != nil {
		for id := range active {
			sb, known := dbSandboxes[id]
			deleted := known && sb.Status == db.SandboxStatusDeleted
			if known && !deleted {
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

	// Drift 4: DB says idle, snapshot file missing on disk → mark failed.
	if dbSandboxes != nil {
		for id, sb := range dbSandboxes {
			if sb.Status != db.SandboxStatusIdle || !sb.SnapshotID.Valid {
				continue
			}
			snap, snapErr := r.getSnapshot(ctx, sb.SnapshotID.Bytes)
			if snapErr != nil {
				continue
			}
			if _, statErr := os.Stat(snap.Path); statErr == nil {
				r.clearDrift("idle:" + id)
				continue
			}
			if !r.gracePeriodElapsed("idle:"+id, now) {
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				r.writeAudit(ctx, id, "budget_exhausted", "mark_failed suppressed by rate limit", "idle_snapshot_missing")
				continue
			}
			log.Warn().Str("vm_id", id).Str("snapshot_path", snap.Path).
				Str("drift", "idle_snapshot_missing").
				Msg("idle sandbox snapshot file missing — marking failed")
			r.markFailedInDB(ctx, id)
			r.writeAudit(ctx, id, "mark_failed", "snapshot file missing", "idle_snapshot_missing")
			r.clearDrift("idle:" + id)
		}
	}

	// Drift 5: BoltDB record exists but DB has no corresponding sandbox
	// row (either never written or soft-deleted). Clean up the BoltDB
	// entry. If the VM is still live, we ALSO need to stop it — leaving
	// a systemd unit running for a sandbox the control plane forgot about
	// is a resource leak and a security risk.
	if dbSandboxes != nil {
		for id, rec := range bolted {
			if _, ok := dbSandboxes[id]; ok {
				continue
			}
			if !r.gracePeriodElapsed("bolt-orphan:"+id, now) {
				continue
			}
			if !r.consumeAutoFailBudget(id) {
				r.writeAudit(ctx, id, "budget_exhausted", "stale_cleanup suppressed by rate limit", "boltdb_present_db_missing")
				continue
			}
			log.Warn().Str("vm_id", id).Str("drift", "boltdb_present_db_missing").
				Msg("BoltDB entry with no DB row — cleaning up")
			// Stop the unit if it's still live so we don't leak a VM.
			if rec.Status == StatusRunning {
				if err := stopUnit(ctx, systemdUnitName(id)); err != nil {
					log.Error().Err(err).Str("vm_id", id).Msg("failed to stop orphan unit from BoltDB")
				}
				removeUnitDropIn(id)
			}
			r.markStale(id)
			r.writeAudit(ctx, id, "stale_cleanup", "BoltDB entry with no DB row", "boltdb_present_db_missing")
			r.clearDrift("bolt-orphan:" + id)
		}
	}
}

// isAlive returns true when the VM's systemd unit is currently active.
func (r *Reconciler) isAlive(ctx context.Context, vmID string, _ map[string]VMRecord) bool {
	return isUnitActive(ctx, systemdUnitName(vmID))
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

// getSnapshot loads a snapshot row by ID via the internal (unscoped)
// query. The reconciler is host-scoped, not team-scoped, so it uses
// GetSnapshotByID which bypasses the tenant filter. Guards the call
// with dbQueryTimeout so a slow DB can't wedge the loop.
func (r *Reconciler) getSnapshot(ctx context.Context, id [16]byte) (db.Snapshot, error) {
	qctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	return r.cfg.DB.GetSnapshotByID(qctx, id)
}

// dbQueryTimeout is the per-query deadline for short reconciler writes
// and single-row reads. Kept below runTimeout so a single slow query
// can't consume the whole run's budget.
const dbQueryTimeout = 5 * time.Second

// markFailedInDB writes status=failed for the given sandbox ID. No-op if
// the DB is not configured.
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

	r.mu.Lock()
	delete(r.driftSeen, vmID)
	r.mu.Unlock()

	r.mgr.log.Warn().Str("component", "reconciler").Str("vm_id", vmID).
		Str("action", "mark_stale").Msg("reconciler: cleaned up stale VM record")
}
