package vm

import (
	"context"
	"os"
	"sync"
	"time"
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
//   - BoltDB: VMD's own fast-path cache (authoritative for nothing)
//   - systemd: which firecracker@ units are actually running (authoritative
//     for liveness)
//
// It runs as a goroutine under the manager's lifecycle. Destructive actions
// are rate-limited via MaxAutoFailPerHour and require the drift to persist
// across at least two consecutive runs (GracePeriod).
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
	r.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("reconciler exiting")
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce performs a single reconciliation pass. Each pass:
//  1. Queries BoltDB and systemd for all known/running VMs on this host.
//  2. Compares the two sets.
//  3. For each drifted VM, records the drift timestamp and (only if the
//     drift has persisted past the grace period) applies the fix.
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

	// Source B: active systemd units (only meaningful in systemd mode).
	var active map[string]bool
	if r.mgr.useSystemd {
		ids, err := listActiveFirecrackerUnits(ctx)
		if err != nil {
			log.Error().Err(err).Msg("failed to list systemd units")
			return
		}
		active = make(map[string]bool, len(ids))
		for _, id := range ids {
			active[id] = true
		}
	}

	now := time.Now()
	var drifted []string

	// Drift kind 1: BoltDB says running, systemd has no unit.
	// This is a dead Firecracker — the process crashed after VMD recorded
	// it. Mark the BoltDB entry stale.
	for id, rec := range bolted {
		if rec.Status != StatusRunning {
			continue
		}
		if r.mgr.useSystemd && !active[id] {
			r.mu.Lock()
			if _, seen := r.driftSeen[id]; !seen {
				r.driftSeen[id] = now
			}
			firstSeen := r.driftSeen[id]
			r.mu.Unlock()

			if now.Sub(firstSeen) >= r.cfg.GracePeriod {
				drifted = append(drifted, id)
				log.Warn().Str("vm_id", id).Str("drift", "boltdb_running_systemd_missing").
					Msg("dead Firecracker detected")
			}
			continue
		}
		// Also check the socket for non-systemd mode.
		if !r.mgr.useSystemd && rec.SocketPath != "" {
			if _, statErr := os.Stat(rec.SocketPath); statErr != nil {
				r.mu.Lock()
				if _, seen := r.driftSeen[id]; !seen {
					r.driftSeen[id] = now
				}
				firstSeen := r.driftSeen[id]
				r.mu.Unlock()

				if now.Sub(firstSeen) >= r.cfg.GracePeriod {
					drifted = append(drifted, id)
					log.Warn().Str("vm_id", id).Str("drift", "boltdb_running_socket_missing").
						Msg("dead Firecracker detected")
				}
				continue
			}
		}

		// VM healthy — clear any drift marker.
		r.mu.Lock()
		delete(r.driftSeen, id)
		r.mu.Unlock()
	}

	// Drift kind 2: systemd has a unit, BoltDB doesn't know about it.
	// This is an orphan — likely a VMD crash that lost BoltDB state, or
	// a unit leaked from a previous lifetime. We just log for now; adoption
	// requires DB context the reconciler doesn't have yet (Phase 3 stage 2).
	if r.mgr.useSystemd {
		for id := range active {
			if _, known := bolted[id]; !known {
				log.Warn().Str("vm_id", id).Str("drift", "systemd_active_boltdb_missing").
					Msg("orphan systemd unit detected (no BoltDB record)")
			}
		}
	}

	// Apply fixes, rate-limited by MaxAutoFailPerHour.
	for _, id := range drifted {
		if !r.consumeAutoFailBudget(id) {
			continue
		}
		r.markStale(id)
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
	r.mgr.mu.Lock()
	delete(r.mgr.vms, vmID)
	r.mgr.mu.Unlock()

	if err := r.mgr.state.Delete(vmID); err != nil {
		r.mgr.log.Error().Err(err).Str("vm_id", vmID).Msg("reconciler: failed to delete stale state")
		return
	}

	r.mu.Lock()
	delete(r.driftSeen, vmID)
	r.mu.Unlock()

	r.mgr.log.Warn().Str("component", "reconciler").Str("vm_id", vmID).
		Str("action", "mark_stale").Msg("reconciler: cleaned up stale VM record")
}
