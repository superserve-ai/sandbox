package vm

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// Guest wall-clock correctness gates this whole mechanism.
//
// A restored guest's monotonic clock normally advances by the entire period its
// snapshot sat unused, and the guest spends time working through the resulting
// overdue-timer backlog before it can serve traffic — so readiness gets slower
// the older the snapshot is. Firecracker can freeze that clock across the
// snapshot instead, which removes the cost.
//
// The catch is that the same mechanism is what silently keeps the guest's wall
// clock correct: freeze it and the guest wakes believing it is still the moment
// the snapshot was taken, which breaks TLS validity, token expiry and log
// timestamps. Only a guest that corrects its own wall clock on wake can take
// that trade. Every other snapshot keeps the slower, correct behaviour, so the
// failure direction here is always "no worse than today".
const (
	// clockRealtimeCap is what a Firecracker build advertises when it accepts a
	// per-restore clock policy. A binary that does not is left on legacy.
	clockRealtimeCap = "clock-realtime-flag"
)

// firecrackerCapabilityProbeTimeout bounds one --version exec.
const firecrackerCapabilityProbeTimeout = 5 * time.Second

// firecrackerCapabilityRefreshInterval is how often the binary is re-asked.
//
// The deploy replaces it in place without restarting vmd, so an answer read once
// at startup goes stale in both directions. A rollback leaves a stale true, and
// the restore fallback catches that on the first refusal. An upgrade leaves a
// stale false, and nothing would ever correct it — marked snapshots would keep
// taking the slow path until the daemon happened to restart for another reason.
const firecrackerCapabilityRefreshInterval = 5 * time.Minute

// WatchFirecrackerCapability keeps the cached binary capabilities — the clock
// option and the guarded dirty-tracking session — in step with the binary on
// disk.
//
// Runs entirely off the lifecycle paths: probing execs a process, which belongs
// on neither a restore nor a restart. Until the first probe answers, every
// capability reads false and restores take the older behaviour — slower, correct.
func (m *Manager) WatchFirecrackerCapability(ctx context.Context, log zerolog.Logger) {
	if m.cfg.FirecrackerBin == "" {
		return
	}
	// One --version exec answers for every capability. A change is logged;
	// an absent capability is only worth saying when someone asked for the
	// behaviour, and only once — an older binary is the normal state until
	// the fork's release is rolled out.
	track := func(first bool, caps map[string]bool, cap string, cached *atomic.Bool, wanted bool, changed, lacking string) {
		ok := caps[cap]
		if cached.Swap(ok) != ok {
			log.Info().Bool("capable", ok).Str("bin", m.cfg.FirecrackerBin).Msg(changed)
			return
		}
		if first && !ok && wanted {
			log.Warn().Str("bin", m.cfg.FirecrackerBin).Msg(lacking)
		}
	}
	probe := func(first bool) {
		pctx, cancel := context.WithTimeout(ctx, firecrackerCapabilityProbeTimeout)
		defer cancel()
		caps := firecrackerAdvertisedCaps(pctx, m.cfg.FirecrackerBin)
		track(first, caps, clockRealtimeCap, &m.clockRealtimeCapable, m.cfg.GuestClockFreezeEnabled,
			"firecracker clock-option capability changed",
			"firecracker lacks the clock option; guest clock freeze stays off")
		track(first, caps, dirtyTrackingSessionCap, &m.dirtyTrackingSessionCapable, m.cfg.DirtyTrackingSessionEnabled,
			"firecracker dirty-tracking session capability changed",
			"firecracker lacks the dirty-tracking session; guarded pauses stay off")
	}
	go func() {
		probe(true)
		t := time.NewTicker(firecrackerCapabilityRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				probe(false)
			}
		}
	}()
}

// guestCorrectsWallClock reports whether the guest now being paused fixes its
// own wall clock, judged from the images it was restored from: its own memory
// file, or the layered base beneath it when this is a first pass off a template.
// Any manifest that cannot be read counts as no: absence of proof is not proof,
// and the safe answer is the slow one.
func guestCorrectsWallClock(instMemFile, instBaseMem string) bool {
	for _, p := range []string{instMemFile, instBaseMem} {
		if p == "" {
			continue
		}
		if m, err := imageManifest(p); err == nil && m != nil && m.GuestCorrectsClock {
			return true
		}
	}
	return false
}

// resumeWallClockProperty returns what the image being resumed says about its
// guest, preferring the durable record to the filesystem.
//
// An ordinary resume reloads the exact image the VM was paused into, and that
// pause wrote the property to the record and the manifest together — so the
// record is already the answer and the resume path need not go to disk for it.
// Only an explicit override, supplying an image this VM was never paused into,
// or a record that never carried the answer (a rollback to a binary without the
// field drops it on rewrite, and its silence must not be read as "no") has to
// look. That read also says whether the image holds a frozen workload, which
// the caller must refuse: a manifest this binary cannot trust is an error.
func resumeWallClockProperty(memPath, pausedMemPath string, recorded *bool) (correctsWallClock, workloadFrozen bool, err error) {
	if memPath == pausedMemPath && recorded != nil {
		return *recorded, false, nil
	}
	m, err := imageManifest(memPath)
	if err != nil {
		return false, false, err
	}
	if m != nil {
		return m.GuestCorrectsClock, m.WorkloadFrozen, nil
	}
	// No manifest of its own: the image holds no frozen workload, which an
	// overlay never inherits, but its guest came from the template beneath
	// it, so the capability is read from there, as the pause-time check does.
	if base, ok := readLayeredBase(memPath); ok {
		if bm, berr := imageManifest(base); berr == nil && bm != nil {
			return bm.GuestCorrectsClock, false, nil
		}
	}
	return false, false, nil
}

// clockPolicyFor turns the resolved image fact into a restore policy.
//
// Two independent facts meet here, and only here: whether the image holds a
// frozen workload from a guest that fixes its own wall clock, which is a
// property of the image and is recorded with it, and whether this host's
// Firecracker can be asked to freeze the clock, which is a property of the
// binary and changes under a running daemon. Keeping them apart is what lets a
// host with an older binary restore a marked guest the legacy way while leaving
// its manifest intact for a host that can honour it.
//
// nil means "restore the flags the snapshot itself carries" — the behaviour that
// predates the flag, and the only one valid for every snapshot. A non-nil false
// asks Firecracker to freeze the guest's monotonic clock across the snapshot.
//
// It never returns true: advancing the guest clock by elapsed wall time is the
// behaviour being fixed, so nothing here should be able to ask for it.
func (m *Manager) clockPolicyFor(workloadFrozen bool) *bool {
	if !m.cfg.GuestClockFreezeEnabled || !workloadFrozen || !m.clockRealtimeCapable.Load() {
		return nil
	}
	freeze := false
	return &freeze
}

// restoreWithClockFallback runs a restore and, if this Firecracker rejects the
// clock option as an unknown field, degrades to legacy and retries once.
//
// The deploy replaces the binary in place without restarting vmd, so a rollback
// to an older Firecracker can happen under a running daemon and make the cached
// capability a lie. The refusal is a deserialization error raised before any
// guest state is touched, so retrying without the option is safe. Clearing the
// capability bounds the cost: every restore already in flight with the stale
// value may take the rejection and retry, but restores started afterwards go
// straight to legacy. The retries are independent and do not serialize.
// Reports whether the restore that succeeded actually carried the policy, so a
// caller logging the outcome describes what happened rather than what was asked
// for — after a fallback those differ.
func (m *Manager) restoreWithClockFallback(policy *bool, restore func(clockRealtime *bool) error) (usedPolicy bool, err error) {
	// A refusal seen by any earlier attempt — including this restore's own
	// session fallback, which re-enters here — already settled the answer;
	// spend no request rediscovering it.
	if policy != nil && !m.clockRealtimeCapable.Load() {
		policy = nil
	}
	err = restore(policy)
	if policy == nil || !isUnknownClockFieldErr(err) {
		return policy != nil && err == nil, err
	}
	if m.clockRealtimeCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected the clock option; falling back to legacy clock behaviour for every restore")
	}
	return false, restore(nil)
}
