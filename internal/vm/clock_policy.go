package vm

import (
	"context"
	"fmt"
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

// imageWorkloadFrozen returns whether the image being resumed holds a frozen
// workload, and the token its wake must present, preferring the durable record
// to the filesystem.
//
// An ordinary resume reloads the exact image the VM was paused into, and that
// pause wrote the facts to the record and the manifest together — so the record
// is already the answer and the resume path need not go to disk for it. Only an
// explicit override, supplying an image this VM was never paused into, has to
// look, because the record then describes a different artifact. An unreadable
// manifest is an error the caller must refuse on.
func imageWorkloadFrozen(memPath, pausedMemPath string, recordedFrozen *bool, recordedToken string) (frozen bool, token string, err error) {
	if memPath == pausedMemPath && recordedFrozen != nil {
		return *recordedFrozen, recordedToken, nil
	}
	m, err := imageManifest(memPath)
	if err != nil || m == nil {
		return false, "", err
	}
	return m.WorkloadFrozen, m.FreezeToken, nil
}

// clockPolicyFor turns the resolved image fact into a restore policy.
//
// Two independent facts meet here, and only here: whether the image holds a
// frozen workload from a guest that fixes its own wall clock, which is a
// property of the image and is recorded with it, and
// whether this host's Firecracker can be asked to freeze the clock, which is a
// property of the binary and changes under a running daemon. Keeping them apart
// is what lets a host with an older binary restore a marked guest the legacy way
// while leaving its marker intact for a host that can honour it.
//
// nil means "restore the flags the snapshot itself carries" — the behaviour that
// predates the flag, and the only one valid for every snapshot. A non-nil false
// asks Firecracker to freeze the guest's monotonic clock across the snapshot.
//
// It never returns true: advancing the guest clock by elapsed wall time is the
// behaviour being fixed, so nothing here should be able to ask for it.
func (m *Manager) clockPolicyFor(workloadFrozen bool) *bool {
	if !m.cfg.GuestClockFreezeEnabled || !workloadFrozen || !m.clockRealtimeCapable.Load() || m.guestClockUnready.Load() {
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
// beforeLegacy, if set, runs before the legacy restore, which is skipped if it
// fails. The restore path makes the changed policy durable there, so a crash
// after the legacy load cannot recover the guest as clock-frozen.
func (m *Manager) restoreWithClockFallback(policy *bool, beforeLegacy func() error, restore func(clockRealtime *bool) error) (usedPolicy bool, err error) {
	// A refusal seen by any earlier attempt — including this restore's own
	// session fallback, which re-enters here — already settled the answer;
	// spend no request rediscovering it.
	if policy != nil && !m.clockRealtimeCapable.Load() {
		if beforeLegacy != nil {
			if err := beforeLegacy(); err != nil {
				return false, err
			}
		}
		policy = nil
	}
	err = restore(policy)
	if policy == nil || !isUnknownClockFieldErr(err) {
		return policy != nil && err == nil, err
	}
	if m.clockRealtimeCapable.CompareAndSwap(true, false) {
		m.log.Warn().Msg("firecracker rejected the clock option; falling back to legacy clock behaviour for every restore")
	}
	if beforeLegacy != nil {
		if err := beforeLegacy(); err != nil {
			return false, err
		}
	}
	return false, restore(nil)
}

// defaultGuestFreezeBudget bounds the pause-side wait for the guest to stop
// its workload. Only ever paid when the restore would freeze the clock.
const defaultGuestFreezeBudget = 500 * time.Millisecond

// freezeGuestForPause freezes the workload ahead of a snapshot. A failed freeze
// is ambiguous, so the guest is thawed and that must confirm, else the pause aborts.
func (m *Manager) freezeGuestForPause(ctx context.Context, ip, token string, log zerolog.Logger) (frozen bool, err error) {
	budget := m.cfg.GuestFreezeBudget
	if budget <= 0 {
		budget = defaultGuestFreezeBudget
	}
	fctx, cancel := context.WithTimeout(ctx, budget)
	echo, ferr := boxdFreezeGuest(fctx, ip, token)
	cancel()
	if ferr == nil && (echo.Token != token || echo.Version != WallClockManifestVersion) {
		// The guest froze, but not as this protocol understands it: release it.
		ferr = fmt.Errorf("freeze reply names protocol %d token %q, asked %d %q", echo.Version, echo.Token, WallClockManifestVersion, token)
	}
	if ferr == nil {
		return true, nil
	}
	tctx, tcancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer tcancel()
	if terr := boxdThawGuest(tctx, ip, token); terr != nil {
		return false, fmt.Errorf("guest workload state unknown after failed freeze (%v); thaw not confirmed: %w", ferr, terr)
	}
	log.Warn().Err(ferr).Msg("pause: guest workload not frozen; this image will wake the slower way")
	return false, nil
}

// noteGuestClockUnready latches this host to unfrozen restores: host time is a
// host property, so the caller's retry takes the path that does not need it.
func (m *Manager) noteGuestClockUnready(log zerolog.Logger, cause error) {
	if m.guestClockUnready.CompareAndSwap(false, true) {
		log.Error().Err(cause).Msg("guest could not correct its clock; this host will restore with the clock unfrozen until vmd restarts")
	}
}
