package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Supervision dispatch: one seam per lifecycle question, choosing the cgroup
// or the systemd-unit implementation by a VM's recorded mode. New launches
// pick cgroup mode only when armed; every existing VM follows its record, so
// the two modes coexist through the migration and a rollback drains rather
// than converts.

// directCgroupStopBudget bounds the wait for a killed VM's cgroup to empty.
// Sized under the network pool's defaultVerifyMaxWait (20s) so slot recycle
// never races an FC that still holds its tap — the same constraint the unit
// path met via TimeoutStopSec.
const directCgroupStopBudget = 12 * time.Second

// launchMode reports whether a launch for a VM in the given supervision mode
// should take the cgroup path. A record already in cgroup mode always does;
// a fresh launch does only when armed.
func (m *Manager) cgroupLaunch(existing Supervision) bool {
	if cgroupSupervised(existing) {
		return true
	}
	return m.directSpawnArmed.Load()
}

// launchFirecracker picks cgroup vs unit mode from the VM's existing supervision
// and the armed flag, and returns the mode actually used so the caller stamps it
// before persisting (a resume that flips to cgroup must record it). A cgroup
// record always relaunches cgroup, so a flag-off rollback drains not converts.
// hadPriorLife (resume/verify/in-place/leftover-rundir) runs the legacy-unit
// stop before a cgroup launch; freshUnit is the systemd linger-skip hint,
// ignored on the cgroup path.
func (m *Manager) launchFirecracker(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, existing Supervision, hadPriorLife, freshUnit bool) (pid int, supervision Supervision, err error) {
	if m.launchFirecrackerHook != nil {
		return m.launchFirecrackerHook(ctx, vmID, socketPath, perVMRootfs, basePath, netNS, existing, hadPriorLife, freshUnit)
	}
	return m.launchFirecrackerImpl(ctx, vmID, socketPath, perVMRootfs, basePath, netNS, existing, hadPriorLife, freshUnit)
}

func (m *Manager) launchFirecrackerImpl(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, existing Supervision, hadPriorLife, freshUnit bool) (pid int, supervision Supervision, err error) {
	if !knownSupervision(existing) {
		// A launch over an unknown mode could double-spawn: the prior-life
		// stop below only clears units, and no oracle can prove what an
		// unknown mode left running.
		return 0, existing, fmt.Errorf("vm %s has unknown supervision mode %q; refusing launch", vmID, existing)
	}
	if m.cgroupLaunch(existing) {
		// Arming implies the validated launch path, but a cgroup record
		// reaches here in manage-only mode too, where validation may have
		// failed or never run (flag off). Refuse — the record and the
		// paused VM stay untouched; the arm-time log names the repair.
		if !m.launchPathValidated.Load() {
			return 0, existing, fmt.Errorf("direct launch path not validated on this host; refusing cgroup launch for %s", vmID)
		}
		// A prior life may have left a legacy unit live — a unit whose
		// pause-stop timed out, or the scope-gone fallback below when vmd
		// crashed before persisting the unit mode (so even a cgroup record
		// doesn't prove no unit exists). Spawning a cgroup FC over it gives
		// two processes one ID/tap with only the new one ever cleaned up.
		// Stop, then require a terminal state (unitFullyDown, not
		// unitDefinitelyDead): a wedged stop settles as "deactivating",
		// which both report as stopped while the old FC is still exiting.
		// A no-op unit stop costs one D-Bus round trip; fresh creates never
		// had a unit and skip it.
		//
		// Timed, and carried into the phase log below: this block runs before
		// the phase clock starts, so without the field it is the invisible
		// difference between fc_start_ms and prestart+spawn+wait_socket —
		// a gap that has to be reconstructed by subtraction across log lines,
		// which mispairs whenever the same VM launched more than once.
		var stopPrior time.Duration
		if hadPriorLife {
			tStopPrior := time.Now()
			_ = stopUnit(ctx, systemdUnitName(vmID))
			if !unitFullyDown(ctx, systemdUnitName(vmID)) {
				return 0, existing, fmt.Errorf("legacy unit for %s not fully down; refusing cgroup launch", vmID)
			}
			stopPrior = time.Since(tStopPrior)
		}
		pid, err = m.startFirecrackerDirect(ctx, vmID, socketPath, perVMRootfs, basePath, netNS, stopPrior)
		if err != nil && errors.Is(err, errScopeGone) {
			// The delegated scope is gone (keeper died, drained scope GC'd).
			// Scope-gone proves no cgroup FC survives for this ID (a populated
			// child would have pinned the scope), so a unit launch cannot
			// double-spawn. The deploy guard restarting the keeper restores
			// the cgroup path with no re-arm.
			m.log.Error().Str("vm_id", vmID).Err(err).Msg("direct spawn scope missing; falling back to unit supervision")
			// The unit is only provably fresh for a first-life create; any
			// prior life (or prior cgroup record) must take the guarded path.
			fallbackFresh := freshUnit && !hadPriorLife && !cgroupSupervised(existing)
			pid, err = m.startFirecrackerViaSystemd(ctx, vmID, socketPath, perVMRootfs, basePath, netNS, fallbackFresh)
			return pid, SupervisionUnit, err
		}
		if err != nil && !m.cgroupStillLive(vmID) {
			// Launch failed with no surviving cgroup (startFirecrackerDirect
			// cleans up on every error path): claiming cgroup would persist a
			// StatusError record for a nonexistent cgroup that blocks
			// drain-check. Keep the prior mode.
			return pid, existing, err
		}
		return pid, SupervisionCgroup, err
	}
	pid, err = m.startFirecrackerViaSystemd(ctx, vmID, socketPath, perVMRootfs, basePath, netNS, freshUnit)
	return pid, SupervisionUnit, err
}

// stopVM terminates a VM by its supervision mode. cgroup mode: kill the
// group and wait it empty, then rmdir; unit mode: the existing systemd stop.
// Idempotent — a missing group or unit is a no-op.
func (m *Manager) stopVM(ctx context.Context, vmID string, supervision Supervision) error {
	if !knownSupervision(supervision) {
		// Dispatching unknown to the unit path would no-op against a
		// nonexistent unit and report the stop clean.
		return fmt.Errorf("stop vm %s: unknown supervision mode %q", vmID, supervision)
	}
	if cgroupSupervised(supervision) {
		if m.cgroups == nil {
			return fmt.Errorf("stop cgroup VM %s: no delegated subtree (not armed)", vmID)
		}
		// Detach from the caller's deadline and give the kill its full
		// budget: freeing the tap MUST complete, and several callers pass a
		// context shorter than directCgroupStopBudget (reattach 5s, restore
		// cleanup 10s). A stop cut short would let a caller recycle the slot
		// while a UFFD-blocked FC still holds the tap.
		killCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directCgroupStopBudget)
		defer cancel()
		if err := m.cgroups.killVMCgroup(killCtx, vmID, directCgroupStopBudget); err != nil {
			return err
		}
		m.awaitReaper(vmID)
		return m.cgroups.removeVMCgroup(context.WithoutCancel(ctx), vmID)
	}
	return stopUnit(ctx, systemdUnitName(vmID))
}

// awaitReaper drains this process's exit channel for a VM it directly spawned,
// so a killed child is reaped (not left a zombie) before callers free its
// slot. No-op for adopted VMs (post-restart, init-parented) — they have no
// reaper here; their exit is init's, and their liveness is the cgroup.
func (m *Manager) awaitReaper(vmID string) {
	ch, ok := m.reapers.LoadAndDelete(vmID)
	if !ok {
		return
	}
	select {
	case <-ch.(chan struct{}):
	case <-time.After(2 * time.Second):
		// The kill already confirmed the cgroup empty; a stuck Wait must not
		// wedge the stop. The reaper goroutine still closes and exits.
	}
}

// vmDefinitelyDead reports whether a VM is definitively not running, by its
// supervision mode. Mirrors unitDefinitelyDead's contract on BOTH paths:
// only a real answer says dead — an unreadable cgroup or an inconclusive
// systemd probe reads as ALIVE, so an overloaded host never reaps a live VM.
func (m *Manager) vmDefinitelyDead(ctx context.Context, vmID string, supervision Supervision) bool {
	if !knownSupervision(supervision) {
		return false // no oracle applies to an unknown mode — maybe-alive
	}
	if cgroupSupervised(supervision) {
		return m.cgroupDefinitelyDead(vmID)
	}
	return unitDefinitelyDead(ctx, systemdUnitName(vmID))
}

// cgroupDefinitelyDead is the cgroup-mode twin of unitDefinitelyDead, kept a
// named oracle beside it so the two supervision modes share ONE definition of
// the fail-safe rather than re-deriving it per call site. Only a conclusively
// empty group says dead; a missing subtree (not armed) or an unreadable
// cgroup.events is inconclusive and reads as ALIVE — identical to the unit
// oracle, so an overloaded host never reaps a live VM.
func (m *Manager) cgroupDefinitelyDead(vmID string) bool {
	if m.cgroups == nil {
		return false // can't prove death without the subtree
	}
	populated, err := m.cgroups.vmCgroupPopulated(vmID)
	if err != nil {
		return false // unreadable == inconclusive == alive
	}
	return !populated
}

// cgroupStillLive reports whether a per-VM cgroup for vmID is populated (or
// unreadable — inconclusive reads live). It is the mode-AGNOSTIC guard the
// destroy path checks before freeing a slot: unlike cgroupDefinitelyDead it
// returns false when there is no delegated subtree (nothing to strand), so a
// plain unit VM never blocks its own destroy. The point is that the record's
// supervision mode can be stale — a verify throwaway can leak a cgroup FC onto
// a unit record, and a no-op unit stop even succeeds — so freeing the tap must
// consult reality (the cgroup) rather than trust the record's dispatch mode.
func (m *Manager) cgroupStillLive(vmID string) bool {
	if m.cgroups == nil {
		return false
	}
	populated, err := m.cgroups.vmCgroupPopulated(vmID)
	return err != nil || populated
}

// startFirecrackerDirect launches Firecracker into the VM's own cgroup,
// forked by vmd (not PID 1). Returns the child PID synchronously — the exec
// chain (nsenter→unshare→sh→exec fc) preserves a single PID end to end, so
// the async unit-MainPID resolution is unnecessary here. A leftover populated
// cgroup at launch is the winding-down case: kill it empty first, mirroring
// the unit path's replace semantics.
func (m *Manager) startFirecrackerDirect(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, stopPrior time.Duration) (int, error) {
	tPrestart := time.Now()
	if m.cgroups == nil {
		return 0, fmt.Errorf("direct launch %s: not armed", vmID)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	// Replace preamble: a populated group means a stale FC (interrupted stop)
	// still holds this vmID's socket. Kill-and-wait-empty before forking, or
	// two FCs race one socket. An unreadable cgroup.events (err != nil) is
	// inconclusive — treat it as maybe-populated and kill, matching the
	// fail-safe (inconclusive == alive) rule the oracles use; only a
	// definitive not-populated skips the kill.
	if pop, perr := m.cgroups.vmCgroupPopulated(vmID); perr != nil || pop {
		if kerr := m.cgroups.killVMCgroup(ctx, vmID, directCgroupStopBudget); kerr != nil {
			return 0, fmt.Errorf("clear stale cgroup before launch: %w", kerr)
		}
		m.awaitReaper(vmID)
	}

	setupCmds := fcSetupCmds(m.templateRunDir(), basePath, perVMRootfs)
	launcherPath := m.launchLauncherPath(vmID)
	scriptContent, err := directSpawnScript(netNS, launcherPath, setupCmds, m.cfg.FirecrackerBin, socketPath, vmID)
	if err != nil {
		return 0, err
	}
	scriptPath := filepath.Join(filepath.Dir(socketPath), "start.sh")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
		return 0, fmt.Errorf("write start script: %w", err)
	}

	cgDir, err := m.cgroups.createVMCgroup(vmID)
	if err != nil {
		return 0, err
	}
	// spawnDirect takes ownership of cgDir and closes it; until the hand-off
	// this path still owns it, so close it on the openVMConsole error return.
	console, err := openVMConsole(m.cfg.RunDir, vmID)
	if err != nil {
		cgDir.Close()
		// An abandoned empty cgroup plus the cgroup-supervised record the
		// caller persists sits outside every reaper's rules and wedges
		// drain-check.
		_ = m.cgroups.removeVMCgroup(context.WithoutCancel(ctx), vmID)
		return 0, fmt.Errorf("open vm console: %w", err)
	}

	tStart := time.Now()
	cmd, err := spawnDirect(scriptPath, cgDir, console)
	console.Close() // the child holds its own dup; vmd's copy is done
	if err != nil {
		// Log locally: the error otherwise only surfaces as a gRPC failure at
		// the control plane, hiding daemon-side launch faults from the journal.
		m.log.Error().Str("vm_id", vmID).Err(err).Msg("direct spawn failed")
		_ = m.cgroups.removeVMCgroup(context.WithoutCancel(ctx), vmID)
		return 0, fmt.Errorf("spawn firecracker: %w", err)
	}
	pid := cmd.Process.Pid
	// exited is closed once the child is reaped; any number of stop paths can
	// wait on it (a closed channel never blocks a reader), and its closure is
	// the zombie-free proof a slot recycle needs.
	exited := make(chan struct{})
	m.reapers.Store(vmID, exited)
	go func() {
		res := waitDirect(cmd)
		close(exited)
		// Drop our own entry so a VM that exits WITHOUT a stop (guest
		// shutdown, crash, OOM) doesn't leak a map entry — the only other
		// remover is awaitReaper, which runs on stop paths. CompareAndDelete
		// so a same-ID relaunch's Store isn't clobbered.
		m.reapers.CompareAndDelete(vmID, exited)
		m.log.Info().Str("vm_id", vmID).Int("exit_code", res.ExitCode).
			Msg("direct-spawned firecracker exited")
	}()
	tSpawnDone := time.Now()

	socketWait := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		socketWait = max(2*time.Second, min(socketWait, time.Until(dl)))
	}
	if err := waitForSocket(socketPath, socketWait); err != nil {
		m.log.Warn().Str("vm_id", vmID).Err(err).Msg("firecracker socket missing after direct launch")
		_ = m.cgroups.killVMCgroup(context.WithoutCancel(ctx), vmID, directCgroupStopBudget)
		m.awaitReaper(vmID)
		_ = m.cgroups.removeVMCgroup(context.WithoutCancel(ctx), vmID)
		return 0, fmt.Errorf("wait for socket (direct %s): %w", vmID, err)
	}
	tSocketReady := time.Now()

	ev := m.log.Info().
		Str("vm_id", vmID).
		Int64("stop_prior_ms", stopPrior.Milliseconds()).
		Int64("prestart_ms", tStart.Sub(tPrestart).Milliseconds()).
		Int64("spawn_ms", tSpawnDone.Sub(tStart).Milliseconds()).
		Int64("wait_socket_ms", tSocketReady.Sub(tSpawnDone).Milliseconds()).
		Bool("direct", true)
	// chain = fork return → the script's pre-exec stamp (nsenter/unshare/
	// mounts); fc_socket = Firecracker init plus our detection latency.
	// Emitted to both the log and the phase histogram when the stamp is
	// usable; the coarse phases always emit.
	launchPhases := map[string]time.Duration{
		"stop_prior":  stopPrior,
		"prestart":    tStart.Sub(tPrestart),
		"spawn":       tSpawnDone.Sub(tStart),
		"wait_socket": tSocketReady.Sub(tSpawnDone),
	}
	if ts, ok := readFCExecStamp(socketPath, tSpawnDone, tSocketReady); ok {
		ev = ev.Int64("chain_ms", ts.Sub(tSpawnDone).Milliseconds()).
			Int64("fc_socket_ms", tSocketReady.Sub(ts).Milliseconds())
		launchPhases["chain"] = ts.Sub(tSpawnDone)
		launchPhases["fc_socket"] = tSocketReady.Sub(ts)
	}
	ev.Msg("fc startup phases")
	m.recordPhases("launch", "direct", launchPhases)

	return pid, nil
}

// launchLauncherPath resolves the launcher-namespace pin for this launch,
// falling back to legacy with the same per-launch logging as the unit path.
// Shared so the direct and unit launchers make the identical decision.
func (m *Manager) launchLauncherPath(vmID string) string {
	pin := m.launcherNSPath()
	switch {
	case pin == "":
		return ""
	case !m.launcherReady.Load():
		if m.launcherBuilt.Load() {
			m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin invalidated — using legacy path for this launch")
		} else {
			m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin not built — using legacy path for this launch")
		}
		return ""
	case pinIsMounted(pin):
		return pin
	default:
		m.log.Warn().Str("path", pin).Str("vm_id", vmID).Msg("launcher pin not mounted at launch — using legacy path for this launch")
		return ""
	}
}
