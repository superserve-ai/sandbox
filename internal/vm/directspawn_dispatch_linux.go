package vm

import (
	"context"
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
func (m *Manager) cgroupLaunch(existing string) bool {
	if cgroupSupervised(existing) {
		return true
	}
	return m.directSpawnArmed.Load()
}

// stopVM terminates a VM by its supervision mode. cgroup mode: kill the
// group and wait it empty, then rmdir; unit mode: the existing systemd stop.
// Idempotent — a missing group or unit is a no-op.
func (m *Manager) stopVM(ctx context.Context, vmID, supervision string) error {
	if cgroupSupervised(supervision) {
		if m.cgroups == nil {
			return fmt.Errorf("stop cgroup VM %s: no delegated subtree (not armed)", vmID)
		}
		if err := m.cgroups.killVMCgroup(ctx, vmID, directCgroupStopBudget); err != nil {
			return err
		}
		m.awaitReaper(vmID)
		return m.cgroups.removeVMCgroup(vmID)
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
func (m *Manager) vmDefinitelyDead(ctx context.Context, vmID, supervision string) bool {
	if cgroupSupervised(supervision) {
		if m.cgroups == nil {
			return false // can't prove death without the subtree
		}
		populated, err := m.cgroups.vmCgroupPopulated(vmID)
		if err != nil {
			return false // unreadable == inconclusive == alive
		}
		return !populated
	}
	return unitDefinitelyDead(ctx, systemdUnitName(vmID))
}

// startFirecrackerDirect launches Firecracker into the VM's own cgroup,
// forked by vmd (not PID 1). Returns the child PID synchronously — the exec
// chain (nsenter→unshare→sh→exec fc) preserves a single PID end to end, so
// the async unit-MainPID resolution is unnecessary here. A leftover populated
// cgroup at launch is the winding-down case: kill it empty first, mirroring
// the unit path's replace semantics.
func (m *Manager) startFirecrackerDirect(ctx context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string) (int, error) {
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
	// two FCs race one socket.
	if pop, err := m.cgroups.vmCgroupPopulated(vmID); err == nil && pop {
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
	defer cgDir.Close()
	console, err := openVMConsole(m.cfg.RunDir, vmID)
	if err != nil {
		return 0, fmt.Errorf("open vm console: %w", err)
	}

	tStart := time.Now()
	cmd, err := spawnDirect(scriptPath, cgDir, console)
	console.Close() // the child holds its own dup; vmd's copy is done
	if err != nil {
		_ = m.cgroups.removeVMCgroup(vmID)
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
		_ = m.cgroups.removeVMCgroup(vmID)
		return 0, fmt.Errorf("wait for socket (direct %s): %w", vmID, err)
	}
	tSocketReady := time.Now()

	m.log.Info().
		Str("vm_id", vmID).
		Int64("prestart_ms", tStart.Sub(tPrestart).Milliseconds()).
		Int64("spawn_ms", tSpawnDone.Sub(tStart).Milliseconds()).
		Int64("wait_socket_ms", tSocketReady.Sub(tSpawnDone).Milliseconds()).
		Bool("direct", true).
		Msg("fc startup phases")

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
