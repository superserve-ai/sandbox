package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Direct spawn: vmd forks the per-VM start.sh itself (into the VM's cgroup
// via CLONE_INTO_CGROUP) instead of asking PID 1 to start a service unit.
// The rendered script and the whole nsenter→unshare→sh→exec chain are the
// same as the unit path; only the parent and the supervision change.

// directSpawnEnv is the ENTIRE environment a direct-spawned VM chain gets.
// systemd gave start.sh a clean environment; vmd's own environ carries
// DATABASE_URL, INTERNAL_API_TOKEN, and every VMD_* flag, none of which may
// reach Firecracker's process memory (it is the sandbox boundary and it
// dumps core). PATH covers the script's bare tool names; RUN_DIR matches
// the unit file's one declared variable. Nothing else — additions here are
// a security review, not a convenience.
func directSpawnEnv() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"RUN_DIR=/var/lib/sandbox/rundir",
	}
}

// directSpawnScript renders the launch script for direct spawn: the unit
// path's script with a prlimit hop pinning NOFILE to the systemd service
// defaults. Without it the chain inherits vmd's 65536 soft limit and
// Firecracker's fd-table preallocation (sized to the soft limit) costs
// ~0.5MB of kernel memory per VM at fleet density.
func directSpawnScript(netNS, launcherNSPath, setupCmds, fcBin, socketPath, vmID string) (string, error) {
	base := fcStartScript(netNS, launcherNSPath, setupCmds, fcBin, socketPath, vmID)
	const prefix = "#!/bin/sh\nexec "
	rest, ok := strings.CutPrefix(base, prefix)
	if !ok {
		// fcStartScript's shape changed without this wrapper following —
		// refuse rather than launch with the wrong limits.
		return "", fmt.Errorf("fcStartScript shape changed; directSpawnScript needs updating")
	}
	return prefix + "prlimit --nofile=1024:524288 " + rest, nil
}

// maxConsoleBytes caps a VM's console file. The guest serial console is
// UNTRUSTED output: without a bound, a guest that spams its console grows
// console.log without limit and fills the host disk, taking down every VM on
// the host. The bound is enforced out-of-band by trimOversizedConsoles on
// the reconcile tick (NOT by interposing vmd in the write path — the child
// must own its file fd so its output survives a vmd restart). 1 MiB is far
// more than a boot log plus a panic dump; the reconciler keeps the first
// maxConsoleBytes (boot + earliest fault) and drops the overflow.
const maxConsoleBytes = 1 << 20

// openVMConsole opens the per-VM console file the child's stdout/stderr
// attach to. Firecracker's own log line plus panic/abort output land here —
// including the UFFD handler-death message that precedes an exit(70). The
// child holds this fd directly (O_APPEND), so its console keeps flowing to
// the file even across a vmd restart — the survival property. A file, not a
// journald stream: journald rate-limits by unit cgroup, so shared streams
// would let one spamming VM suppress vmd's own logs. The size bound journald
// would otherwise give is supplied by trimOversizedConsoles.
func openVMConsole(runDir, vmID string) (*os.File, error) {
	return os.OpenFile(filepath.Join(runDir, vmID, "console.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

// trimOversizedConsoles bounds every direct-spawn console file to
// maxConsoleBytes by truncating the overflow, keeping the first
// maxConsoleBytes (boot + earliest fault). Truncating to a size that a live
// FC is appending to (O_APPEND) is safe: the file caps at maxConsoleBytes and
// the next append lands just past it, trimmed again next tick. This is a
// total-file-size bound, so it also caps growth across resume/verify cycles
// that reuse the same file. No-op unless armed; runs on the reconcile tick.
func (m *Manager) trimOversizedConsoles() {
	if m.cgroups == nil {
		return
	}
	ids, err := m.cgroups.scanVMCgroups()
	if err != nil {
		return
	}
	for _, id := range ids {
		path := filepath.Join(m.cfg.RunDir, id, "console.log")
		fi, err := os.Stat(path)
		if err != nil || fi.Size() <= maxConsoleBytes {
			continue
		}
		if terr := os.Truncate(path, maxConsoleBytes); terr != nil {
			m.log.Warn().Err(terr).Str("vm_id", id).Msg("failed to trim oversized console")
			continue
		}
		m.log.Warn().Str("vm_id", id).Int64("cap", maxConsoleBytes).
			Msg("trimmed oversized vm console")
	}
}

// directSpawnResult is what the reaper records when the VM's process chain
// exits. Exit code 70 is Firecracker's UFFD-handler-death abort; it has no
// programmatic consumer, but the log line preserves the forensic signal the
// systemd unit's Result field used to carry.
type directSpawnResult struct {
	ExitCode int
	Err      error
	At       time.Time
}

// spawnDirect launches script (already on disk, mode 0755) into the given
// cgroup directory fd. Returns the started Cmd; the caller owns Wait (via
// waitDirect). console is the raw per-VM file: os/exec passes its fd straight
// to the child, so the child owns it and keeps writing even after vmd exits —
// no vmd-owned pipe in the path. The caller closes vmd's copy after Start.
// The file's size bound is enforced separately by trimOversizedConsoles.
//
// Setsid: the VM gets its own session — signals to vmd's process group
// must never reach VMs (precedent: the cold-boot path). Deliberately NO
// Pdeathsig: children must outlive vmd; that is the survival property.
func spawnDirect(scriptPath string, cgroupDir, console *os.File) (*exec.Cmd, error) {
	cmd := exec.Command(scriptPath)
	cmd.Env = directSpawnEnv()
	cmd.Stdout = console
	cmd.Stderr = console
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:      true,
		UseCgroupFD: true,
		CgroupFD:    int(cgroupDir.Fd()),
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// waitDirect blocks until the chain exits and reports the outcome. It is
// what keeps a killed child from lingering as a zombie — kill paths wait for
// the reaper's completion signal, never on kill(pid,0) polling (zombies
// answer those polls as alive). VMs from a previous vmd life have init as
// their reaper and no exit-code visibility; their liveness is the cgroup.
func waitDirect(cmd *exec.Cmd) directSpawnResult {
	err := cmd.Wait()
	res := directSpawnResult{Err: err, At: time.Now(), ExitCode: 0}
	if err != nil {
		res.ExitCode = -1
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		}
	}
	return res
}
