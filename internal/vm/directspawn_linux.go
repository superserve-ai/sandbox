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

// openVMConsole opens the per-VM console file the child's stdout/stderr
// attach to (Firecracker's logs plus panic/abort output, incl. the exit-70
// handler-death message). The child holds the fd directly, so console output
// survives a vmd restart. A file, not journald: journald rate-limits per unit
// cgroup, so a shared stream would let one VM suppress others' output.
//
// The untrusted guest console is size-bounded by the paired Firecracker
// serial cap (1 MiB per boot) — a deploy prerequisite for arming direct
// spawn. O_TRUNC resets the file each launch, so the on-disk total stays
// within one boot's capped output even across resume cycles.
func openVMConsole(runDir, vmID string) (*os.File, error) {
	return os.OpenFile(filepath.Join(runDir, vmID, "console.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
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
// The file's size bound is enforced by Firecracker's serial cap plus the
// O_TRUNC-per-launch in openVMConsole (see there).
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
