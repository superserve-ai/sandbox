package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
// attach to. Firecracker's own log line plus panic/abort output land here —
// including the UFFD handler-death message that precedes an exit(70).
// A file, not a journald stream: journald rate-limits by unit cgroup, so
// shared streams would let one spamming VM suppress vmd's own logs. Growth
// is bounded by the reconciler's disk sweep, not here.
func openVMConsole(runDir, vmID string) (*os.File, error) {
	return os.OpenFile(filepath.Join(runDir, vmID, "console.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
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
// reapDirect) and the console file's lifetime beyond exec is the child's.
//
// spawnDirect OWNS cgroupDir and closes it on every return — callers must not
// close it themselves. The fd is needed only synchronously, to seed
// CLONE_INTO_CGROUP at clone3 time; owning it here makes the lifecycle
// unambiguous (no per-caller close, so no leak) and lets a single
// runtime.KeepAlive pin the *os.File across cmd.Start(). Without that pin the
// value is unreferenced after the .Fd() call, so os.File's finalizer is free
// to close the fd mid-clone3 — an intermittent invalid-CgroupFD launch failure.
//
// Setsid: the VM gets its own session — signals to vmd's process group
// must never reach VMs (precedent: the cold-boot path). Deliberately NO
// Pdeathsig: children must outlive vmd; that is the survival property.
func spawnDirect(scriptPath string, cgroupDir *os.File, console *os.File) (*exec.Cmd, error) {
	defer cgroupDir.Close()
	cmd := exec.Command(scriptPath)
	cmd.Env = directSpawnEnv()
	cmd.Stdout = console
	cmd.Stderr = console
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:      true,
		UseCgroupFD: true,
		CgroupFD:    int(cgroupDir.Fd()),
	}
	err := cmd.Start()
	// Keep cgroupDir reachable through the clone3 inside Start; the deferred
	// Close then releases the fd on both the success and failure paths.
	runtime.KeepAlive(cgroupDir)
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

// reapDirect waits for the chain to exit and reports the outcome. Run it in
// a per-VM goroutine for every spawn: it is what keeps a killed child from
// lingering as a zombie (kill paths wait on done, never on kill(pid,0)
// polling — zombies answer those polls). VMs from a previous vmd life have
// init as their reaper and no exit-code visibility; their liveness is the
// cgroup, not this.
func reapDirect(cmd *exec.Cmd, done chan<- directSpawnResult) {
	err := cmd.Wait()
	res := directSpawnResult{Err: err, At: time.Now(), ExitCode: 0}
	if err != nil {
		res.ExitCode = -1
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		}
	}
	done <- res
}
