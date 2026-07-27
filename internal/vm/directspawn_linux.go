package vm

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
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
// the host. 1 MiB is far more than a boot log plus a panic dump, yet the
// aggregate worst case (every VM malicious) stays bounded. Kept as the FIRST
// bytes: boot output and the earliest fault are the forensic value; a guest
// that spams megabytes before crashing is already the pathological case.
const maxConsoleBytes = 1 << 20

// openVMConsole opens the per-VM console file that the child's stdout/stderr
// attach to (through cappedConsole). Firecracker's own log line plus
// panic/abort output land here — including the UFFD handler-death message
// that precedes an exit(70). A file, not a journald stream: journald
// rate-limits by unit cgroup, so shared streams would let one spamming VM
// suppress vmd's own logs; the per-VM cap below supplies the bound journald
// would otherwise give.
func openVMConsole(runDir, vmID string) (*os.File, error) {
	return os.OpenFile(filepath.Join(runDir, vmID, "console.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

// cappedConsole bounds how much a VM's console can write. Once the cap is
// reached it drops further output, reporting success so the guest's writes
// never block on a full pipe. os/exec routes both stdout and stderr through
// one copier when they are the same writer value, so Write is not called
// concurrently — the mutex is cheap insurance, not a hot path.
type cappedConsole struct {
	mu        sync.Mutex
	w         io.Writer
	remaining int64
	capped    bool
	vmID      string
	log       zerolog.Logger
}

func newCappedConsole(w io.Writer, cap int64, vmID string, log zerolog.Logger) *cappedConsole {
	return &cappedConsole{w: w, remaining: cap, vmID: vmID, log: log}
}

func (c *cappedConsole) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		if !c.capped {
			c.capped = true
			c.log.Warn().Str("vm_id", c.vmID).Msg("console output hit cap — dropping further output")
		}
		return len(p), nil // drop; report consumed so the copier keeps draining
	}
	if int64(len(p)) > c.remaining {
		n, err := c.w.Write(p[:c.remaining])
		c.remaining -= int64(n)
		return len(p), err // wrote up to the cap; the rest is dropped
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	return n, err
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
// waitDirect). console is a cappedConsole (an io.Writer, not the raw file),
// so os/exec pipes the child's output through the cap; the underlying file
// is closed by the caller after Wait, when the copier has drained.
//
// Setsid: the VM gets its own session — signals to vmd's process group
// must never reach VMs (precedent: the cold-boot path). Deliberately NO
// Pdeathsig: children must outlive vmd; that is the survival property.
func spawnDirect(scriptPath string, cgroupDir *os.File, console io.Writer) (*exec.Cmd, error) {
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
