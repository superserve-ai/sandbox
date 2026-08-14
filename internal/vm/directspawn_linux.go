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

// directSpawnPATH is the PATH the launch chain runs under; the arm-time prlimit
// check validates against it, not vmd's own PATH.
const directSpawnPATH = "/usr/sbin:/usr/bin:/sbin:/bin"

// directSpawnEnv is the ENTIRE environment a direct-spawned chain gets: vmd's
// own environ carries DATABASE_URL, INTERNAL_API_TOKEN and VMD_* flags, none of
// which may cross the sandbox boundary into Firecracker. Additions are a
// security review, not a convenience.
func directSpawnEnv() []string {
	return []string{
		"PATH=" + directSpawnPATH,
		"RUN_DIR=/var/lib/sandbox/rundir",
	}
}

// prlimitOnLaunchPath reports whether prlimit (which directSpawnScript prepends)
// resolves on the restricted launch PATH — not vmd's PATH, which LookPath would
// search: a prlimit only in e.g. /usr/local/bin would pass LookPath yet break
// every launch.
func prlimitOnLaunchPath() bool { return toolOnPath("prlimit", directSpawnPATH) }

// toolOnPath reports whether an executable named tool exists in one of the
// directories of a PATH-style, os.PathListSeparator-delimited list.
func toolOnPath(tool, path string) bool {
	for _, dir := range filepath.SplitList(path) {
		if fi, err := os.Stat(filepath.Join(dir, tool)); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// directSpawnScript wraps the unit path's script with a prlimit hop pinning
// NOFILE to the service default — without it the chain inherits vmd's 65536 soft
// limit and FC's fd-table preallocation wastes ~0.5MB/VM at fleet density.
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

// openVMConsole opens the per-VM console file the child's stdout/stderr attach
// to (FC logs + panic output). A file, not journald (which rate-limits per unit
// cgroup, letting one VM starve others'), so output survives a vmd restart.
// Bounded by FC's 1 MiB/boot serial cap plus O_TRUNC-per-launch here.
func openVMConsole(runDir, vmID string) (*os.File, error) {
	dir := filepath.Join(runDir, vmID)
	// Defensive: the launch path already MkdirAll's this (via the socket dir);
	// create it here too so we don't depend on that ordering.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir vm console dir: %w", err)
	}
	return os.OpenFile(filepath.Join(dir, "console.log"),
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
func spawnDirect(scriptPath string, cgroupDir, console *os.File) (*exec.Cmd, error) {
	defer cgroupDir.Close()
	// Exec /bin/sh with the script as an argument, not the script directly. A
	// concurrent launch's fork can transiently inherit this freshly-written
	// script's write fd (CLOEXEC closes it at exec, not at fork), and exec'ing a
	// write-open file returns ETXTBSY — an intermittent launch failure under
	// burst. /bin/sh is never written by vmd (never busy) and merely READS the
	// script, so the race can't bite. Behaviorally identical: the script's
	// #!/bin/sh shebang already runs it via /bin/sh, and every stage `exec`s so
	// the chain stays a single PID in the cgroup.
	cmd := exec.Command("/bin/sh", scriptPath)
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
