package vm

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Direct-spawn cgroup management. vmd's unit is delegated (Delegate=yes), so
// vmd owns everything below its unit cgroup: it moves itself into daemon/,
// enables controllers on vms/, and gives every direct-spawned VM its own
// vms/<vmID>/ group. PID 1 is never involved per VM — that per-unit
// serialization is the cost this path exists to delete.

const (
	cgroupMount = "/sys/fs/cgroup"
	// vmMemoryMaxFraction of MemTotal caps the vms/ subtree, replacing
	// sandboxes.slice's MemoryMax=95%. vmd itself lives in daemon/, outside
	// the cap — the daemon must never compete with sandboxes for the
	// ceiling that protects it.
	vmMemoryMaxFraction = 0.95
)

// cgroupTree holds the resolved paths of vmd's delegated subtree.
type cgroupTree struct {
	root   string // vmd's own unit cgroup (delegated root)
	daemon string // root/daemon — vmd's processes
	vms    string // root/vms — parent of all per-VM groups
}

// ownCgroupPath resolves this process's cgroup v2 path from
// /proc/self/cgroup ("0::<path>").
func ownCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupMount, rest), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}

// ArmDirectSpawn enables the cgroup launch path for NEW VMs when the flag is
// set AND the host proves the survival property. Returns (armed, err):
// (false, nil) flag off; (false, err) requested but a precondition failed —
// the caller logs and continues on the unit path; (true, nil) armed.
//
// Preconditions, all fail-closed:
//   - cgroup v2 unified hierarchy (cgroup.kill / cgroup.events exist);
//   - the unit configured KillMode=process, or a vmd restart/deploy would
//     SIGKILL every direct-spawned VM — the exact opposite of the property
//     this whole design preserves;
//   - the delegated subtree is usable (setupCgroupTree succeeds, which needs
//     Delegate=yes to write cgroup.subtree_control).
//
// The subtree is set up whenever the flag is on OR this host already owns
// cgroup-mode VMs — otherwise a flag-off rollback would leave m.cgroups nil
// while cgroup VMs still run, and their liveness would read inconclusive
// forever, pause/reconcile could not touch them, and resume would loop on
// "not armed". Only NEW launches are gated by directSpawnArmed; management
// of existing cgroup VMs is always available once any exist.
func (m *Manager) ArmDirectSpawn(ctx context.Context) (bool, error) {
	wantArm := m.cfg.DirectSpawn
	// Manage the subtree if the flag is on, OR any cgroup-mode VM might still
	// exist — from a BoltDB record OR a live per-VM cgroup with no record (a
	// crash between spawn and persist). Detecting only records would strand
	// that unrecorded survivor: m.cgroups nil, so reattach and the reconciler
	// both skip it and it runs forever.
	haveCgroupVMs := m.hasCgroupRecords() || delegatedTreeHasVMs()
	if !wantArm && !haveCgroupVMs {
		return false, nil // nothing to arm, nothing to manage
	}
	if _, err := os.Stat(filepath.Join(cgroupMount, "cgroup.controllers")); err != nil {
		if wantArm {
			return false, fmt.Errorf("cgroup v2 unified hierarchy required: %w", err)
		}
		return false, fmt.Errorf("cgroup-mode VMs exist but cgroup v2 is unavailable: %w", err)
	}
	tree, err := setupCgroupTree()
	if err != nil {
		if wantArm {
			return false, fmt.Errorf("prepare delegated subtree (needs Delegate=yes): %w", err)
		}
		return false, fmt.Errorf("cannot manage existing cgroup-mode VMs: %w", err)
	}
	// Tree is usable: existing cgroup VMs are now manageable regardless of
	// the flag.
	m.cgroups = tree
	if !wantArm {
		return false, nil // manage-only (rollback / drain)
	}
	// cgroup.kill (kernel 5.14+) and cgroup.events are how stop and liveness
	// work; a v2 host too old to have them would launch fine but never be
	// able to stop or reap a VM. Verify on the real tree before arming.
	for _, f := range []string{"cgroup.kill", "cgroup.events"} {
		if _, err := os.Stat(filepath.Join(tree.vms, f)); err != nil {
			return false, fmt.Errorf("delegated tree lacks %s (kernel too old?): %w", f, err)
		}
	}
	if km := selfUnitKillMode(ctx); km != "process" {
		// Managing existing VMs is fine, but a KillMode that would kill the
		// subtree on stop must not gate NEW launches onto it.
		return false, fmt.Errorf("unit KillMode=%q, need \"process\" — direct spawn would die on the next vmd stop", km)
	}
	if !selfUnitDelegated(ctx) {
		// setupCgroupTree may have written subtree_control as root without
		// Delegate, but without the systemd guarantee PID 1 can reorganize
		// the subtree on a daemon-reload and strand VMs. Refuse to arm.
		return false, fmt.Errorf("unit is not Delegate=yes — direct spawn needs a delegated subtree")
	}
	// The guest console is untrusted; the only bound on its file is the
	// Firecracker serial cap. Refuse to arm on a binary that doesn't
	// advertise it, or a direct-spawned guest could fill the host disk.
	if !firecrackerAdvertisesCap(ctx, m.cfg.FirecrackerBin, "serial-console-cap") {
		return false, fmt.Errorf("firecracker %q lacks serial-console-cap — cannot arm direct spawn", m.cfg.FirecrackerBin)
	}
	m.directSpawnArmed.Store(true)
	return true, nil
}

// firecrackerAdvertisesCap reports whether the firecracker binary lists cap
// among the "capability: <name>" lines of its --version output. Fail-closed:
// any exec or read error reads as absent, so arming never proceeds on an
// unverifiable binary. Runs once at arm time, not on the launch path.
func firecrackerAdvertisesCap(ctx context.Context, fcBin, cap string) bool {
	out, err := exec.CommandContext(ctx, fcBin, "--version").Output()
	if err != nil {
		return false
	}
	want := "capability: " + cap
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// selfUnitDelegated reports whether this vmd unit has Delegate set, via
// D-Bus (fallback systemctl). Unknown reads as NOT delegated — fail-closed,
// so arming never proceeds on an unverified subtree.
func selfUnitDelegated(ctx context.Context) bool {
	const unit = "superserve-vmd.service"
	if val, notLoaded, ok := sdbusUnitProperty(ctx, unit, "Service", "Delegate"); ok && !notLoaded {
		if b, isBool := val.(bool); isBool {
			return b
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "Delegate", "--value", unit).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

// delegatedTreeHasVMs reports whether a prior armed life left any per-VM
// cgroup under vms/ — including crash-survivors with no BoltDB record. Cheap
// and side-effect-free: resolve the path, ReadDir, tolerate not-exist (fresh
// host, never armed). Complements hasCgroupRecords so a rollback still
// manages an unrecorded survivor.
func delegatedTreeHasVMs() bool {
	root, err := ownCgroupPath()
	if err != nil {
		return false
	}
	if filepath.Base(root) == "daemon" {
		root = filepath.Dir(root)
	}
	entries, err := os.ReadDir(filepath.Join(root, "vms"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			return true
		}
	}
	return false
}

// hasCgroupRecords reports whether this host has any persisted cgroup-mode
// VM — the signal that the delegated subtree must be initialized for
// management even when the direct-spawn flag is off (a rollback in progress).
func (m *Manager) hasCgroupRecords() bool {
	if m.state == nil {
		return false
	}
	recs, err := m.state.All()
	if err != nil {
		return false
	}
	for _, r := range recs {
		if cgroupSupervised(r.Supervision) {
			return true
		}
	}
	return false
}

// selfUnitKillMode reads this vmd unit's KillMode via D-Bus (falling back to
// systemctl show), returning "" when it cannot be determined — which the
// caller treats as not-process, i.e. fail-closed.
func selfUnitKillMode(ctx context.Context) string {
	const unit = "superserve-vmd.service"
	if val, notLoaded, ok := sdbusUnitProperty(ctx, unit, "Service", "KillMode"); ok && !notLoaded {
		if s, isStr := val.(string); isStr {
			return s
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "KillMode", "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// setupCgroupTree prepares the delegated subtree for direct spawn:
// daemon/ created and every process in the root moved into it (the v2
// no-internal-process rule forbids enabling controllers on a group that
// still holds processes), then vms/ created with memory+pids controllers
// and the host memory cap. Idempotent — safe across vmd restarts, where
// prior-life VM groups already populate vms/.
func setupCgroupTree() (*cgroupTree, error) {
	root, err := ownCgroupPath()
	if err != nil {
		return nil, fmt.Errorf("resolve own cgroup: %w", err)
	}
	// A previous life already moved us into daemon/ — normalize to the root.
	if filepath.Base(root) == "daemon" {
		root = filepath.Dir(root)
	}
	t := &cgroupTree{
		root:   root,
		daemon: filepath.Join(root, "daemon"),
		vms:    filepath.Join(root, "vms"),
	}
	for _, d := range []string{t.daemon, t.vms} {
		if err := os.Mkdir(d, 0o755); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// Move every root-resident process (vmd + any helpers) into daemon/.
	// Writing a PID to cgroup.procs moves all its threads.
	pids, err := readCgroupProcs(t.root)
	if err != nil {
		return nil, fmt.Errorf("read root procs: %w", err)
	}
	for _, pid := range pids {
		if err := os.WriteFile(filepath.Join(t.daemon, "cgroup.procs"),
			[]byte(strconv.Itoa(pid)), 0o644); err != nil {
			return nil, fmt.Errorf("move pid %d to daemon/: %w", pid, err)
		}
	}
	// Enable controllers at BOTH levels. root's subtree_control gives its
	// children (daemon/, vms/) their memory/pids files — so vms/memory.max
	// works. vms's subtree_control is what gives the PER-VM groups
	// (vms/<id>/) their files: without it vms/<id>/memory.oom.group does not
	// exist and createVMCgroup fails on every launch. memory = containment +
	// accounting; pids = a runaway-fork ceiling for free.
	if err := os.WriteFile(filepath.Join(t.root, "cgroup.subtree_control"),
		[]byte("+memory +pids"), 0o644); err != nil {
		return nil, fmt.Errorf("enable controllers on root: %w", err)
	}
	if err := os.WriteFile(filepath.Join(t.vms, "cgroup.subtree_control"),
		[]byte("+memory +pids"), 0o644); err != nil {
		return nil, fmt.Errorf("enable controllers on vms: %w", err)
	}
	if max, err := vmMemoryMaxFromMeminfo(); err == nil {
		if werr := os.WriteFile(filepath.Join(t.vms, "memory.max"),
			[]byte(strconv.FormatUint(max, 10)), 0o644); werr != nil {
			return nil, fmt.Errorf("write vms/memory.max: %w", werr)
		}
	} else {
		return nil, fmt.Errorf("size vms/memory.max: %w", err)
	}
	return t, nil
}

// vmMemoryMaxFromMeminfo returns vmMemoryMaxFraction of MemTotal in bytes.
func vmMemoryMaxFromMeminfo() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if kb, ok := parseMemTotalKB(sc.Text()); ok {
			return uint64(float64(kb*1024) * vmMemoryMaxFraction), nil
		}
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// parseMemTotalKB parses a /proc/meminfo "MemTotal: N kB" line.
func parseMemTotalKB(line string) (uint64, bool) {
	rest, ok := strings.CutPrefix(line, "MemTotal:")
	if !ok {
		return 0, false
	}
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return 0, false
	}
	kb, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return kb, true
}

func readCgroupProcs(dir string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, s := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(s); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// vmCgroupDir returns the per-VM cgroup path for vmID.
func (t *cgroupTree) vmCgroupDir(vmID string) string {
	return filepath.Join(t.vms, vmID)
}

// firstPID returns any one live PID in the VM's cgroup, or 0 if empty/missing.
// Used to recover an untracked survivor's netns from its process before the
// kill removes the last handle to it.
func (t *cgroupTree) firstPID(vmID string) int {
	pids, err := readCgroupProcs(t.vmCgroupDir(vmID))
	if err != nil || len(pids) == 0 {
		return 0
	}
	return pids[0]
}

// createVMCgroup makes the per-VM group and returns an open directory fd
// for CLONE_INTO_CGROUP (SysProcAttr.CgroupFD): the child is created
// directly inside the group, so there is no fork-to-move window at all.
// memory.oom.group makes an OOM kill take the whole VM, never a lone
// thread of it.
// safeVMCgroupDir resolves the per-VM cgroup path, rejecting a vmID that
// isn't a leaf name. A traversal like "../daemon" would otherwise escape the
// vms/ subtree onto vmd's own group, and a kill there would take the daemon
// down with the VM. Defense-in-depth behind the launch-entry check.
func (t *cgroupTree) safeVMCgroupDir(vmID string) (string, error) {
	if !isLeafName(vmID) {
		return "", fmt.Errorf("invalid vm_id %q for cgroup path", vmID)
	}
	return t.vmCgroupDir(vmID), nil
}

func (t *cgroupTree) createVMCgroup(vmID string) (*os.File, error) {
	dir, err := t.safeVMCgroupDir(vmID)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("mkdir vm cgroup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.oom.group"), []byte("1"), 0o644); err != nil {
		return nil, fmt.Errorf("set oom.group: %w", err)
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open vm cgroup dir: %w", err)
	}
	return f, nil
}

// vmCgroupPopulated reports whether the VM's cgroup holds any live process.
// (false, nil) on a missing group — a removed group is definitively empty.
// Read errors OTHER than not-exist return the error: callers on kill/reap
// paths must treat an unreadable answer as "maybe alive", mirroring the
// unit oracle's inconclusive-reads-alive rule, or an overloaded host reaps
// live VMs.
func (t *cgroupTree) vmCgroupPopulated(vmID string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(t.vmCgroupDir(vmID), "cgroup.events"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return parseCgroupPopulated(string(data)), nil
}

// parseCgroupPopulated parses a cgroup.events body ("populated 0|1\n...").
func parseCgroupPopulated(events string) bool {
	for _, line := range strings.Split(events, "\n") {
		if rest, ok := strings.CutPrefix(line, "populated "); ok {
			return strings.TrimSpace(rest) == "1"
		}
	}
	return false
}

// killVMCgroup SIGKILLs every process in the VM's group (one atomic write)
// and waits until the group reads empty. SIGKILL is asynchronous for a
// UFFD-blocked Firecracker — it holds its netns and tap until it actually
// exits — so returning before populated==0 would resurrect the tap-busy
// failure class the network pool's verify discipline exists to prevent.
// The wait is event-driven (inotify on cgroup.events) with a poll floor.
func (t *cgroupTree) killVMCgroup(ctx context.Context, vmID string, budget time.Duration) error {
	dir, derr := t.safeVMCgroupDir(vmID)
	if derr != nil {
		return derr
	}
	err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644)
	if os.IsNotExist(err) {
		return nil // group already gone == already dead
	}
	if err != nil {
		return fmt.Errorf("cgroup.kill %s: %w", vmID, err)
	}
	deadline := time.Now().Add(budget)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	watcher, werr := fsnotify.NewWatcher()
	if werr == nil {
		defer watcher.Close()
		if watcher.Add(filepath.Join(dir, "cgroup.events")) != nil {
			watcher = nil
		}
	} else {
		watcher = nil
	}
	// Poll floor covers missed events and the no-watcher fallback; the
	// common case resolves on the first inotify wake.
	const pollFloor = 50 * time.Millisecond
	for {
		populated, perr := t.vmCgroupPopulated(vmID)
		if perr == nil && !populated {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("cgroup %s still populated after kill budget %s", vmID, budget)
		}
		wait := pollFloor
		if remaining < wait {
			wait = remaining
		}
		if watcher != nil {
			select {
			case <-watcher.Events:
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// removeVMCgroup rmdirs the VM's group. The kernel can lag rmdir briefly
// after the last exit; bounded retries absorb that, and the reconciler
// sweeps any straggler.
func (t *cgroupTree) removeVMCgroup(vmID string) error {
	dir, derr := t.safeVMCgroupDir(vmID)
	if derr != nil {
		return derr
	}
	var err error
	for i := 0; i < 20; i++ {
		err = os.Remove(dir)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("rmdir vm cgroup %s: %w", vmID, err)
}

// scanVMCgroups returns the vmIDs of every per-VM group currently present,
// populated or not. Reattach and the reconciler's active-set union consume
// this; an error must abort the caller's pass (fail closed) — an empty
// answer from a failed scan would present every cgroup VM as dead.
func (t *cgroupTree) scanVMCgroups() ([]string, error) {
	entries, err := os.ReadDir(t.vms)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	return ids, nil
}
