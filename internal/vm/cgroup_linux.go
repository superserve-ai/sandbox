package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ErrCgroupVMsUnmanageable means the host holds cgroup-supervised VMs (records
// or live groups) but the delegated scope could not be adopted, so those VMs
// are unmanageable. Startup treats this as fatal — never a silent degrade.
var ErrCgroupVMsUnmanageable = errors.New("existing cgroup-mode VMs cannot be managed")

// Direct-spawn cgroup management. VMs live in the shipped, delegated
// superserve-vms.service under sandboxes.slice — sharing the one aggregate
// memory ceiling with the legacy firecracker@ units, while vmd itself stays in
// system.slice outside the VM memory and kill domains. vmd adopts that scope
// (never creates it), moves its keeper into keeper/, enables controllers on the
// root, and gives every direct-spawned VM its own <vmID>/ group. PID 1 is never
// involved per VM — that per-unit serialization is the cost this path deletes.

const (
	cgroupMount = "/sys/fs/cgroup"
	// vmsUnitName is the shipped, delegated systemd service whose subtree holds
	// every direct-spawn VM. It lives under sandboxes.slice, so VMs share the
	// one aggregate memory ceiling with the legacy firecracker@ units, and its
	// subtree is delegated (systemd will not reorganize it). vmd validates and
	// adopts it — never creates it.
	vmsUnitName = "superserve-vms.service"
	// keeperSubdir holds the unit's keeper process, moved out of the delegated
	// root so controllers can be enabled there (cgroup v2 no-internal-process
	// rule). Reserved — never a vmID.
	keeperSubdir = "keeper"
)

// cgroupTree holds the resolved paths of the delegated VM subtree — the
// superserve-vms.service ControlGroup and its keeper leaf.
type cgroupTree struct {
	vms    string // the service ControlGroup; per-VM groups are vms/<id>
	keeper string // vms/keeper — the keeper process's leaf
}

// ArmDirectSpawn enables the cgroup launch path for NEW VMs when the flag is
// set AND the host proves the survival property. Returns (armed, err):
// (false, nil) flag off; (false, err) requested but a precondition failed —
// the caller logs and continues on the unit path; (true, nil) armed.
//
// Preconditions, all fail-closed:
//   - cgroup v2 unified hierarchy (cgroup.kill / cgroup.events exist);
//   - the shipped superserve-vms.service is active, delegated, and rooted
//     under sandboxes.slice — its subtree is where VMs live and share the one
//     aggregate memory ceiling; vmd adopts it, never creates it;
//   - firecracker advertises the serial-console-cap (console bound).
//
// The subtree is adopted whenever the flag is on OR this host already owns
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
	haveCgroupVMs := m.hasCgroupRecords() || delegatedTreeHasVMs(ctx)
	if !wantArm && !haveCgroupVMs {
		return false, nil // nothing to arm, nothing to manage
	}
	if _, err := os.Stat(filepath.Join(cgroupMount, "cgroup.controllers")); err != nil {
		if wantArm {
			return false, fmt.Errorf("cgroup v2 unified hierarchy required: %w", err)
		}
		return false, fmt.Errorf("cgroup-mode VMs exist but cgroup v2 is unavailable: %w", err)
	}
	tree, err := adoptVmsScope(ctx)
	if err != nil {
		if haveCgroupVMs {
			// Existing cgroup-mode VMs but the scope can't be adopted → they are
			// unmanageable. Fatal at the caller, never a silent degrade to ready.
			return false, fmt.Errorf("%w: adopt %s: %v", ErrCgroupVMsUnmanageable, vmsUnitName, err)
		}
		return false, fmt.Errorf("adopt delegated VM scope (%s): %w", vmsUnitName, err)
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
			return false, fmt.Errorf("delegated scope lacks %s (kernel too old?): %w", f, err)
		}
	}
	// A dead keeper leaves the unit "failed"; refuse to arm NEW launches. The
	// scope was still adopted above (systemd keeps a failed-but-populated unit's
	// ControlGroup), so m.cgroups is set and existing VMs stay managed — the
	// keeper-death policy: block new launches, keep servicing the live ones.
	if !unitIsActive(ctx, vmsUnitName) {
		return false, fmt.Errorf("%s is not active — cannot arm direct spawn", vmsUnitName)
	}
	if !unitDelegated(ctx, vmsUnitName) {
		// Without the delegation guarantee, systemd could reorganize the
		// subtree on a daemon-reload and strand VMs. Refuse to arm.
		return false, fmt.Errorf("%s is not Delegate=yes — direct spawn needs a delegated subtree", vmsUnitName)
	}
	// KillMode=process on the vms service is load-bearing: a stop or restart of
	// that unit must signal only the keeper, never cascade into the VM children.
	// Refuse to arm if it drifted from the shipped config.
	if km := unitStringProperty(ctx, vmsUnitName, "Service", "KillMode"); km != "process" {
		return false, fmt.Errorf("%s KillMode=%q, need \"process\" — a scope stop would kill every VM", vmsUnitName, km)
	}
	// The aggregate memory ceiling lives on an ancestor of the scope
	// (sandboxes.slice). If it drifted to unlimited, the reserve that protects
	// the host from OOM is gone. Require a finite memory.max at or above it.
	if !parentMemoryCapped(tree.vms) {
		return false, fmt.Errorf("delegated scope %q has no effective memory ceiling — refusing to arm", tree.vms)
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

// unitStringProperty reads a unit property via D-Bus (Unit interface unless
// iface=="Service"), falling back to systemctl show. Empty on any failure —
// callers treat that as absent/fail-closed.
func unitStringProperty(ctx context.Context, unit, iface, name string) string {
	if val, notLoaded, ok := sdbusUnitProperty(ctx, unit, iface, name); ok && !notLoaded {
		if s, isStr := val.(string); isStr {
			return s
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", name, "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// unitControlGroup resolves a unit's cgroup path as systemd owns it — never
// construct it from the unit name, which systemd escapes and may nest.
func unitControlGroup(ctx context.Context, unit string) string {
	return unitStringProperty(ctx, unit, "Unit", "ControlGroup")
}

// unitIsActive reports whether the unit's ActiveState is "active"; unknown
// reads as not-active (fail-closed).
func unitIsActive(ctx context.Context, unit string) bool {
	return unitStringProperty(ctx, unit, "Unit", "ActiveState") == "active"
}

// unitDelegated reports whether the unit has Delegate set, via D-Bus (fallback
// systemctl). Unknown reads as NOT delegated — fail-closed, so arming never
// proceeds on an unverified subtree.
func unitDelegated(ctx context.Context, unit string) bool {
	if val, notLoaded, ok := sdbusUnitProperty(ctx, unit, "Service", "Delegate"); ok && !notLoaded {
		if b, isBool := val.(bool); isBool {
			return b
		}
	}
	return unitStringProperty(ctx, unit, "Service", "Delegate") == "yes"
}

// delegatedTreeHasVMs reports whether the delegated VM scope already holds a
// per-VM cgroup — including crash-survivors with no BoltDB record. Cheap and
// side-effect-free: resolve the scope path via systemd, ReadDir, skip the
// keeper, tolerate an absent scope (never armed). Complements hasCgroupRecords
// so a rollback still manages an unrecorded survivor.
func delegatedTreeHasVMs(ctx context.Context) bool {
	rel := unitControlGroup(ctx, vmsUnitName)
	if rel == "" {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(cgroupMount, rel))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != keeperSubdir {
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

// adoptVmsScope resolves and prepares the shipped superserve-vms.service
// delegated subtree for direct spawn. It reads the unit's ControlGroup (never
// constructs the path), moves the keeper process into keeper/ so the delegated
// root is free of processes (cgroup v2 no-internal-process rule), and enables
// the memory+pids controllers on that root so per-VM groups get their files.
// No memory.max here: the subtree lives under sandboxes.slice and inherits its
// 95% ceiling hierarchically. Idempotent across vmd restarts, where the keeper
// already sits in keeper/ and controllers are already enabled.
func adoptVmsScope(ctx context.Context) (*cgroupTree, error) {
	rel := unitControlGroup(ctx, vmsUnitName)
	if rel == "" {
		return nil, fmt.Errorf("%s has no ControlGroup (not loaded/active?)", vmsUnitName)
	}
	if !strings.Contains(rel, "/sandboxes.slice/") {
		return nil, fmt.Errorf("%s ControlGroup %q is not under sandboxes.slice", vmsUnitName, rel)
	}
	t := &cgroupTree{
		vms:    filepath.Join(cgroupMount, rel),
		keeper: filepath.Join(cgroupMount, rel, keeperSubdir),
	}
	if err := os.Mkdir(t.keeper, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("mkdir keeper: %w", err)
	}
	// Move any process still in the delegated root (the keeper on first
	// bootstrap; none on a restart) into keeper/, so controllers can be enabled
	// on the now-empty root. Per-VM groups live in vms/<id>, not here.
	pids, err := readCgroupProcs(t.vms)
	if err != nil {
		return nil, fmt.Errorf("read scope root procs: %w", err)
	}
	for _, pid := range pids {
		if err := os.WriteFile(filepath.Join(t.keeper, "cgroup.procs"),
			[]byte(strconv.Itoa(pid)), 0o644); err != nil {
			return nil, fmt.Errorf("move keeper pid %d: %w", pid, err)
		}
	}
	// root's subtree_control gives its children (vms/<id>/) their memory/pids
	// files — so per-VM memory.oom.group exists and createVMCgroup succeeds.
	// The parent sandboxes.slice already exposes memory+pids to this scope; a
	// failure here (it does not) is a fail-closed arm refusal.
	if err := os.WriteFile(filepath.Join(t.vms, "cgroup.subtree_control"),
		[]byte("+memory +pids"), 0o644); err != nil {
		return nil, fmt.Errorf("enable controllers on scope root: %w", err)
	}
	return t, nil
}

// parentMemoryCapped reports whether any cgroup at or above scopePath sets a
// finite memory.max — the effective ceiling that bounds the VM subtree (v2
// enforces memory.max as the min over ancestors). All "max" up to the mount
// root means the aggregate cap drifted away.
func parentMemoryCapped(scopePath string) bool {
	for dir := scopePath; strings.HasPrefix(dir, cgroupMount); dir = filepath.Dir(dir) {
		data, err := os.ReadFile(filepath.Join(dir, "memory.max"))
		if err == nil && strings.TrimSpace(string(data)) != "max" {
			return true
		}
		if dir == cgroupMount {
			break
		}
	}
	return false
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
	if !isLeafName(vmID) || vmID == keeperSubdir {
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
		if e.IsDir() && e.Name() != keeperSubdir {
			ids = append(ids, e.Name())
		}
	}
	return ids, nil
}

// DrainReport summarizes any residual direct-spawn state on a host, so rollback
// tooling can refuse to install a pre-direct-spawn binary that would mishandle
// it. All three counts must be zero to downgrade safely.
type DrainReport struct {
	ScopePath       string // resolved superserve-vms.service ControlGroup ("" if none)
	CgroupRecords   int    // BoltDB records (incl. PAUSED) with Supervision=cgroup
	PerVMDirs       int    // per-VM cgroup directories present (recordless or not)
	PopulatedGroups int    // per-VM cgroups holding a live process
}

// Drained reports whether the host has no direct-spawn state at all.
func (r DrainReport) Drained() bool {
	return r.CgroupRecords == 0 && r.PerVMDirs == 0 && r.PopulatedGroups == 0
}

// CheckDrained inspects a host for residual direct-spawn state before a
// rollback: cgroup-supervised records (including PAUSED ones — no live process,
// invisible to a cgroup scan, yet still mishandled by an old binary on resume),
// leftover per-VM cgroup directories, and populated groups. It reads the store
// read-only, so it fails closed on a missing/locked DB (a running vmd holds the
// lock) rather than falsely reporting drained — run it with vmd stopped. Never
// mutates the store or the cgroup tree.
func CheckDrained(ctx context.Context, statePath string) (DrainReport, error) {
	var r DrainReport
	store, err := OpenStateStoreReadOnly(statePath)
	if err != nil {
		return r, fmt.Errorf("read state (is vmd still running? stop it first): %w", err)
	}
	defer store.Close()
	recs, err := store.All()
	if err != nil {
		return r, fmt.Errorf("read records: %w", err)
	}
	for _, rec := range recs {
		if cgroupSupervised(rec.Supervision) {
			r.CgroupRecords++
		}
	}
	// An absent scope (unit never installed/started) means no per-VM dirs, so
	// conditions 2 and 3 are trivially empty.
	rel := unitControlGroup(ctx, vmsUnitName)
	if rel == "" {
		return r, nil
	}
	r.ScopePath = filepath.Join(cgroupMount, rel)
	entries, err := os.ReadDir(r.ScopePath)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return r, fmt.Errorf("scan scope %s: %w", r.ScopePath, err)
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == keeperSubdir {
			continue
		}
		r.PerVMDirs++
		data, rerr := os.ReadFile(filepath.Join(r.ScopePath, e.Name(), "cgroup.events"))
		if rerr == nil && parseCgroupPopulated(string(data)) {
			r.PopulatedGroups++
		}
	}
	return r, nil
}
