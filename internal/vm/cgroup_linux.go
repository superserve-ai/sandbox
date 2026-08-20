package vm

import (
	"bufio"
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

// errScopeGone marks a launch failure caused by the delegated VM scope
// itself being absent — the only failure the dispatch may answer with a
// unit-supervision fallback.
var errScopeGone = errors.New("delegated vm scope missing")

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
	// A state-store read failure is FATAL: a corrupt/unreadable BoltDB means the
	// daemon can't load any VM record (reattach and the reconciler both fail),
	// so coming up "ready" would hide it and leave every cgroup VM unmanaged.
	tScan := time.Now()
	hasRecords, rerr := m.hasCgroupRecords()
	if rerr != nil {
		return false, fmt.Errorf("%w: cannot read state store: %v", ErrCgroupVMsUnmanageable, rerr)
	}
	haveCgroupVMs := hasRecords
	if !haveCgroupVMs {
		// A scope read error (transient systemctl/D-Bus) can't rule out a
		// recordless survivor. Fail closed — assume present — so the management-
		// critical checks below run; a persistent scope fault then becomes fatal
		// via adoptVmsScope rather than crashlooping a healthy flag-off host here.
		treeHas, terr := delegatedTreeHasVMs(ctx)
		if terr != nil {
			haveCgroupVMs = true
		} else {
			haveCgroupVMs = treeHas
		}
	}
	// Detection (record + delegated-tree scan) split from the systemd/cgroup
	// validation below, for startup timing. Async: the write must not sit on
	// the startup path.
	detectDur := time.Since(tScan)
	haveVMs := haveCgroupVMs
	go func() {
		m.log.Info().Dur("cgroup_detect_ms", detectDur).Bool("has_cgroup_vms", haveVMs).
			Msg("cgroup arm: detection scan")
	}()
	if !wantArm && !haveCgroupVMs {
		return false, nil // nothing to arm, nothing to manage
	}

	// A management-critical failure means existing cgroup VMs can't be stopped,
	// reaped, or adopted. That is FATAL when this host has them (they would run
	// unmanaged while the daemon reports ready); on a host with none it's an
	// ordinary error that degrades NEW launches to the unit path.
	fatalIfManaging := func(err error) error {
		if haveCgroupVMs {
			return fmt.Errorf("%w: %v", ErrCgroupVMsUnmanageable, err)
		}
		return err
	}

	// --- Management-critical: must hold BEFORE declaring existing cgroup VMs
	// manageable, so manage-only mode never claims a VM it cannot stop. ---
	// The breadcrumb first: the rollback guard finds the store only through
	// it, and a paused fleet leaves no live cgroup dirs — the record scan is
	// then the guard's ONLY evidence. Operating (or creating) cgroup records
	// with a failed or stale breadcrumb would let a later rollback scan the
	// wrong path, read "drained", and install a binary that mishandles them.
	if m.state != nil {
		if err := WriteStateBreadcrumb(m.state.Path()); err != nil {
			return false, fatalIfManaging(fmt.Errorf("record state path for the rollback guard: %w", err))
		}
	}
	if _, err := os.Stat(filepath.Join(cgroupMount, "cgroup.controllers")); err != nil {
		return false, fatalIfManaging(fmt.Errorf("cgroup v2 unified hierarchy required: %w", err))
	}
	tree, err := adoptVmsScope(ctx)
	if err != nil {
		return false, fatalIfManaging(fmt.Errorf("adopt delegated VM scope (%s): %w", vmsUnitName, err))
	}
	// cgroup.kill (kernel 5.14+) and cgroup.events are how stop and liveness
	// work; a v2 host too old to have them could never stop or reap a VM.
	for _, f := range []string{"cgroup.kill", "cgroup.events"} {
		if _, err := os.Stat(filepath.Join(tree.vms, f)); err != nil {
			return false, fatalIfManaging(fmt.Errorf("delegated scope lacks %s (kernel too old?): %w", f, err))
		}
	}
	m.cgroups = tree // existing cgroup VMs are now manageable

	// Run the launch validations in manage-only mode too (flag off here
	// implies cgroup VMs exist): a record's relaunch forks a new FC just
	// like a fresh create, and a failure must refuse it, never spawn
	// unvalidated.
	verr := m.validateDirectLaunchPath(ctx, tree)
	if verr == nil {
		m.launchPathValidated.Store(true)
	} else if !wantArm {
		m.log.Warn().Err(verr).Msg("direct launch path failed validation — cgroup VM resumes will refuse until repaired")
	}
	if !wantArm {
		return false, nil // manage-only (rollback / drain)
	}
	if verr != nil {
		return false, verr
	}
	// Arming is what first creates VMs an old binary cannot manage, so the
	// downgrade protection must provably exist BEFORE the hazard does: refuse
	// to arm unless the host-resident guard and its drop-in are installed.
	// Manage-only mode is deliberately not gated: existing cgroup VMs must
	// stay manageable even on a host that somehow lost its guard.
	if gerr := rollbackGuardInstalled(); gerr != nil {
		return false, fmt.Errorf("host rollback guard not installed — refusing to arm: %w", gerr)
	}
	m.directSpawnArmed.Store(true)
	return true, nil
}

// validateDirectLaunchPath verifies everything a NEW direct-spawned process
// depends on, beyond what managing existing ones needs: the keeper's survival
// property, the shared memory/pids ceilings, the capped-console Firecracker,
// and the launch tooling. Gates arming and cgroup relaunches alike.
func (m *Manager) validateDirectLaunchPath(ctx context.Context, tree *cgroupTree) error {
	// A dead keeper leaves the unit "failed"; refuse NEW launches. The scope
	// was still adopted (systemd keeps a failed-but-populated unit's
	// ControlGroup), so existing VMs stay managed — block new, service the live.
	if !unitIsActive(ctx, vmsUnitName) {
		return fmt.Errorf("%s is not active — cannot arm direct spawn", vmsUnitName)
	}
	if !unitDelegated(ctx, vmsUnitName) {
		return fmt.Errorf("%s is not Delegate=yes — direct spawn needs a delegated subtree", vmsUnitName)
	}
	// KillMode=process on the vms service is load-bearing: a stop/restart of it
	// must signal only the keeper, never cascade into the VM children.
	if km := unitStringProperty(ctx, vmsUnitName, "Service", "KillMode"); km != "process" {
		return fmt.Errorf("%s KillMode=%q, need \"process\" — a scope stop would kill every VM", vmsUnitName, km)
	}
	// sandboxes.slice is the single ceiling both legacy and direct VMs share; a
	// drifted, missing, or ineffective cap removes the OOM reserve.
	if !sandboxesSliceReserved() {
		return fmt.Errorf("sandboxes.slice has no effective memory ceiling with a host reserve — refusing to arm")
	}
	// Every direct VM's threads share the vms service's ONE pids ceiling
	// (per-unit VMs each had their own), and systemd's derived TasksMax
	// default is host-size dependent — small hosts inherit a cap that binds
	// as clone3 EAGAIN at create. The shipped unit sets TasksMax=infinity;
	// validate the effective value on the layers this repo owns.
	for _, p := range []string{
		filepath.Join(tree.vms, "pids.max"),
		filepath.Join(cgroupMount, "sandboxes.slice", "pids.max"),
	} {
		data, perr := os.ReadFile(p)
		if perr != nil {
			if os.IsNotExist(perr) {
				continue // pids controller not enabled at this layer: no bound
			}
			return fmt.Errorf("read %s: %w — refusing to arm", p, perr)
		}
		if !pidsCeilingAdequate(string(data)) {
			return fmt.Errorf("%s = %q caps the fleet's shared task count — set TasksMax=infinity on %s; refusing to arm",
				p, strings.TrimSpace(string(data)), vmsUnitName)
		}
	}
	// The guest console is untrusted; the only bound on its file is the
	// Firecracker serial cap. Refuse a binary that doesn't advertise it, or a
	// direct-spawned guest could fill the host disk.
	if !firecrackerAdvertisesCap(ctx, m.cfg.FirecrackerBin, "serial-console-cap") {
		return fmt.Errorf("firecracker %q lacks serial-console-cap — cannot arm direct spawn", m.cfg.FirecrackerBin)
	}
	// directSpawnScript prepends prlimit to every launch; if it's absent from
	// the restricted launch PATH the chain exits before Firecracker starts.
	// Validate it here — like unshare/nsenter, it's a mandatory launch tool —
	// so arming refuses rather than routing every create/resume through a path
	// that silently fails.
	if !prlimitOnLaunchPath() {
		return fmt.Errorf("prlimit not found on the direct-spawn launch PATH (%s) — every direct launch would exit before firecracker; refusing to arm", directSpawnPATH)
	}
	return nil
}

// rollbackGuardDropInPath is where the deploy installs the guard's
// ExecStartPre drop-in. Kept in lockstep with deploy-vmd.py and
// deploy/superserve-vmd-rollback-guard.conf.
const rollbackGuardDropInPath = "/etc/systemd/system/superserve-vmd.service.d/10-rollback-guard.conf"

// rollbackGuardInstalled verifies the host-resident downgrade guard exists:
// the guard script beside this binary (the deploy installs both to the same
// dir) and its ExecStartPre drop-in. A var for tests.
var rollbackGuardInstalled = func() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own binary path: %w", err)
	}
	return checkRollbackGuard(filepath.Join(filepath.Dir(self), "vmd-rollback-guard"), rollbackGuardDropInPath)
}

// checkRollbackGuard is rollbackGuardInstalled's testable core: the script
// must exist and be executable, the drop-in must exist.
func checkRollbackGuard(script, dropIn string) error {
	fi, err := os.Stat(script)
	if err != nil {
		return fmt.Errorf("guard script %s: %w", script, err)
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("guard script %s is not executable", script)
	}
	if _, err := os.Stat(dropIn); err != nil {
		return fmt.Errorf("guard drop-in %s: %w", dropIn, err)
	}
	return nil
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
// construct it from the unit name, which systemd escapes and may nest. Returns
// ("", nil) when the unit is definitively absent or has no cgroup, and ("", err)
// when the lookup itself failed (D-Bus unavailable AND systemctl errored) so
// safety callers can fail closed instead of mistaking a query failure for an
// absent scope.
func unitControlGroup(ctx context.Context, unit string) (string, error) {
	if val, notLoaded, handled := sdbusUnitProperty(ctx, unit, "Unit", "ControlGroup"); handled {
		if notLoaded {
			return "", nil // definitively not loaded → no cgroup
		}
		if s, isStr := val.(string); isStr {
			return s, nil
		}
		// handled but unexpected value type — fall through to systemctl.
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "ControlGroup", "--value", unit).Output()
	if err != nil {
		return "", fmt.Errorf("resolve %s ControlGroup: %w", unit, err)
	}
	return strings.TrimSpace(string(out)), nil
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
func delegatedTreeHasVMs(ctx context.Context) (bool, error) {
	rel, err := unitControlGroup(ctx, vmsUnitName)
	if err != nil {
		return false, err // query failed → caller fails closed
	}
	if rel == "" {
		return false, nil // scope definitively absent → no cgroup VMs under it
	}
	entries, err := os.ReadDir(filepath.Join(cgroupMount, rel))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err // scope exists but unreadable — caller fails closed
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != keeperSubdir {
			return true, nil
		}
	}
	return false, nil
}

// hasCgroupRecords reports whether this host has any persisted cgroup-mode
// VM — the signal that the delegated subtree must be initialized for
// management even when the direct-spawn flag is off (a rollback in progress).
func (m *Manager) hasCgroupRecords() (bool, error) {
	if m.state == nil {
		return false, nil
	}
	return m.state.HasCgroupRecords()
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
	rel, err := unitControlGroup(ctx, vmsUnitName)
	if err != nil {
		return nil, err
	}
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
	// root's subtree_control gives its children (vms/<id>/) their controller
	// files. memory+pids are REQUIRED — per-VM memory.oom.group must exist or
	// createVMCgroup fails — so a failure here is a fail-closed arm refusal.
	subtree := filepath.Join(t.vms, "cgroup.subtree_control")
	if err := os.WriteFile(subtree, []byte("+memory +pids"), 0o644); err != nil {
		return nil, fmt.Errorf("enable memory/pids on scope root: %w", err)
	}
	// cpu+io make each per-VM cgroup its OWN scheduling domain at the default
	// weight 100 — one peer of every other direct VM and of each legacy
	// firecracker@ unit, the per-VM isolation adjustDirectSpawnWeight assumes.
	// Best-effort: a kernel that can't delegate them leaves per-VM CPU to
	// CFS (per-thread) as before, which is a fairness downgrade, not a
	// safety one — never worth refusing to arm over.
	_ = os.WriteFile(subtree, []byte("+cpu +io"), 0o644)
	return t, nil
}

// sandboxesSliceReserved reports whether sandboxes.slice — the single ceiling
// both legacy and direct VMs share — has a finite memory.max that leaves a host
// reserve. It checks the slice SPECIFICALLY (a service-local cap under an
// unlimited slice would not hold the two populations together) and rejects a
// finite-but-ineffective cap that leaves almost no headroom (e.g. 100% of host).
// Fail-closed: any unreadable value refuses arming. The exact reserve fraction
// is an ops choice; this only proves a meaningful ceiling exists.
func sandboxesSliceReserved() bool {
	data, err := os.ReadFile(filepath.Join(cgroupMount, "sandboxes.slice", "memory.max"))
	if err != nil {
		return false
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return false
	}
	max, err := strconv.ParseUint(s, 10, 64)
	if err != nil || max == 0 {
		return false
	}
	total, err := hostMemTotalBytes()
	if err != nil {
		return false
	}
	return capLeavesReserve(max, total)
}

// minDirectSpawnPids is the smallest numeric pids.max accepted at arm time:
// the fleet ceiling is a few thousand VMs at roughly a dozen tasks each
// (VMM + vCPUs + API), so 64k gives at least 2x headroom while rejecting
// the small-host class of systemd's derived TasksMax default.
const minDirectSpawnPids = 65536

// pidsCeilingAdequate parses a cgroup pids.max value: "max" (unbounded) or a
// numeric bound with fleet headroom passes; anything else — including an
// unparseable value — fails closed.
func pidsCeilingAdequate(s string) bool {
	s = strings.TrimSpace(s)
	if s == "max" {
		return true
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n >= minDirectSpawnPids
}

// capLeavesReserve reports whether a memory.max of max bytes leaves a host
// reserve against total RAM — reject a cap sitting at (or within ~2% of) total,
// which provides no effective reserve. The shipped 95% passes with margin.
func capLeavesReserve(max, total uint64) bool {
	return max > 0 && max <= total*98/100
}

// hostMemTotalBytes returns MemTotal from /proc/meminfo in bytes.
func hostMemTotalBytes() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) >= 1 {
			if kb, perr := strconv.ParseUint(fields[0], 10, 64); perr == nil {
				return kb * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
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
		if os.IsNotExist(err) {
			// The parent scope is gone (keeper died, drained scope GC'd) —
			// the ONE condition the launch dispatch may fall back to unit
			// supervision on. A dedicated sentinel, not bare fs.ErrNotExist:
			// later launch stages (socket waits) can wrap ENOENT too, and a
			// transient failure there must not convert the VM's mode.
			return nil, fmt.Errorf("%w: mkdir vm cgroup: %v", errScopeGone, err)
		}
		return nil, fmt.Errorf("mkdir vm cgroup: %w", err)
	}
	// Failures past the mkdir remove the group: nothing was cloned into it,
	// and a leftover empty dir behind a persisted record is invisible to the
	// empty-group reap (which skips recorded IDs) yet blocks drain-check.
	if err := os.WriteFile(filepath.Join(dir, "memory.oom.group"), []byte("1"), 0o644); err != nil {
		_ = os.Remove(dir)
		return nil, fmt.Errorf("set oom.group: %w", err)
	}
	f, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
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
	return parseCgroupPopulated(string(data))
}

// parseCgroupPopulated parses a cgroup.events body. Only an explicit
// "populated 0" or "populated 1" is conclusive; a missing or malformed line
// is an error so callers treat the read as maybe-alive, never as empty.
func parseCgroupPopulated(events string) (bool, error) {
	for _, line := range strings.Split(events, "\n") {
		if rest, ok := strings.CutPrefix(line, "populated "); ok {
			switch strings.TrimSpace(rest) {
			case "1":
				return true, nil
			case "0":
				return false, nil
			default:
				return false, fmt.Errorf("malformed cgroup.events line %q", line)
			}
		}
	}
	return false, fmt.Errorf("no populated line in cgroup.events")
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
func (t *cgroupTree) removeVMCgroup(ctx context.Context, vmID string) error {
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
		// Interruptible so a shutdown-time reconciler sweep isn't stuck here;
		// cleanup callers pass a detached ctx so an expired launch deadline
		// can't abandon the rmdir and leak the group.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
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
		// != unit, not == cgroup: an UNKNOWN mode (written by a newer binary)
		// must also block the rollback — the old binary can't manage it either.
		if rec.Supervision != SupervisionUnit {
			r.CgroupRecords++
		}
	}
	// An absent scope (unit never installed/started) means no per-VM dirs, so
	// conditions 2 and 3 are trivially empty. A lookup FAILURE, though, must not
	// read as "drained" — propagate it so the guard blocks the downgrade.
	rel, err := unitControlGroup(ctx, vmsUnitName)
	if err != nil {
		return r, err
	}
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
		if rerr != nil && os.IsNotExist(rerr) {
			continue // group removed mid-scan: conclusively no live process
		}
		if pop, perr := parseCgroupPopulated(string(data)); rerr != nil || perr != nil || pop {
			r.PopulatedGroups++ // unreadable/malformed reads maybe-alive
		}
	}
	return r, nil
}
