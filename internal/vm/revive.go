package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReviveVM cold-boots a sandbox whose VM died, from a salvaged copy of
// its own disk. The salvaged image carries the sandbox's identity (its
// boxd config, workspace, everything it wrote), so unlike a template
// clone nothing is re-injected: the guest boots as itself, on a fresh
// network slot. Residue of the dead VM (run dir, unit or cgroup,
// network slot) is force-torn-down first through the same path
// DestroyVM uses, so revive is safe on a zombie whose process is gone
// but whose slot state remains. The salvage is copied, never booted in
// place: a failed revive leaves it pristine for retry.
//
// The caller owns the control-plane side: the DB row flips to active
// only after this returns, and the ordinary auto-pause machinery then
// takes the revived sandbox through the standard pause path, which is
// what lands it paused with a fresh, uploaded generation.
func (m *Manager) ReviveVM(ctx context.Context, vmID, diskPath, basePath string, vcpu, memMiB uint32, rules *sandboxNetworkRules) (*VMInstance, error) {
	if !isLeafName(vmID) || isReservedRunDirName(vmID) {
		return nil, status.Error(codes.InvalidArgument, "vm_id must be a valid per-VM identifier")
	}
	fi, err := os.Stat(diskPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path %q is not a regular file", diskPath)
	}
	// The whole revival transaction holds the VM's lifecycle lock:
	// without it, two concurrent revives for one id can interleave so
	// that the loser's teardown destroys the winner's freshly booted VM.
	// DestroyVM deliberately does not take this lock, so calling it
	// below cannot deadlock.
	unlock, err := m.lockVMOp(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Never revive over a live or healthy VM. A paused VM with its
	// snapshot is healthy at rest and refused: resume owns that path.
	if inst, err := m.getInstance(vmID); err == nil {
		inst.mu.RLock()
		st, snap, mem, baseMem := inst.Status, inst.SnapshotPath, inst.MemFilePath, inst.BaseMemPath
		inst.mu.RUnlock()
		if st == StatusPaused && snap != "" {
			// The refusal delegates to resume, so it only holds when
			// resume is actually possible: every recorded pause artifact
			// must still exist. A paused record whose snapshot or memory
			// file is gone is unresumable, and refusing revival too
			// would strand a sandbox that has a usable salvaged disk.
			if statRegularFile(snap) && mem != "" && statRegularFile(mem) && (baseMem == "" || statRegularFile(baseMem)) {
				return nil, status.Errorf(codes.FailedPrecondition, "vm %s is paused with a snapshot; resume owns healthy paused VMs", vmID)
			}
			m.log.Warn().Str("vm_id", vmID).Msg("paused record has missing snapshot artifacts; treating as unresumable and allowing revival")
		}
	}
	// Liveness comes from the supervisors, not the record or a PID: the
	// record is exactly what a zombie lies about, and a live
	// systemd-supervised VM can carry PID 0 while its MainPID resolves
	// asynchronously. vmConfirmedAtRest requires BOTH possible
	// supervisors terminally quiet, so a genuinely running VM of either
	// mode refuses here rather than being torn down as a zombie.
	if !m.vmConfirmedAtRest(ctx, vmID) {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s is not confirmed at rest; revive only replaces dead VMs", vmID)
	}
	// The zombie's durable record carries policy that must survive
	// revival: preview publication (a private preview must not come
	// back public) and ownership. Captured before the teardown deletes
	// the record; absence is fine, the fields stay zero for sandboxes
	// that never set policy.
	var prevRec *VMRecord
	if m.state != nil {
		if rec, err := m.state.Get(vmID); err == nil {
			prevRec = rec
		}
	}
	// Revival replaces a sandbox the platform knows. Without a durable
	// record (a mistyped or foreign id), proceeding would mint a
	// brand-new VM with no control-plane row: unroutable, unbilled, and
	// invisible until the reconciler flags it. Sandboxes whose record
	// was genuinely lost recover through host restore, not revive.
	if prevRec == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %s has no durable record on this host; revive only replaces known sandboxes", vmID)
	}

	// Overlay-mode sandboxes salvage as sparse overlays whose holes are
	// windows to a shared base image; booting one standalone would read
	// every hole as zeros and corrupt the guest's filesystem. The base
	// comes from the request or, absent there, the zombie's own durable
	// record, and when neither names one the disk boots standalone
	// (legacy full-image sandboxes). A named base must exist.
	if basePath == "" && prevRec != nil {
		basePath = prevRec.BasePath
	}
	if basePath != "" {
		bfi, err := os.Stat(basePath)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "base_path: %v", err)
		}
		if !bfi.Mode().IsRegular() {
			return nil, status.Errorf(codes.InvalidArgument, "base_path %q is not a regular file", basePath)
		}
	}

	// The salvage must live outside the zombie's run directory: the
	// forced teardown below removes that directory, and a salvage
	// inside it would be deleted before the boot could copy it.
	// Symlinks resolve first so a link cannot smuggle the source in.
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path: %v", err)
	}
	vmRunDir := filepath.Join(m.cfg.RunDir, vmID) + string(filepath.Separator)
	if strings.HasPrefix(resolved+string(filepath.Separator), vmRunDir) || strings.HasPrefix(resolved, vmRunDir) {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path %q is inside the VM's run directory, which revival deletes; copy the salvage elsewhere first", diskPath)
	}
	diskPath = resolved
	// The base dies in the same teardown if it lives inside the run
	// directory: revival would delete it, boot a broken overlay, and
	// restore a record pointing at a file that no longer exists.
	if basePath != "" {
		resolvedBase, berr := filepath.EvalSymlinks(basePath)
		if berr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "base_path: %v", berr)
		}
		if strings.HasPrefix(resolvedBase+string(filepath.Separator), vmRunDir) || strings.HasPrefix(resolvedBase, vmRunDir) {
			return nil, status.Errorf(codes.InvalidArgument, "base_path %q is inside the VM's run directory, which revival deletes; stage the base elsewhere first", basePath)
		}
		basePath = resolvedBase
	}

	reviveStart := time.Now()
	// Force-clear the zombie's residue. Fail closed on error: booting
	// over half-cleared state (a live unit, an occupied network slot)
	// is exactly the wedge class the teardown exists to prevent.
	if err := m.DestroyVM(ctx, vmID, true); err != nil {
		return nil, fmt.Errorf("clear residue: %w", err)
	}
	// The teardown above deleted the zombie's durable record, and a
	// failed boot may persist a fresh partial one. Until the revived VM
	// is durably recorded, any exit restores the original record: a
	// failed attempt must stay retryable (revival requires a known
	// record) and must not lose ownership, preview policy, shape, or
	// base metadata.
	committed := false
	// Every destroy this revival performs is counted; the rollback
	// compares the completed-destroy epoch against its own count, so an
	// external destroy that fully completed in between (tombstone
	// already cleared) is visible and owns the record's absence.
	selfDestroys := uint64(0)
	epochBase := m.destroyEpoch(vmID)
	// A teardown that cannot confirm the replacement stopped must also
	// suppress the rollback: restoring the zombie record over a
	// still-live unready VM would lie about the host's state, and
	// DestroyVM's own failure discipline already leaves a truthful
	// teardown-pending record for the forced retry.
	teardownFailed := false
	teardownSelf := func(c context.Context) {
		selfDestroys++
		if derr := m.DestroyVM(c, vmID, true); derr != nil {
			teardownFailed = true
			m.log.Error().Err(derr).Str("vm_id", vmID).Msg("teardown after failed revival did not confirm; record left as-is")
		}
	}
	defer func() {
		if committed || teardownFailed || m.state == nil {
			return
		}
		// The record-owner mutex makes the checks and the restore one
		// unit against DestroyVM, which holds it through its epoch bump
		// and tombstone clear: a destroy in flight is waited out and
		// then seen by the epoch, and one starting later blocks until
		// this write lands and then deletes it (the destroy wins). An
		// external destroy owns the record's absence either way.
		unlockOwner := m.lockRecordOwner(vmID)
		defer unlockOwner()
		if _, destroying := m.destroying.Load(vmID); destroying {
			return
		}
		if m.destroyEpoch(vmID) != epochBase+selfDestroys {
			return
		}
		if perr := m.state.Put(*prevRec); perr != nil {
			m.log.Error().Err(perr).Str("vm_id", vmID).Msg("restore zombie record after failed revival")
		}
	}()
	teardownDur := time.Since(reviveStart)
	// The revived VM lives under the fleet's real supervision, seeded
	// from the zombie's recorded mode (default unit for records that
	// predate the mode field): auto-pause's mode-directed stop and every
	// at-rest oracle must see this VM the way they see any sandbox, and
	// an unsupervised spawn would read as at-rest while running.
	supervision := prevRec.Supervision
	if !knownSupervision(supervision) {
		supervision = SupervisionUnit
	}
	// Omitted shape means the sandbox's own recorded shape, not the
	// cold-boot fallback of 1 vCPU and 1 GiB: a larger workload revived
	// undersized would report clean and then fail under its normal load.
	if vcpu == 0 {
		vcpu = prevRec.VCPU
	}
	if memMiB == 0 {
		memMiB = prevRec.MemoryMiB
	}
	phaseStart := time.Now()
	// Egress rules ride into the boot itself so they install before the
	// guest executes (resume's ordering); the rules travel on the
	// request, the control plane owns them, exactly as ResumeVM's do.
	// The zombie's policy and ownership seed the instance before it is
	// visible or persisted, and the record stays Unverified until the
	// guest proves itself: every intermediate durable write then carries
	// full metadata, and a vmd crash during the boot or readiness wait
	// leaves a record reattachment refuses to adopt as a live serving VM
	// rather than one that trusts an unverified guest or reads empty
	// preview policy as legacy-public.
	seed := func(inst *VMInstance) {
		inst.Unverified = true
		inst.TeamID = prevRec.TeamID
		inst.OwnerID = prevRec.OwnerID
		inst.PreviewAccess = prevRec.PreviewAccess
		inst.PreviewPorts = previewPortsFromRecord(prevRec.PreviewPorts, prevRec.PreviewPortAccess, prevRec.PreviewPortTokenVersions)
		inst.PreviewPolicyRevision = prevRec.PreviewPolicyRevision
		inst.PreviewTokenPolicyRevision = prevRec.PreviewTokenPolicyRevision
	}
	inst, err := m.coldBootFromRootfs(ctx, vmID, diskPath, basePath, rules, seed, true, supervision, vcpu, memMiB)
	if err != nil {
		return nil, err
	}
	bootDur := time.Since(phaseStart)
	inst.mu.RLock()
	ip := inst.IP
	inst.mu.RUnlock()
	// Revival is only real when the guest is: Firecracker accepting the
	// boot proves nothing about a corrupt or incompatible salvaged disk,
	// and reporting success on a wedged guest would flip the DB row to
	// active for a sandbox nobody can reach. On failure, tear the VM
	// back down so the retry starts clean and the salvage stays
	// pristine.
	phaseStart = time.Now()
	if err := m.waitForBoxd(ctx, ip, reviveBoxdReadyBudget); err != nil {
		// Teardown must not run under the RPC's possibly-expired
		// context: a canceled stop leaves exactly the half-cleared state
		// revival exists to avoid.
		teardownSelf(context.WithoutCancel(ctx))
		if teardownFailed {
			return nil, status.Errorf(codes.Internal, "guest did not become ready (%v) and teardown did not confirm; VM left for forced destroy", err)
		}
		return nil, status.Errorf(codes.Unavailable, "guest did not become ready: %v", err)
	}
	// The guest proved itself; the durable record may now claim a
	// verified running VM.
	inst.mu.Lock()
	inst.Unverified = false
	inst.mu.Unlock()
	// Durable record: reattach and the reconciler must know this VM
	// after a vmd restart, exactly like any created VM. A revival the
	// state store cannot record is not a revival: an unrecorded running
	// VM would be invisible to reconciliation and refused by the next
	// revive's liveness probe, so fail closed and tear down.
	wrote := m.persistState(inst)
	// Post-write ownership recheck, resume's discipline: a concurrent
	// force-destroy can complete during the readiness wait, and the
	// write above would then resurrect a Running record for a VM that
	// no longer exists. The destroy owns the outcome, so delete the
	// resurrected record and suppress the zombie-record restore too.
	m.mu.RLock()
	_, stillTracked := m.vms[vmID]
	m.mu.RUnlock()
	_, beingDestroyed := m.destroying.Load(vmID)
	if !stillTracked || beingDestroyed {
		if wrote {
			m.deleteState(vmID)
		}
		committed = true
		return nil, status.Errorf(codes.Aborted, "vm %s was destroyed while revival was completing", vmID)
	}
	if !wrote {
		teardownSelf(context.WithoutCancel(ctx))
		if teardownFailed {
			return nil, status.Error(codes.Internal, "revived VM could not be durably recorded and teardown did not confirm; VM left for forced destroy")
		}
		return nil, status.Error(codes.Internal, "revived VM could not be durably recorded; torn down for clean retry")
	}
	committed = true
	// Rare operator path, so phase durations go to the structured log
	// rather than a new metric surface: enough to see where a slow
	// revival spent its time (teardown and copy fold into boot).
	m.log.Info().Str("vm_id", vmID).
		Dur("teardown", teardownDur).
		Dur("copy_and_boot", bootDur).
		Dur("readiness", time.Since(phaseStart)).
		Dur("total", time.Since(reviveStart)).
		Msg("sandbox revived")
	return inst, nil
}

// statRegularFile reports whether path exists and is a regular file.
func statRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// reviveBoxdReadyBudget bounds the wait for a revived guest's boxd. Cold
// boots run full guest init (no warm memory image), so this is more
// generous than the resume budget.
const reviveBoxdReadyBudget = 90 * time.Second
