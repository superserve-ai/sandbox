package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/preview"
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
func (m *Manager) ReviveVM(ctx context.Context, vmID, diskPath, basePath string, standaloneDisk, allowRecordless bool, teamID, ownerID string, vcpu, memMiB uint32, rules *sandboxNetworkRules) (*VMInstance, error) {
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
		inst.mu.RLock()
		pausedDisk := inst.DiskPath
		if pausedDisk == "" {
			rundirKey := vmID
			if inst.RunDirID != "" {
				rundirKey = inst.RunDirID
			}
			fname := "rootfs.ext4"
			if inst.Config.BasePath != "" {
				fname = "overlay.ext4"
			}
			pausedDisk = filepath.Join(m.cfg.RunDir, rundirKey, fname)
		}
		pausedBase := inst.Config.BasePath
		inst.mu.RUnlock()
		// Idempotency: a live, verified VM whose recorded salvage path
		// matches this request is this request's own completed work (a
		// lost RPC response, or a retry after a failed post-commit
		// injection). Returning it lets the caller resume the documented
		// post-steps instead of stranding a successful revival behind
		// the liveness guard. Any other live VM still refuses below.
		inst.mu.RLock()
		liveStatus, liveUnverified, revivedDisk := inst.Status, inst.Unverified, inst.RevivedDisk
		inst.mu.RUnlock()
		if liveStatus == StatusRunning && !liveUnverified && revivedDisk != "" {
			if rd, rerr := filepath.EvalSymlinks(diskPath); rerr == nil && rd == revivedDisk {
				// The record alone is exactly what a zombie lies about
				// (the reason this RPC exists): confirm the supervisor
				// actually reports live before short-circuiting, the same
				// oracle the fresh-attempt path uses for its own refusal.
				if !m.vmConfirmedAtRest(ctx, vmID) {
					// Only the disk (immutable: it names the boot this
					// instance already ran) short-circuits. Policy is
					// mutable and reapplies on every idempotent hit, so a
					// retry with corrected allow/deny/domain rules is not
					// silently ignored the way returning early outright
					// would leave it.
					if rules != nil {
						inst.mu.RLock()
						netInfo := &network.VMNetInfo{HostIP: inst.IP, TAPDevice: inst.TAPDevice, Namespace: inst.Namespace}
						inst.mu.RUnlock()
						if perr := m.applySandboxNetworkRules(vmID, netInfo, rules); perr != nil {
							return nil, status.Errorf(codes.Internal, "reapply network rules on idempotent revive: %v", perr)
						}
					}
					return inst, nil
				}
			}
		}
		if st == StatusPaused && snap != "" {
			// The refusal delegates to resume, so it only holds when
			// resume is actually possible: every recorded pause artifact
			// must still exist. A paused record whose snapshot or memory
			// file is gone is unresumable, and refusing revival too
			// would strand a sandbox that has a usable salvaged disk.
			// The disk resume would boot (recorded, or inferred from the
			// run directory exactly as resume infers it) and any overlay
			// base count as pause artifacts too: a paused VM that lost
			// its rootfs is precisely the case the salvaged disk exists
			// to recover.
			if statRegularFile(snap) && mem != "" && statRegularFile(mem) && (baseMem == "" || statRegularFile(baseMem)) && statRegularFile(pausedDisk) && (pausedBase == "" || statRegularFile(pausedBase)) {
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
	// Sampled before the record read: any destroy completing after this
	// point is visible as an epoch step, so a deletion that interleaves
	// anywhere between reading the record and committing the
	// replacement is detected rather than silently resurrected.
	epochAtRead := m.destroyEpoch(vmID)
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
		// Startup stale cleanup deletes dead non-paused records, which is
		// exactly the state a to-be-revived zombie is in after a vmd
		// restart; without an escape hatch the recovery path dies with
		// the record. allow_recordless is the operator's attestation that
		// the sandbox belongs to this host. Nothing can be defaulted
		// without a record, so the shape and base disposition must be
		// explicit, and the synthesized record carries no ownership or
		// preview policy: the control plane re-establishes those before
		// the row flips, and the default preview posture is private.
		if !allowRecordless {
			return nil, status.Errorf(codes.FailedPrecondition, "vm %s has no durable record on this host; revive only replaces known sandboxes (allow_recordless overrides with explicit shape and base)", vmID)
		}
		if vcpu == 0 || memMiB == 0 {
			return nil, status.Error(codes.InvalidArgument, "allow_recordless requires explicit vcpu and mem_mib")
		}
		if basePath == "" && !standaloneDisk {
			return nil, status.Error(codes.InvalidArgument, "allow_recordless requires base_path or standalone_disk; there is no record to name the base")
		}
		if teamID == "" {
			// Optional for OwnerID (individual sandboxes may have none),
			// required for TeamID: exec/file usage attribution and
			// billing key on it, and there is no follow-up RPC to add it
			// after the fact.
			return nil, status.Error(codes.InvalidArgument, "allow_recordless requires team_id; data-plane attribution has no other source")
		}
		// Empty PreviewAccess reads as legacy-public to the preview
		// proxy (every listening non-privileged port routable), which
		// would expose the workload before an operator sets real policy.
		// Recordless revival fails closed to private instead.
		prevRec = &VMRecord{ID: vmID, Status: StatusError, Supervision: SupervisionUnit, TeamID: teamID, OwnerID: ownerID, PreviewAccess: preview.AccessPrivate}
	}

	// Overlay-mode sandboxes salvage as sparse overlays whose holes are
	// windows to a shared base image; booting one standalone would read
	// every hole as zeros and corrupt the guest's filesystem. The base
	// comes from the request or, absent there, the zombie's own durable
	// record, and when neither names one the disk boots standalone
	// (legacy full-image sandboxes). A named base must exist.
	if standaloneDisk {
		// A flattened salvage must not inherit the recorded base: its
		// sparse zero regions are real zeros, and overlay mode would
		// read them from the old base as stale filesystem contents.
		if basePath != "" {
			return nil, status.Error(codes.InvalidArgument, "standalone_disk excludes base_path")
		}
	} else if basePath == "" && prevRec != nil {
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
	// Absolute paths only: EvalSymlinks keeps relative inputs relative,
	// which defeats the prefix comparison against the absolute run
	// directory (a salvage inside it would slip past and be deleted by
	// the teardown), and a relative base breaks inside Firecracker's
	// mount namespace.
	if !filepath.IsAbs(diskPath) {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path %q must be absolute", diskPath)
	}
	if basePath != "" && !filepath.IsAbs(basePath) {
		return nil, status.Errorf(codes.InvalidArgument, "base_path %q must be absolute", basePath)
	}
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "disk_path: %v", err)
	}
	// The run dir resolves through the same symlink canonicalization as
	// the salvage path: comparing a physical salvage path against an
	// unresolved configured prefix would let a salvage inside a
	// symlinked run directory slip past and be deleted by the teardown.
	runDirRoot := m.cfg.RunDir
	if resolvedRoot, rerr := filepath.EvalSymlinks(runDirRoot); rerr == nil {
		runDirRoot = resolvedRoot
	}
	vmRunDir := filepath.Join(runDirRoot, vmID) + string(filepath.Separator)
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
	// The preserve entry precedes the residue clear: the teardown's own
	// record deletion is exactly the delete-then-rewrite gap that must
	// not exist. Installed under the record-owner mutex with an epoch
	// check: an external destroy clears the preserve at entry and holds
	// this mutex to completion, so the entry can never be repopulated
	// under a destroy still in flight, and one that completed since the
	// record read is visible here and aborts the revival.
	unlockInstall := m.lockRecordOwner(vmID)
	if m.destroyEpoch(vmID) != epochAtRead {
		unlockInstall()
		return nil, status.Errorf(codes.Aborted, "vm %s was destroyed while revival was preparing; the destroy is authoritative", vmID)
	}
	{
		pending := *prevRec
		pending.RevivalPending = true
		m.preserveRecordOnDestroy.Store(vmID, pending)
	}
	unlockInstall()
	defer m.preserveRecordOnDestroy.Delete(vmID)
	if err := m.DestroyVM(context.WithValue(ctx, reviveTeardownCtxKey{}, true), vmID, true); err != nil {
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
	epochBase := epochAtRead + 1
	// A teardown that cannot confirm the replacement stopped must also
	// suppress the rollback: restoring the zombie record over a
	// still-live unready VM would lie about the host's state, and
	// DestroyVM's own failure discipline already leaves a truthful
	// teardown-pending record for the forced retry.
	teardownFailed := false
	teardownSelf := func(c context.Context) {
		// Detached from the RPC's deadline but bounded: a hung stop must
		// not wedge the RPC and the per-VM lifecycle lock indefinitely.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(c), reviveTeardownBudget)
		defer cancel()
		dctx = context.WithValue(dctx, reviveTeardownCtxKey{}, true)
		// The count mirrors the epoch: only successful destroys bump it,
		// so only successful teardowns count as our own.
		if derr := m.DestroyVM(dctx, vmID, true); derr != nil {
			teardownFailed = true
			m.log.Error().Err(derr).Str("vm_id", vmID).Msg("teardown after failed revival did not confirm; record left as-is")
		} else {
			// The destroy completed and bumped the epoch, so it counts as
			// ours either way; but DestroyVM can log-and-ignore a failed
			// unit stop and still return nil, and restoring durable
			// state or recycling the slot under a live replacement needs
			// the terminal claim, exactly as the supervised cold-boot
			// path requires it. Both supervisors, since the failed
			// attempt's mode may not be what the record says.
			selfDestroys++
			// cgroupStillLive is the mode-agnostic gate (DestroyVM's own):
			// a nil cgroup subtree (unit-only hosts, the default config)
			// reads as no cgroup residue, where the definitely-dead probe
			// would read it as never-dead and mark every teardown failed.
			if !vmUnitFullyDown(vmID) || m.cgroupStillLive(vmID) {
				teardownFailed = true
				m.log.Error().Str("vm_id", vmID).Msg("replacement not terminally down after teardown; rollback suppressed, residue left for forced destroy")
			}
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
			// A destroy interleaved. Anything this attempt re-persisted
			// (a pending Error record from a failed boot, or the
			// preserved anchor) undoes that authoritative deletion, so
			// delete deliberately, through the preserve.
			m.deleteStateForce(vmID)
			return
		}
		restored := *prevRec
		restored.RevivalPending = true
		if perr := m.state.Put(restored); perr != nil {
			m.log.Error().Err(perr).Str("vm_id", vmID).Msg("restore zombie record after failed revival")
		}
	}()
	// Exactly one destroy (ours) may separate the record read from this
	// point; more means an external destroy interleaved, and its deletion
	// is authoritative. The check and the record's return to the store
	// happen under the record-owner mutex so a destroy cannot complete
	// between them and be silently undone by the write. The record rides
	// out the copy marked RevivalPending: the copy can take minutes on a
	// full disk, a crash there must not leave the sandbox recordless
	// (revival refuses unknown sandboxes), and startup stale cleanup
	// parks pending records instead of deleting them.
	unlockOwner := m.lockRecordOwner(vmID)
	if m.destroyEpoch(vmID) != epochAtRead+1 {
		unlockOwner()
		return nil, status.Errorf(codes.Aborted, "vm %s was destroyed while revival was preparing; the destroy is authoritative", vmID)
	}
	if m.state != nil {
		pending := *prevRec
		pending.RevivalPending = true
		if perr := m.state.Put(pending); perr != nil {
			unlockOwner()
			return nil, status.Errorf(codes.Internal, "keep record across boot: %v", perr)
		}
	}
	unlockOwner()
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
		inst.RevivalPending = true
		inst.RevivedDisk = diskPath
		inst.TeamID = prevRec.TeamID
		inst.OwnerID = prevRec.OwnerID
		inst.PreviewAccess = prevRec.PreviewAccess
		inst.PreviewPorts = previewPortsFromRecord(prevRec.PreviewPorts, prevRec.PreviewPortAccess, prevRec.PreviewPortTokenVersions)
		inst.PreviewPolicyRevision = prevRec.PreviewPolicyRevision
		inst.PreviewTokenPolicyRevision = prevRec.PreviewTokenPolicyRevision
		inst.Metadata = prevRec.Metadata
	}
	inst, err := m.coldBootFromRootfs(ctx, vmID, diskPath, basePath, rules, seed, true, supervision, vcpu, memMiB)
	if err != nil {
		// An unconfirmed stop of the spawned VM keeps the boot's
		// truthful StatusError record: restoring the zombie record over
		// a possibly-live replacement would misdescribe the host.
		if errors.Is(err, errSpawnedStopUnconfirmed) {
			teardownFailed = true
		}
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
	inst.RevivalPending = false
	inst.mu.Unlock()
	// Durable record: reattach and the reconciler must know this VM
	// after a vmd restart, exactly like any created VM. A revival the
	// state store cannot record is not a revival: an unrecorded running
	// VM would be invisible to reconciliation and refused by the next
	// revive's liveness probe, so fail closed and tear down.
	// Ownership check BEFORE the verified persist, atomic with it under
	// the record-owner mutex: writing first would leave a crash window
	// in which a destroyed sandbox's restart adopts an ordinary
	// verified Running record. DestroyVM holds the same mutex for its
	// whole run, so a destroy either completed before this block (and
	// the epoch shows it) or waits until the commit is durable and then
	// deletes it, destroy-wins either way.
	unlockCommit := m.lockRecordOwner(vmID)
	m.mu.RLock()
	_, stillTracked := m.vms[vmID]
	m.mu.RUnlock()
	_, beingDestroyed := m.destroying.Load(vmID)
	externallyDestroyed := m.destroyEpoch(vmID) != epochBase+selfDestroys
	if !stillTracked || beingDestroyed || externallyDestroyed {
		unlockCommit()
		// Whatever the interleaving, the replacement or its residue must
		// go: a destroy that raced the boot may have missed the spawned
		// process or the just-written record (it can complete before
		// either exists), and DestroyVM force-cleans residue even for
		// untracked VMs, serializing behind any destroy still in flight.
		teardownSelf(context.WithoutCancel(ctx))
		m.deleteStateForce(vmID)
		committed = true
		if teardownFailed {
			// The destroy owns the outcome but the replacement could not
			// be confirmed stopped; say so, rather than reporting a
			// clean abort over a possibly-live VM.
			return nil, status.Errorf(codes.Internal, "vm %s was destroyed while revival was completing and teardown did not confirm; residue left for forced destroy", vmID)
		}
		return nil, status.Errorf(codes.Aborted, "vm %s was destroyed while revival was completing", vmID)
	}
	wrote := m.persistState(inst)
	unlockCommit()
	if !wrote {
		teardownSelf(context.WithoutCancel(ctx))
		if teardownFailed {
			return nil, status.Error(codes.Internal, "revived VM could not be durably recorded and teardown did not confirm; VM left for forced destroy")
		}
		return nil, status.Error(codes.Internal, "revived VM could not be durably recorded; torn down for clean retry")
	}
	committed = true
	m.preserveRecordOnDestroy.Delete(vmID)
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

// statRegularFile reports whether path exists as a non-empty regular
// file. Zero length rejects: a truncated or never-finalized artifact is
// as unresumable as a missing one.
func statRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}

// reviveBoxdReadyBudget bounds the wait for a revived guest's boxd. Cold
// boots run full guest init (no warm memory image), so this is more
// generous than the resume budget.
const reviveBoxdReadyBudget = 90 * time.Second

// reviveTeardownBudget bounds a failed revival's teardown: DestroyVM
// stops the unit or cgroup, releases the slot, and clears the run
// directory, so it gets more room than a bare unit stop, but never an
// unbounded hold on the RPC and lifecycle lock.
const reviveTeardownBudget = 60 * time.Second
