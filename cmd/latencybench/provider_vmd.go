package main

import (
	"context"
	"errors"
	"fmt"
)

// ErrVMDNotWired is returned by vmdProvider.Wake until the real Firecracker/vmd
// integration is implemented. It is a sentinel so callers/tests can detect the
// "stubbed but not faked" state.
var ErrVMDNotWired = errors.New("vmd provider not wired yet: requires a Linux KVM host and the internal/vm resume/restore integration")

// vmdProvider is the REAL wake provider — it must drive Firecracker/vmd to put a
// VM into a tier, trigger the wake, and time each phase against the guest probe.
// It is intentionally NOT implemented here: this dev box has no KVM, and faking
// these numbers would defeat the purpose of the benchmark.
//
// Integration seam — what Wake() must do per tier, and which existing APIs it
// wraps. Each phase below maps to a span in PhaseTimings (§2.3). The functions
// referenced live in internal/vm (module github.com/superserve-ai/sandbox):
//
//	Tier 1 (paused-in-RAM):
//	  TODO: issue the BARE Firecracker pause/resume, distinct from the snapshot-
//	        based PauseVM. internal/vm.Manager today exposes:
//	          - PauseVM  (manager.go ~L541): snapshot-to-disk + stop unit — TOO HEAVY for Tier 1.
//	          - ResumeVM (manager.go ~L585): restore-from-snapshot — also not the
//	            light path.
//	        The bare path is Firecracker `PATCH /vm {"state":"Paused"}` ->
//	        `{"state":"Resumed"}` with memory left resident. firecracker.go has the
//	        FC client plumbing (newFCClient, the operations.* calls) to add a
//	        PatchVMState helper; vmd must expose Pause/Resume that call it without
//	        touching the snapshot. (Validation plan §3 Tier 1, Phase B.)
//	  Phases: T_control (lease/route) + T_resume (PATCH Resumed) + T_net (must be ~0:
//	          keep netns attached while paused — §4) + T_guest (probe first op).
//	  Gate: wake p99 < 10ms.
//
//	Tier 2 (local snapshot + UFFD):
//	  TODO: snapshot via PauseVM (manager.go ~L541, CreateSnapshot), reclaim RAM,
//	        then restore with the UFFD mem-backend and an external UFFD handler.
//	        RestoreSnapshotUffdInternalWithOverrides (firecracker.go ~L358) already
//	        sets MemBackend{BackendType: UffdInternal, ...} — wire vmd to call the
//	        UFFD restore path and stand up the page handler. Also A/B against eager
//	        full-RAM load (RestoreSnapshot, firecracker.go ~L299) to quantify the
//	        UFFD win. (§3 Tier 2, Phase C.)
//	  Phases: + T_load (build VM + load snapshot + UFFD up). T_guest dominated by
//	          faulting in the working set during the probe.
//	  Gate: wake p99 < 50ms.
//
//	Tier 3 (cold / cross-host):
//	  TODO: push snapshot + state to object storage, restore on a DIFFERENT host,
//	        attach /state there. New long poles to time independently:
//	          - T_fetch: snapshot transport (full pull vs stream-on-demand UFFD).
//	          - T_attach: /state mount on a cold host — run Mesa vs Archil side by
//	            side; this comparison picks the state backend (§3 Tier 3, §6).
//	        Reuse the Tier-2 UFFD restore on the destination host. (Phase D.)
//	  Phases: + T_fetch + T_attach. Gate: wake p50 < 1s and p99 < 2s.
//
// Cross-cutting integration TODOs (apply to all tiers):
//   - Drive the in-guest probe-guest binary to first-meaningful-op and parse its
//     `FIRST_OP_DONE <nanos>` line into T_guest. The trigger transport (stdin byte
//     via vsock/boxd, or HTTP GET) must NOT itself include network-reattach cost —
//     keep that in T_net.
//   - Cross-check the probe's guest_monotonic clock against the host clock to catch
//     wall-clock skew across thaw (§4 NUMA/clock).
//   - For the `cold` cache arm: drop the host page cache (echo 3 > drop_caches) and,
//     for Tier 3, evict the local snapshot copy before each iteration (§4).
//   - For contention arms: keep K paused VMs per core resident during Tier-1 wakes
//     (§4 CPU oversubscription) — the density test.
//   - Pull VMM-internal phase timings from Firecracker's own metrics where the host
//     clock can't see inside the load/resume (§2.3).
type vmdProvider struct{}

func newVMDProvider() *vmdProvider { return &vmdProvider{} }

func (p *vmdProvider) Label() string { return "vmd (REAL — NOT WIRED)" }

// Wake is the real measurement path. It is deliberately unimplemented: see the
// integration seam documented on vmdProvider. It returns ErrVMDNotWired rather
// than fabricating timings.
func (p *vmdProvider) Wake(_ context.Context, params WakeParams) (PhaseTimings, error) {
	// TODO(epic-1.1): implement per the tier-specific seam above against
	// internal/vm on a Linux KVM host. Until then, do not return fake numbers.
	return PhaseTimings{}, fmt.Errorf("tier %s: %w", params.Cell.Tier, ErrVMDNotWired)
}
