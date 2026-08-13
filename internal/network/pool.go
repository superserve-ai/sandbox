package network

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// PoolConfig controls the pre-allocated network slot pool.
type PoolConfig struct {
	// NewSize is the number of fresh pre-allocated slots to keep ready.
	// Default: 32.
	NewSize int
	// RecycleSize is the capacity for recycled slots — network namespaces
	// returned from destroyed sandboxes. Recycled slots skip the full
	// setup (namespace, veth, TAP, nftables are already configured).
	// Default: 100.
	RecycleSize int
	// ResetTapOnRecycle recreates a returned slot's tap0 before it is made
	// claimable again (see verifyAndRecycle). Off by default.
	ResetTapOnRecycle bool
	// AbandonOnStop makes Stop leave warm slots in the kernel instead of
	// tearing them down, so shutdown is near-instant regardless of pool depth
	// and the next process adopts the slots via AdoptOrphanSlots. Off by
	// default (legacy teardown).
	AbandonOnStop bool
}

// Pool pre-allocates network namespaces, veth pairs, TAP devices, and
// firewall rules so that SetupVM can claim a ready slot off the hot path
// instead of building one inline.
//
// The pool is optional — if not started, SetupVM falls back to on-demand
// setup (the original behavior). Call StartPool after NewManager to enable.
type Pool struct {
	mgr      *Manager
	log      zerolog.Logger
	newSize  int
	fresh    chan *preallocSlot // pre-allocated from scratch
	recycled chan *preallocSlot // returned from destroyed sandboxes
	stopCh   chan struct{}
	wg       sync.WaitGroup
	drainMu  sync.RWMutex
	// refillDrainGate is closed while the controller is draining warm inventory.
	// Refill workers select on it before handing a built slot to the pool so a
	// send that was already blocked when drain started can still abort instead
	// of immediately replacing the drained slot.
	refillDrainGate chan struct{}
	// refillPaused suspends the refill loop while the controller is tearing
	// down warm inventory. That keeps the pool from immediately rebuilding the
	// same slots that the pressure controller just shed.
	refillPaused bool

	// verifyPollInterval/verifyMaxWait tune Return's pre-recycle liveness
	// check (see verifyAndRecycle). Zero means use the package defaults;
	// tests override these to run the timeout path without a real 20s wait.
	verifyPollInterval time.Duration
	verifyMaxWait      time.Duration

	// refillActive counts refill workers currently building or delivering a
	// slot. Workers declare themselves active for the whole construction-
	// through-delivery span and inactive during backoff sleeps, so claimants
	// read actual producer state instead of inferring liveness from timing.
	refillActive atomic.Int64

	// adoptPhase is the adoption pass's lifecycle: idle → scanning (orphan
	// scan, zero output possible) → verifying (workers judging candidates) →
	// idle. A single atomic so claimants can never observe contradictory
	// intermediate states.
	adoptPhase atomic.Int32

	// adoptStreak counts consecutive verified candidates that yielded no
	// inventory; any delivery resets it. At adoptEscapeStreak, claimants stop
	// treating the pass as a producer (it may be chewing through invalid
	// slots forever) until it delivers again. The escape is DERIVED from the
	// streak (adoptionTrusted), never stored separately — one atomic means a
	// stale failure can't race a fresh delivery out of its trust restore. An
	// explicit, logged heuristic — whether the REMAINING candidates are
	// valid is unknowable without receipt/version evidence.
	adoptStreak       atomic.Int64
	adoptEscapeStreak int64

	// notifyCh broadcasts producer progress (a delivery or a state change) to
	// ClaimWait waiters by close-and-replace, so a burst of claimants wakes on
	// events instead of hammering a fine-grained poll. Lazily created; nil
	// while nobody has asked to wait.
	notifyMu sync.Mutex
	notifyCh chan struct{}

	// resetTapOnRecycle recreates tap0 before a returned slot is recycled.
	resetTapOnRecycle bool
	// abandonOnStop: Stop leaves slots in the kernel for the next process
	// to adopt instead of tearing them down (see PoolConfig.AbandonOnStop).
	abandonOnStop bool
	// resetSem bounds concurrent tap rebuilds so a mass delete's returns can't
	// fork-storm the kernel's netlink lock.
	resetSem chan struct{}
}

// preallocSlot holds a fully configured network namespace ready to be
// assigned to a VM.
type preallocSlot struct {
	idx  int
	info *VMNetInfo
	// vethName is needed for cleanup if the slot is never claimed.
	vethName string
	// adopted marks a slot recovered from a previous vmd lifetime: its tap is
	// rebuilt in verifyAndRecycle regardless of the pool-level flag (unknown
	// provenance — a previous owner may have died holding the fd), and it may
	// overflow into the fresh channel when the recycle channel is full, since
	// it is fully built and counts against the refill target.
	adopted bool
}

// pidsInNsFunc is a seam over pidsInNs so tests can simulate a namespace
// that's still occupied (or clear) without a real kernel netns/process.
var pidsInNsFunc = pidsInNs

// resetTapFunc is a seam over Manager.resetTap so tests can drive the
// recycle-vs-teardown decision without building a real netns + tap device.
var resetTapFunc = (*Manager).resetTap

const (
	// defaultVerifyPollInterval trades a small amount of slot-reuse latency
	// (negligible against the 10s+ stop window it's guarding) for meaningfully
	// less /proc scanning: each poll is a full readdir + per-pid stat, and the
	// case that makes verification take a while — host I/O contention slowing
	// process teardown — is exactly the case where many verifiers end up
	// polling concurrently, adding VFS load to an already-contended host.
	defaultVerifyPollInterval = 150 * time.Millisecond
	// defaultVerifyMaxWait comfortably exceeds firecracker@.service's
	// TimeoutStopSec=10 (systemd's own worst case for a unit that ignores
	// SIGTERM) plus margin for kernel teardown under host I/O contention.
	defaultVerifyMaxWait = 20 * time.Second
	// resetTapConcurrency caps in-flight tap rebuilds (see Pool.resetSem);
	// rebuilds are short once uncontended, so a small window drains a backlog
	// quickly.
	resetTapConcurrency = 8
	// refillFailureBackoff paces retries after a failed slot build. Failures
	// are host-wide conditions (an exhausted slot range, a sick netlink), not
	// per-attempt luck, so retrying immediately burns a core and floods the
	// log with thousands of identical lines a second without fixing anything.
	refillFailureBackoff = 2 * time.Second
	// refillConcurrency is the number of refill workers rebuilding the fresh
	// pool. A single worker refills at one slot per build-time, which cannot
	// catch a drained pool back up while claims keep arriving; builds stay
	// individually cheap because Manager.setupSem bounds them globally.
	refillConcurrency = 4
	// resetTapTimeout bounds one batched rebuild — a healthy one takes well
	// under a second, and a tight bound keeps a stalled backlog (and Stop)
	// from dragging.
	resetTapTimeout = 3 * time.Second
	// abandonStopWait bounds Stop's wait for in-flight pool goroutines under
	// abandon-on-stop. Only quiesces logging — abandoned slots are recovered
	// by boot-time adoption regardless.
	abandonStopWait = 2 * time.Second
	// adoptConcurrency bounds parallel orphan adoptions: each runs /proc
	// scans and possibly a tap rebuild, and boot is exactly when the host is
	// also reattaching VMs — keep the sweep gentle.
	adoptConcurrency = 4
	// adoptSlotTimeout bounds one slot's validation (a handful of ip/netlink
	// calls); a hung namespace shouldn't stall the whole adoption pass.
	adoptSlotTimeout = 10 * time.Second
	// adoptTimeoutAbort ends the whole pass after this many validation
	// timeouts. Each timeout strands one pinned OS thread in the wedged
	// syscall, and wedges are systemic (a stuck netlink wedges every
	// candidate) — better to stop early and leave the rest for a healthier
	// boot than to accumulate a thread per slot.
	adoptTimeoutAbort = 3
	// defaultAdoptEscapeStreak is how many consecutive adoption candidates may
	// yield no inventory before claimants stop waiting on the pass (see
	// adoptYieldedNothing). The single tuning point, deliberately in code:
	// changing it is a reviewed one-line diff, not a host edit that a rebuild
	// forgets. The escape is bounded by the claim budget regardless.
	defaultAdoptEscapeStreak = 32
)

// Adoption pass phases (Pool.adoptPhase).
const (
	adoptPhaseIdle int32 = iota
	adoptPhaseScanning
	adoptPhaseVerifying
)

// adoptSlotFunc is a seam over Manager.adoptSlot so tests can drive adoption
// without real kernel namespaces.
var adoptSlotFunc = (*Manager).adoptSlot

// StartPool creates the network slot pool and fills it in the background, so
// startup (and the gRPC readiness gate) doesn't block on ~newSize slot setups;
// SetupVM falls back to on-demand setup until it warms. m.pool is set before the
// gate opens, and the fill only touches the pool's concurrency-safe channels.
func (m *Manager) StartPool(ctx context.Context, cfg PoolConfig) *Pool {
	newSize := cfg.NewSize
	if newSize <= 0 {
		newSize = 32
	}
	recycleSize := cfg.RecycleSize
	if recycleSize <= 0 {
		recycleSize = 100
	}

	p := &Pool{
		mgr:               m,
		log:               m.log.With().Str("component", "net_pool").Logger(),
		newSize:           newSize,
		fresh:             make(chan *preallocSlot, newSize),
		recycled:          make(chan *preallocSlot, recycleSize),
		stopCh:            make(chan struct{}),
		refillDrainGate:   make(chan struct{}),
		resetTapOnRecycle: cfg.ResetTapOnRecycle,
		abandonOnStop:     cfg.AbandonOnStop,
		resetSem:          make(chan struct{}, resetTapConcurrency),
	}
	p.adoptEscapeStreak = defaultAdoptEscapeStreak
	m.pool = p

	p.log.Info().Int("target", newSize).Int("recycle_cap", recycleSize).
		Bool("reset_tap_on_recycle", p.resetTapOnRecycle).Msg("network pool starting (filling in background)")
	// Each worker can park one pre-built slot in a blocked send when the pool
	// is full, so inventory can exceed the target by up to the worker count.
	// Clamping workers to the target keeps that overshoot proportionate for
	// pools smaller than the default worker count.
	workers := refillConcurrency
	if newSize < workers {
		workers = newSize
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go func() { defer sentrylog.Recover("netpool-refill"); p.refillLoop(ctx) }()
	}

	return p
}

// Claim takes a slot from the pool and assigns it to the given VM ID.
// Prefers recycled slots (zero setup cost) over fresh ones (one nftables
// call). Returns nil if both pools are empty — caller falls back to
// on-demand SetupVM.
//
// Validates each slot's kernel netns is still present; phantoms are
// discarded and their idx returned to the allocator via cleanup.
func (p *Pool) Claim(vmID string) *VMNetInfo {
	tEntry := time.Now()
	for {
		var slot *preallocSlot

		select {
		case slot = <-p.recycled:
		default:
			select {
			case slot = <-p.fresh:
			default:
				return nil
			}
		}
		if slot == nil {
			// Defensive: no producer sends nil today, but a nil here would
			// otherwise panic the claim path — fall back to on-demand setup.
			return nil
		}
		tPopped := time.Now()

		// Race: ns can vanish between this check and devmap insert; fc startup catches it.
		if !nsExists(slot.info.Namespace) {
			p.log.Warn().
				Str("vm_id", vmID).
				Str("namespace", slot.info.Namespace).
				Int("slot", slot.idx).
				Msg("pool: discarded phantom slot (kernel netns missing)")
			p.cleanup(slot)
			continue
		}
		tNsChecked := time.Now()

		p.mgr.mu.Lock()
		p.mgr.devices[vmID] = slot.info
		// Transfer ownership of the index from the pool to this VM.
		p.mgr.assignSlotLocked(slot.idx, vmID)
		p.mgr.mu.Unlock()
		tDone := time.Now()

		p.log.Info().
			Str("vm_id", vmID).
			Int64("claim_pop_ms", tPopped.Sub(tEntry).Milliseconds()).
			Int64("claim_nscheck_ms", tNsChecked.Sub(tPopped).Milliseconds()).
			Int64("claim_devmap_ms", tDone.Sub(tNsChecked).Milliseconds()).
			Int64("claim_total_ms", tDone.Sub(tEntry).Milliseconds()).
			Msg("pool: claim complete")
		return slot.info
	}
}

// producing reports whether some producer has declared itself active: a
// refill worker mid-build/mid-delivery, or an adoption pass that is scanning
// or still trusted to yield inventory. While true, a claimant is better off
// waiting for the next slot than building one inline alongside the producers
// — both paths cross the same kernel locks, and the producers already hold
// them. Declared state, not inference: a worker sleeping in failure backoff
// counts as inactive, so a dead pool releases claimants immediately.
func (p *Pool) producing() bool {
	if p.adoptionTrusted() || p.adoptPhase.Load() == adoptPhaseScanning {
		return true
	}
	return p.refillActive.Load() > 0
}

// adoptionTrusted reports whether claimants should treat the adoption pass as
// a producer worth waiting on: a pass is running and hasn't tripped the
// no-yield escape. Trust is reversible — a later delivery restores it.
func (p *Pool) adoptionTrusted() bool {
	return p.adoptPhase.Load() != adoptPhaseIdle && p.adoptStreak.Load() < p.adoptEscapeStreak
}

// progressCh returns the channel the next progress broadcast will close.
// Callers must capture it BEFORE their Claim attempt so a delivery landing
// between the miss and the wait still wakes them.
func (p *Pool) progressCh() <-chan struct{} {
	p.notifyMu.Lock()
	defer p.notifyMu.Unlock()
	if p.notifyCh == nil {
		p.notifyCh = make(chan struct{})
	}
	return p.notifyCh
}

// signalProgress wakes every ClaimWait waiter: a slot was delivered or a
// producer changed state, so waiters must re-evaluate what they're waiting
// for (and whether they still should be).
func (p *Pool) signalProgress() {
	p.notifyMu.Lock()
	defer p.notifyMu.Unlock()
	if p.notifyCh != nil {
		close(p.notifyCh)
		p.notifyCh = nil
	}
}

// claimWaitFallbackPoll bounds how stale a waiter's view can get if a
// progress signal is missed; the notify broadcast is the primary wakeup.
const claimWaitFallbackPoll = 100 * time.Millisecond

// ClaimWait is Claim with bounded patience: while a producer declares itself
// active, keep retrying so the claimant consumes producer output instead of
// racing the producers. The failure this exists for: a restart (or a burst)
// momentarily empties the pool, N claimants each commit to an inline build,
// and those builds queue behind a bounded semaphore while contending with the
// pool's own refill for netlink and the mount table — each claimant pays tens
// of seconds for a slot the pool would have handed it moments later.
//
// The budget follows adoption trust dynamically: a claimant that started on
// the generous adoption budget is re-clamped to the normal one the moment the
// pass trips its no-yield escape. Returns nil when no producer is active
// (after one final Claim — a producer may deliver immediately before
// declaring itself inactive), when the budget lapses, or when ctx/shutdown
// ends the wait.
func (p *Pool) ClaimWait(ctx context.Context, vmID string) *VMNetInfo {
	start := time.Now()
	for {
		ch := p.progressCh()
		if info := p.Claim(vmID); info != nil {
			return info
		}
		if !p.producing() {
			return p.Claim(vmID)
		}
		budget := poolClaimWaitBudget
		if p.adoptionTrusted() {
			budget = adoptionClaimWaitBudget
		}
		remaining := budget - time.Since(start)
		if remaining <= 0 {
			return nil
		}
		wait := claimWaitFallbackPoll
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-ch:
		case <-time.After(wait):
		case <-p.stopCh:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Return reclaims a sandbox's network slot after destroy. The previous
// occupant's process being gone from vmd's/systemd's point of view (SIGKILL
// sent, unit reported inactive, etc.) is not proof the kernel has finished
// releasing its TAP fd — SIGKILL is asynchronous with respect to a process
// blocked in an uninterruptible wait (e.g. a UFFD page fault resolving
// against local SSD), and "systemd unit not active" also covers "still
// deactivating." Handing the slot straight to a new VM on that basis is what
// produced the "Open tap device failed: Device or resource busy" incident:
// the new VM's Firecracker raced the old one's still-open tap0 fd.
//
// So Return doesn't decide fast vs. full teardown itself — it verifies. The
// slot stays owned by the pool (not claimable — Claim only ever reads from
// p.recycled) while verifyAndRecycle confirms the namespace is actually
// empty of processes, off the caller's hot path.
func (p *Pool) Return(slot *preallocSlot) {
	p.mgr.mu.Lock()
	p.mgr.assignSlotLocked(slot.idx, poolOwner)
	p.mgr.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer sentrylog.Recover("netpool-verify-return")
		p.verifyAndRecycle(slot)
	}()
}

// drain tears down up to max warm slots from the pool so host-side namespace
// and mount pressure can be reduced without reclaiming a live sandbox.
func (p *Pool) drain(max int) int {
	if max <= 0 {
		return 0
	}
	p.setRefillPaused(true)
	p.closeRefillDrainGate()
	defer func() {
		p.resetRefillDrainGate()
		p.setRefillPaused(false)
	}()
	drained := 0
	for drained < max {
		var slot *preallocSlot
		select {
		case slot = <-p.recycled:
		default:
			select {
			case slot = <-p.fresh:
			default:
				return drained
			}
		}
		if slot == nil {
			return drained
		}
		p.cleanup(slot)
		drained++
	}
	return drained
}

func (p *Pool) closeRefillDrainGate() {
	p.drainMu.Lock()
	if p.refillDrainGate != nil {
		close(p.refillDrainGate)
	}
	p.drainMu.Unlock()
}

func (p *Pool) resetRefillDrainGate() {
	p.drainMu.Lock()
	p.refillDrainGate = make(chan struct{})
	p.drainMu.Unlock()
}

func (p *Pool) setRefillPaused(paused bool) {
	p.drainMu.Lock()
	p.refillPaused = paused
	p.drainMu.Unlock()
}

func (p *Pool) refillIsPaused() bool {
	p.drainMu.RLock()
	paused := p.refillPaused
	p.drainMu.RUnlock()
	return paused
}

func (p *Pool) refillDrainCh() <-chan struct{} {
	p.drainMu.RLock()
	gate := p.refillDrainGate
	p.drainMu.RUnlock()
	return gate
}

// verifyAndRecycle blocks (in its own goroutine, never the caller's) until
// slot's namespace has no attached processes, then makes it claimable. It
// re-kills defensively first — this is also the backstop for the DestroyVM
// paths that skip or race their own kill (an untracked VM after a vmd
// restart, or a reconciler markStale that never sent a signal at all).
//
// A namespace still occupied after verifyMaxWait isn't a slow teardown, it's
// stuck — recycling it would poison the pool, so it's torn down for real
// instead of being handed to the next VM.
// The boolean result reports whether the slot was actually delivered into
// pool inventory (as opposed to torn down or abandoned) — adoption uses it to
// maintain its no-yield trust streak.
func (p *Pool) verifyAndRecycle(slot *preallocSlot) bool {
	pollInterval := p.verifyPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultVerifyPollInterval
	}
	maxWait := p.verifyMaxWait
	if maxWait <= 0 {
		maxWait = defaultVerifyMaxWait
	}
	ns := slot.info.Namespace

	killProcessesInNs(ns)

	deadline := time.Now().Add(maxWait)
	for {
		pids, ok := pidsInNsFunc(ns)
		// A failed scan (ok=false) is "don't know," not "clear" — keep
		// polling rather than risk recycling a namespace that's still held.
		if ok && len(pids) == 0 {
			break
		}
		if time.Now().After(deadline) {
			p.log.Error().Str("namespace", ns).Int("slot", slot.idx).
				Msg("pool: namespace still occupied after max wait — tearing down instead of recycling")
			p.cleanup(slot)
			return false
		}
		select {
		case <-time.After(pollInterval):
		case <-p.stopCh:
			p.stopSlot(slot)
			return false
		}
	}

	// Process-free doesn't prove tap0's fd is released, so rebuild the tap
	// before recycling; if it can't be rebuilt, tear down instead.
	if p.resetTapOnRecycle || slot.adopted {
		// A full pool means this slot is headed for teardown anyway — skip
		// the rebuild rather than pay it for a slot about to be destroyed
		// (mass deletes overflow the pool by design). Racy but safe: the send
		// below still has a default arm.
		if p.placementFull(slot) {
			p.cleanup(slot)
			return false
		}
		// The semaphore is acquired before the deadline starts, so queueing
		// behind a backlog doesn't eat into a rebuild's own budget.
		select {
		case p.resetSem <- struct{}{}:
		case <-p.stopCh:
			p.stopSlot(slot)
			return false
		}
		poolFull, err := func() (bool, error) {
			// Deferred so a panicking rebuild can't leak the token — Return's
			// goroutine recovers panics, and a leaked token outlives them.
			defer func() { <-p.resetSem }()
			// Recheck after queueing: a mass return can fill the pool while
			// this slot waited, and a doomed slot shouldn't pay for a rebuild.
			if p.placementFull(slot) {
				return true, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), resetTapTimeout)
			defer cancel()
			return false, resetTapFunc(p.mgr, ctx, ns)
		}()
		if poolFull {
			p.cleanup(slot)
			return false
		}
		if err != nil {
			p.log.Error().Err(err).Str("namespace", ns).Int("slot", slot.idx).
				Msg("pool: tap reset failed on recycle — tearing down instead of recycling")
			p.cleanup(slot)
			return false
		}
	}

	select {
	case p.recycled <- slot:
		// Trust is restored before the delivery broadcast: a claimant woken
		// by this slot's arrival must never observe the pass as still
		// untrusted and bail to an inline build.
		if slot.adopted {
			p.adoptDelivered()
		}
		p.signalProgress()
		return true
	case <-p.stopCh:
		// Stop() closes p.recycled only after p.wg.Wait() returns, and this
		// goroutine holds a wg slot until it returns — so stopCh firing here
		// (pool shutting down mid-verify) can't race a send on a closed channel.
		p.stopSlot(slot)
		return false
	default:
		// Recycle pool full. An adopted slot is fully built, so it counts as
		// fresh inventory instead of being destroyed while the refill loop
		// rebuilds its twin from scratch; otherwise tear down (cleanup
		// releases the pool's ownership).
		if slot.adopted {
			select {
			case p.fresh <- slot:
				p.adoptDelivered()
				p.signalProgress()
				return true
			default:
			}
		}
		p.cleanup(slot)
		return false
	}
}

// placementFull reports that slot has nowhere to go, so pre-recycle work
// (the tap rebuild) would be wasted on it. Adopted slots can also land in
// the fresh channel; returned slots only ever recycle.
func (p *Pool) placementFull(slot *preallocSlot) bool {
	if len(p.recycled) < cap(p.recycled) {
		return false
	}
	return !slot.adopted || len(p.fresh) == cap(p.fresh)
}

// stopSlot disposes of a slot the shutdown path can no longer place: torn
// down under legacy shutdown, left in the kernel under abandon-on-stop (the
// next process adopts or sweeps it — a graceful stop and a crash leave the
// host in the same state, so boot only needs one recovery path).
func (p *Pool) stopSlot(slot *preallocSlot) {
	if p.abandonOnStop {
		return
	}
	p.cleanup(slot)
}

// AdoptOrphanSlots claims every namespace a previous vmd lifetime left behind
// and feeds the valid ones through the recycle verification path, so a restart
// starts with a warm pool instead of rebuilding it from scratch. Slots that
// fail validation are torn down; slots that couldn't be judged (shutdown,
// slow host) are left for a later pass. Must run after startup slot
// reservation completed successfully — record-owned indexes must never be
// candidates. Returns the pass's counts.
//
// Prefer StartAdoption over calling this directly at boot: it enters the
// scanning phase before its goroutine is spawned, so no request can observe
// the gap between launch and the pass actually starting.
func (p *Pool) AdoptOrphanSlots(ctx context.Context) (adopted, invalid, skipped int64) {
	// Direct callers (tests, legacy paths) enter the phase here; via
	// StartAdoption it is already scanning and the CAS no-ops. The deferred
	// reset is the panic backstop AND clears the trust state for the next
	// pass; the explicit idle transition before the sweep is the normal path
	// — the stray-veth sweep delivers nothing a claimant could wait for.
	p.adoptPhase.CompareAndSwap(adoptPhaseIdle, adoptPhaseScanning)
	defer func() {
		p.adoptPhase.Store(adoptPhaseIdle)
		p.adoptStreak.Store(0)
		p.signalProgress()
	}()
	indexes := p.mgr.claimOrphanSlots()
	p.adoptPhase.Store(adoptPhaseVerifying)
	p.signalProgress()
	if len(indexes) > 0 {
		p.log.Info().Int("candidates", len(indexes)).Msg("pool: adopting slots left by previous run")

		var nAdopted, nInvalid, nSkipped, nTimeouts atomic.Int64
		work := make(chan int)
		var workers sync.WaitGroup
		for i := 0; i < adoptConcurrency; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer sentrylog.Recover("netpool-adopt")
				for idx := range work {
					p.adoptOne(ctx, idx, &nAdopted, &nInvalid, &nSkipped, &nTimeouts)
				}
			}()
		}

		aborted := false
	feed:
		for i, idx := range indexes {
			// Priority check: once shutdown fires, no more work may be
			// dispatched — the plain select below picks randomly among ready
			// arms, which would keep feeding a dying process.
			select {
			case <-p.stopCh:
				break feed
			case <-ctx.Done():
				break feed
			default:
			}
			if nTimeouts.Load() >= adoptTimeoutAbort {
				// The host is wedged, not the slots: each timeout strands a
				// pinned thread, so stop dispatching. Unlike a shutdown break
				// this process lives on — release the remainder so it isn't
				// held pool-owned and invisible to the leak gauge.
				aborted = true
				for _, rest := range indexes[i:] {
					p.mgr.releaseIfOwned(rest, poolOwner)
					nSkipped.Add(1)
				}
				break feed
			}
			select {
			case work <- idx:
			case <-p.stopCh:
				// Shutdown mid-pass: un-fed indexes stay claimed and in the
				// kernel — the same abandoned state the next boot adopts from.
				break feed
			case <-ctx.Done():
				break feed
			}
		}
		close(work)
		workers.Wait()
		if aborted {
			p.log.Error().Int64("timeouts", nTimeouts.Load()).
				Msg("pool: adoption aborted — validation timing out systemically; remaining slots left for a later boot")
		}
		p.log.Info().Int64("adopted", nAdopted.Load()).Int64("torn_down", nInvalid.Load()).
			Int64("skipped", nSkipped.Load()).Msg("pool: adoption pass complete")
		adopted, invalid, skipped = nAdopted.Load(), nInvalid.Load(), nSkipped.Load()
	}

	p.adoptPhase.Store(adoptPhaseIdle)
	p.signalProgress()
	p.mgr.SweepStrayHostVeths()
	return adopted, invalid, skipped
}

// StartAdoption runs AdoptOrphanSlots in the background. The scanning phase
// is entered synchronously, before the goroutine is spawned, so a request
// arriving before the scheduler runs the pass already sees adoption underway
// and waits with adoption-grade patience — launching the goroutine at the
// call site would leave a window where claimants bail early into inline
// builds against the imminent churn. The pass is tracked in the pool wait
// group so Stop cannot outlive its state. A duplicate start is a no-op.
func (p *Pool) StartAdoption(ctx context.Context) bool {
	if !p.adoptPhase.CompareAndSwap(adoptPhaseIdle, adoptPhaseScanning) {
		p.log.Warn().Msg("pool: adoption already running — duplicate start ignored")
		return false
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer sentrylog.Recover("netpool-adopt")
		p.AdoptOrphanSlots(ctx)
	}()
	return true
}

// adoptDelivered and adoptYieldedNothing maintain the pass's trust streak
// (see the adoptStreak field). Trust transitions are logged once per edge —
// detected from the atomic op's own return value, so concurrent workers
// cannot double-log or lose an edge — never per claimant, so a burst can't
// turn them into a log storm.
func (p *Pool) adoptDelivered() {
	if p.adoptStreak.Swap(0) >= p.adoptEscapeStreak {
		p.log.Info().Msg("pool: adoption delivering again — claimants waiting on it restored")
		p.signalProgress()
	}
}

func (p *Pool) adoptYieldedNothing() {
	if p.adoptStreak.Add(1) == p.adoptEscapeStreak {
		p.log.Warn().Int64("consecutive_without_delivery", p.adoptEscapeStreak).
			Msg("pool: adoption yielding no inventory — claimants no longer waiting on the pass")
		p.signalProgress()
	}
}

// adoptOne validates and places a single claimed orphan. Outcomes: adopted
// (into the pool via the recycle verification path), torn down (definitively
// invalid), or skipped — released but left intact in the kernel — when the
// slot couldn't be judged: shutdown cancelled the pass, validation timed out
// on a congested boot, or validation panicked. Skipped slots surface in the
// leak gauge as orphans and are re-adopted on the next boot; destroying them
// on an ambiguous signal would defeat abandon-on-stop.
func (p *Pool) adoptOne(ctx context.Context, idx int, adopted, invalid, skipped, timeouts *atomic.Int64) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error().Interface("panic", r).Int("slot", idx).
				Msg("pool: adoption panicked — releasing slot")
			p.mgr.releaseIfOwned(idx, poolOwner)
			skipped.Add(1)
			p.adoptYieldedNothing()
		}
	}()

	actx, cancel := context.WithTimeout(ctx, adoptSlotTimeout)
	info, vethName, err := adoptSlotFunc(p.mgr, actx, idx)
	// Read the budget verdict from the context itself, BEFORE cancel makes
	// Err() unconditionally non-nil: an exec killed by the deadline surfaces
	// as an exit error ("signal: killed"), not as DeadlineExceeded, and
	// misreading that as a bad slot would tear down an adoptable namespace.
	budgetExpired := errors.Is(actx.Err(), context.DeadlineExceeded)
	cancel()
	if err != nil {
		switch {
		case ctx.Err() != nil:
			// Shutdown, not a bad slot: keep it abandoned for the next boot.
			skipped.Add(1)
		case budgetExpired || errors.Is(err, context.DeadlineExceeded):
			p.log.Warn().Err(err).Int("slot", idx).
				Msg("pool: orphan slot validation timed out — leaving for a later pass")
			p.mgr.releaseIfOwned(idx, poolOwner)
			skipped.Add(1)
			timeouts.Add(1)
			p.adoptYieldedNothing()
		default:
			p.log.Warn().Err(err).Int("slot", idx).
				Msg("pool: orphan slot failed validation — tearing down")
			// Kill occupants first (mirrors the startup sweep): deleting the
			// netns name while a process holds it leaves the namespace
			// running anonymously, beyond the reach of adoption, sweeps, and
			// the leak gauge.
			killProcessesInNs(nsNameForSlot(idx))
			p.cleanup(&preallocSlot{
				idx:      idx,
				info:     &VMNetInfo{Namespace: nsNameForSlot(idx)},
				vethName: vethNameForSlot(idx),
			})
			invalid.Add(1)
			p.adoptYieldedNothing()
		}
		return
	}
	// verifyAndRecycle resets the trust streak itself, ordered before its
	// delivery broadcast (see the recycle send), so waiters never observe a
	// delivered slot alongside stale distrust.
	if !p.verifyAndRecycle(&preallocSlot{
		idx:      idx,
		info:     info,
		vethName: vethName,
		adopted:  true,
	}) {
		// Validated but not placed (occupied namespace, failed tap rebuild,
		// full pool): still a candidate that yielded no inventory.
		p.adoptYieldedNothing()
	}
	adopted.Add(1)
}

// Stop shuts the pool down. Under abandon-on-stop, warm slots are left in the
// kernel for the next process to adopt and Stop returns near-instantly —
// per-slot teardown scales with pool depth and host congestion, and vmd's
// exit gates the restart's whole unavailability window. Legacy mode drains
// both pools and cleans up every unclaimed slot.
func (p *Pool) Stop() {
	close(p.stopCh)

	if p.abandonOnStop {
		// Bounded wait purely to let in-flight goroutines observe stopCh and
		// quiesce; slots stay in the kernel either way, so an expired wait
		// abandons nothing that boot-time adoption doesn't already cover.
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(abandonStopWait):
			p.log.Warn().Msg("pool: in-flight workers still settling at exit — slots remain adoptable")
		}
		p.log.Info().Int("fresh", len(p.fresh)).Int("recycled", len(p.recycled)).
			Msg("network pool stopped (slots abandoned for adoption)")
		return
	}

	p.wg.Wait()

	close(p.fresh)
	for slot := range p.fresh {
		p.cleanup(slot)
	}
	close(p.recycled)
	for slot := range p.recycled {
		p.cleanup(slot)
	}
	p.log.Info().Msg("network pool stopped")
}

// refillStep outcomes: the worker delivered/discarded a slot and should loop,
// failed a build and should back off, or observed shutdown and should exit.
type refillOutcome int

const (
	refillOK refillOutcome = iota
	refillFailed
	refillStopped
)

func (p *Pool) refillLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		if p.refillIsPaused() {
			select {
			case <-time.After(refillFailureBackoff):
			case <-p.stopCh:
				return
			case <-ctx.Done():
				return
			}
			continue
		}
		switch p.refillStep(ctx) {
		case refillStopped:
			return
		case refillFailed:
			if !p.pauseAfterFailure(ctx) {
				return
			}
		}
	}
}

// refillStep builds and delivers (or discards) one slot while the worker is
// declared active. The active span covers construction through delivery so a
// claimant reading refillActive sees real producer state; every retry backoff
// happens in the caller, outside the span, so a pool whose workers are all
// backing off — or spinning on an unsatisfiable allocation, like an exhausted
// slot range — reads as inactive and releases claimants immediately. A full
// pool parks the worker on the send with finished inventory in hand (bounded
// overshoot of one slot per worker); parked-active is truthful, and claimants
// never wait on a full pool anyway. Built outside the select so a shutdown
// while parked can dispose of the slot instead of dropping it.
func (p *Pool) refillStep(ctx context.Context) refillOutcome {
	p.refillActive.Add(1)
	defer func() {
		p.refillActive.Add(-1)
		p.signalProgress()
	}()

	slot, err := p.allocate(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return refillStopped
		}
		p.log.Error().Err(err).Msg("pool refill failed")
		return refillFailed
	}
	if p.refillIsPaused() {
		p.cleanup(slot)
		return refillOK
	}
	select {
	case <-p.refillDrainCh():
		p.cleanup(slot)
		return refillOK
	case p.fresh <- slot:
		return refillOK
	case <-p.stopCh:
		p.stopSlot(slot)
		return refillStopped
	case <-ctx.Done():
		p.stopSlot(slot)
		return refillStopped
	}
}

// pauseAfterFailure waits out the retry backoff, reporting false when the pool
// is shutting down and the caller should give up instead of retrying.
func (p *Pool) pauseAfterFailure(ctx context.Context) bool {
	select {
	case <-time.After(refillFailureBackoff):
		return true
	case <-p.stopCh:
		return false
	case <-ctx.Done():
		return false
	}
}

func (p *Pool) allocate(ctx context.Context) (*preallocSlot, error) {
	idx, err := p.mgr.claimSlotIndex(poolOwner)
	if err != nil {
		return nil, err
	}

	// Run the full network setup (namespace, veth, TAP, nftables).
	// This is the expensive part we're moving off the hot path.
	info, vethName, err := p.mgr.setupSlot(ctx, idx)
	if err != nil {
		// Build failed — release the pool's index so it isn't leaked.
		// claimSlotIndex's nsExists guard prevents re-looping on a colliding idx.
		p.mgr.releaseIfOwned(idx, poolOwner)
		return nil, err
	}

	return &preallocSlot{idx: idx, info: info, vethName: vethName}, nil
}

func (p *Pool) cleanup(slot *preallocSlot) {
	if slot == nil || slot.info == nil {
		return
	}
	// Release the netlink handle with the slot (mirrors the VM teardown
	// path) — adopted slots each carry one, and leaking it survives the ns.
	if slot.info.Firewall != nil {
		_ = slot.info.Firewall.Close()
	}
	nsName := slot.info.Namespace
	p.mgr.cleanupFull(nsName, slot.vethName)
	// The pool slot is gone — release its index back to the recycle list.
	p.mgr.releaseIfOwned(slot.idx, poolOwner)
}
