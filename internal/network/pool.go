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
	// StartGate holds the refill and adoption workers until it is closed.
	// Both walk the whole slot inventory over netlink, and every netlink
	// operation takes the kernel's single global RTNL lock — so while they
	// run, any other caller needing that lock queues behind them. Deferring
	// them until the daemon can serve requests keeps work proportional to
	// the fleet off the startup path. Nil starts them immediately.
	StartGate <-chan struct{}
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
	// startGate delays the refill and adoption workers; see PoolConfig.
	// Nil means "already open".
	startGate <-chan struct{}
	// claimWaiters counts callers currently inside ClaimWait; producers
	// never yield to the foreground while it is non-zero (the foreground is
	// waiting on them).
	claimWaiters atomic.Int64
	// bgSlotSem meters concurrent background slot operations (adoption and
	// refill share it). A gated pool starts it at one token and ramps to
	// full over refillRampStep intervals, so the post-restart RTNL load
	// arrives gradually across BOTH producers rather than as a burst of
	// every worker at once. Nil (tests, ungated legacy construction) meters
	// nothing.
	bgSlotSem chan struct{}
	wg        sync.WaitGroup
	drainMu   sync.RWMutex
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

	// quiesced is set by Stop (abandon mode) only when every pool worker
	// joined within the bound; receiptFresh/receiptRecycled are the settled
	// channel membership drained at that moment. CommitReceipt refuses to
	// write unless quiesced — a receipt may vouch only for slots no worker
	// could still have been touching.
	quiesced        bool
	receiptFresh    []int
	receiptRecycled []int

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

// abandonStopWait bounds Stop's wait for in-flight pool goroutines under
// abandon-on-stop. It must exceed the longest operation a worker can
// legally be inside — a queued tap rebuild (resetTapTimeout) plus
// scheduling margin — because a completed join is what licenses the
// shutdown receipt: a bound shorter than legal work would silently forfeit
// the receipt on every deploy that lands during churn, exactly when it
// matters. Verify-polls waiting out a slow guest (up to verifyMaxWait) can
// still exceed this; those shutdowns forfeit the receipt deliberately
// rather than holding the restart hostage. A var so tests can bound their
// own runtime.
var abandonStopWait = 10 * time.Second

// Adoption pass phases (Pool.adoptPhase).
const (
	adoptPhaseIdle int32 = iota
	// adoptPhasePending is a pass claimed but parked behind the start gate:
	// it holds the duplicate-start guard without reading as a producer, so
	// a claimant arriving before the gate opens builds inline instead of
	// spending its wait budget on a pass that has not begun.
	adoptPhasePending
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
		startGate:         cfg.StartGate,
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
	// One shared concurrency budget across both background producers —
	// adoption and refill — granted gradually after the gate (see
	// rampBGSlots), so neither can burst the RTNL lock alone the moment the
	// daemon starts serving. Created before any worker spawns so every
	// reader sees the same channel.
	p.bgSlotSem = make(chan struct{}, workers+adoptConcurrency)
	p.wg.Add(1)
	go func() { defer sentrylog.Recover("netpool-ramp"); p.rampBGSlots(ctx, workers+adoptConcurrency) }()

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		// Declared active before the goroutine is even scheduled — a create
		// racing boot must see the pool as producing, or it commits to an
		// inline build against the imminent refill (the same synchronous
		// publication StartAdoption makes for its phase). The worker inherits
		// the declaration and relinquishes it on backoff, pause, or exit.
		//
		// Behind a start gate the refill is NOT imminent — nothing is built
		// until the gate opens — so the declaration would make a claimant
		// wait on a producer that has not started. There the worker declares
		// itself once it is past the gate and genuinely producing, and a
		// claimant arriving first correctly takes the bounded inline path.
		if p.startGate == nil {
			p.refillActive.Add(1)
		}
		go func() { defer sentrylog.Recover("netpool-refill"); p.refillLoop(ctx) }()
	}

	return p
}

// waitForStart blocks until the start gate opens. It reports false when the
// pool was stopped or the context cancelled while waiting, so a daemon that
// shuts down before the gate opens never leaves a worker parked on it.
// A nil gate is already open.
func (p *Pool) waitForStart(ctx context.Context) bool {
	if p.startGate == nil {
		return true
	}
	select {
	case <-p.startGate:
		return true
	case <-p.stopCh:
		return false
	case <-ctx.Done():
		return false
	}
}

const (
	// refillRampStep is the interval at which a gated pool's background
	// concurrency budget (bgSlotSem) grows by one token after the gate
	// opens. The gate opens at the same instant the daemon begins serving,
	// and every slot operation competes with request-path work for the
	// kernel's single RTNL lock — granting the whole budget at once would
	// aim that contention exactly at the post-restart burst. Ungated pools
	// (no restart in progress) get the full budget immediately.
	refillRampStep = 2 * time.Second
	// yieldPoll and yieldCapPerOp bound the foreground-priority pause a
	// producer takes between slots. The cap keeps continuous request
	// traffic from starving the producers: yielding is a courtesy with a
	// ceiling, after which the producer proceeds regardless.
	yieldPoll     = 25 * time.Millisecond
	yieldCapPerOp = 500 * time.Millisecond
)

// yieldToForeground briefly pauses a background producer while request-path
// network operations are in flight, giving their RTNL acquisitions priority
// over slot production. It never yields while a claimant is waiting on the
// pool: that foreground caller is waiting on this producer, and yielding to
// it would be priority inversion. Bounded by yieldCapPerOp so producers
// always make progress under sustained traffic; returns early on shutdown.
func (p *Pool) yieldToForeground(ctx context.Context) {
	deadline := time.Now().Add(yieldCapPerOp)
	for p.mgr.foregroundOps.Load() > 0 &&
		p.claimWaiters.Load() == 0 &&
		time.Now().Before(deadline) {
		select {
		case <-time.After(yieldPoll):
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// acquireBGSlot takes one background-concurrency token (and yields to any
// in-flight foreground work first). Reports false on shutdown/cancellation.
// A nil semaphore meters nothing — tests and legacy construction.
func (p *Pool) acquireBGSlot(ctx context.Context) bool {
	p.yieldToForeground(ctx)
	if p.bgSlotSem == nil {
		return true
	}
	select {
	case <-p.bgSlotSem:
		return true
	case <-p.stopCh:
		return false
	case <-ctx.Done():
		return false
	}
}

func (p *Pool) releaseBGSlot() {
	if p.bgSlotSem != nil {
		p.bgSlotSem <- struct{}{}
	}
}

// rampBGSlots grants the background concurrency budget: everything at once
// for an ungated pool, one token per refillRampStep after the gate opens for
// a gated one. Runs in the pool wait group so Stop joins it.
func (p *Pool) rampBGSlots(ctx context.Context, total int) {
	defer p.wg.Done()
	if !p.waitForStart(ctx) {
		return
	}
	granted := 0
	if p.startGate == nil {
		for ; granted < total; granted++ {
			p.bgSlotSem <- struct{}{}
		}
		return
	}
	for granted < total {
		p.bgSlotSem <- struct{}{}
		granted++
		if granted == total {
			return
		}
		select {
		case <-time.After(refillRampStep):
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
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
		p.mgr.recordNetPhase("claim_total", tDone.Sub(tEntry))
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
	// While the pressure controller has refill paused, in-flight workers'
	// output is predestined for the discard arms — active or not, they can
	// deliver nothing, so claimants must not wait on them.
	return p.refillActive.Load() > 0 && !p.refillIsPaused()
}

// adoptionTrusted reports whether claimants should treat the adoption pass as
// a producer worth waiting on: a pass is running and hasn't tripped the
// no-yield escape. Trust is reversible — a later delivery restores it.
// A pending pass (parked behind the start gate) is not running and earns no
// trust: nothing it could deliver exists yet.
func (p *Pool) adoptionTrusted() bool {
	phase := p.adoptPhase.Load()
	running := phase == adoptPhaseScanning || phase == adoptPhaseVerifying
	return running && p.adoptStreak.Load() < p.adoptEscapeStreak
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
// finalClaim is ClaimWait's last look at the pool before giving up (producers
// gone, or budget spent): a slot published in the race window since the last
// miss is consumed rather than orphaned to an inline build — unless the
// caller is already gone, in which case inventory is left for live claimants.
func (p *Pool) finalClaim(ctx context.Context, vmID string) *VMNetInfo {
	if ctx.Err() != nil {
		return nil
	}
	return p.Claim(vmID)
}

func (p *Pool) ClaimWait(ctx context.Context, vmID string) *VMNetInfo {
	// Declared for the producers' yield logic: while anyone is in here, the
	// foreground is waiting on the pool itself, and producers must run flat
	// out rather than politely yielding to the very caller they'd unblock.
	p.claimWaiters.Add(1)
	defer p.claimWaiters.Add(-1)
	start := time.Now()
	for {
		// Checked before every claim attempt, not only in the select: a
		// wakeup can race cancellation, and a dead request must never
		// consume inventory a live claimant is waiting on — the slot would
		// be assigned to a vmID whose caller has already gone away.
		if ctx.Err() != nil {
			return nil
		}
		ch := p.progressCh()
		if info := p.Claim(vmID); info != nil {
			return info
		}
		if !p.producing() {
			return p.finalClaim(ctx, vmID)
		}
		budget := poolClaimWaitBudget
		if p.adoptionTrusted() {
			budget = adoptionClaimWaitBudget
		}
		remaining := budget - time.Since(start)
		if remaining <= 0 {
			return p.finalClaim(ctx, vmID)
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

	// Trust is restored before the slot becomes visible: a claimant can
	// consume it via the broadcast or its own fallback poll the instant the
	// send lands, and the remaining waiters must never observe an empty pool
	// alongside stale distrust. The reset keys on proven validity, not
	// placement — a validated slot that finds every channel full is not
	// evidence of a yieldless pass, and a full pool has no waiters to
	// mislead.
	if slot.adopted {
		p.adoptDelivered()
	}
	select {
	case p.recycled <- slot:
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

// adoptFromReceipt consumes the previous process's receipt and, for every
// candidate it vouches for, runs cheap batched validation — plus an
// in-process firewall rebuild from current policy — and places the slot
// straight into inventory. What it skips is the expensive re-derivation:
// no kill/poll, no route-rewrite subprocesses, no tap rebuild; the receipt
// proves that state is already settled and current. Returns the remaining
// candidates (unvouched plus demoted) for the full path, and the count
// placed. All scans are batched: one netns readdir, one host-interface
// readdir, one /proc pass — the per-slot multiplier is the cost being
// removed.
func (p *Pool) adoptFromReceipt(ctx context.Context, candidates []int) (remaining []int, placed int64) {
	r, reason := consumePoolReceipt()
	if r == nil {
		if reason != "absent" {
			p.log.Warn().Str("reason", reason).Msg("pool: receipt rejected — full adoption for all candidates")
		}
		return candidates, 0
	}

	tStart := time.Now()
	vouched := make(map[int]bool, len(r.Fresh)+len(r.Recycled))
	preferRecycled := make(map[int]bool, len(r.Recycled))
	for _, idx := range r.Fresh {
		vouched[idx] = true
	}
	for _, idx := range r.Recycled {
		vouched[idx] = true
		preferRecycled[idx] = true
	}

	nsSet, occupied, ok := occupiedNamespaces()
	if !ok {
		p.log.Warn().Msg("pool: namespace/proc scan failed — receipt discarded, full adoption for all candidates")
		return candidates, 0
	}
	vethSet := make(map[string]bool)
	if veths, err := listHostVeths(); err == nil {
		for _, v := range veths {
			vethSet[v] = true
		}
	}

	var toValidate []int
	for _, idx := range candidates {
		if vouched[idx] {
			toValidate = append(toValidate, idx)
		} else {
			remaining = append(remaining, idx)
		}
	}

	var demoted, quarantined int64
	var timeouts atomic.Int64
	var mu sync.Mutex
	work := make(chan int)
	var workers sync.WaitGroup
	for i := 0; i < adoptConcurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer sentrylog.Recover("netpool-receipt-adopt")
			for idx := range work {
				slot, timedOut := p.fastAdoptVouched(idx, nsSet, vethSet, occupied)
				if timedOut {
					// The abandoned validator may still be mutating this
					// namespace; the index must not re-enter ANY path this
					// boot. Release it — the nsExists guard keeps the index
					// from being rebuilt while the namespace lives, the leak
					// gauge surfaces it, and the next boot re-adopts it.
					timeouts.Add(1)
					p.mgr.releaseIfOwned(idx, poolOwner)
					mu.Lock()
					quarantined++
					mu.Unlock()
					continue
				}
				if slot == nil {
					mu.Lock()
					remaining = append(remaining, idx)
					demoted++
					mu.Unlock()
					continue
				}
				if !p.placeVouched(slot, preferRecycled[idx]) {
					// No channel space: not a defect, just surplus. Close the
					// attached handle — the full path opens its own — and
					// route the index through it, which owns overflow
					// teardown.
					if slot.info.Firewall != nil {
						_ = slot.info.Firewall.Close()
					}
					mu.Lock()
					remaining = append(remaining, idx)
					demoted++
					mu.Unlock()
					continue
				}
				p.adoptDelivered()
				p.signalProgress()
				mu.Lock()
				placed++
				mu.Unlock()
			}
		}()
	}
feed:
	for i, idx := range toValidate {
		if timeouts.Load() >= adoptTimeoutAbort {
			// Wedges are systemic (a stuck netlink wedges every candidate)
			// and each strands a pinned thread — same reasoning as the full
			// pass's abort. The remainder goes to the full path, which has
			// its own bound and abort.
			p.log.Error().Int64("timeouts", timeouts.Load()).
				Msg("pool: receipt fast path aborting — validation timing out systemically")
			mu.Lock()
			remaining = append(remaining, toValidate[i:]...)
			mu.Unlock()
			break feed
		}
		select {
		case work <- idx:
		case <-p.stopCh:
			mu.Lock()
			remaining = append(remaining, toValidate[i:]...)
			mu.Unlock()
			break feed
		case <-ctx.Done():
			mu.Lock()
			remaining = append(remaining, toValidate[i:]...)
			mu.Unlock()
			break feed
		}
	}
	close(work)
	workers.Wait()

	p.log.Info().Int("vouched", len(toValidate)).Int64("placed", placed).
		Int64("demoted", demoted).Int64("quarantined", quarantined).
		Int("unvouched", len(candidates)-len(toValidate)).
		Int64("fast_path_ms", time.Since(tStart).Milliseconds()).
		Msg("pool: receipt fast adoption complete")
	return remaining, placed
}

// placeVouched returns a vouched slot to inventory, preferring the channel
// it occupied in its previous life; a full preferred channel falls over to
// the other (both directions are safe — the slot is fully built).
func (p *Pool) placeVouched(slot *preallocSlot, preferRecycled bool) bool {
	first, second := p.fresh, p.recycled
	if preferRecycled {
		first, second = p.recycled, p.fresh
	}
	select {
	case first <- slot:
		return true
	default:
	}
	select {
	case second <- slot:
		return true
	default:
	}
	return false
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
	tStart := time.Now()
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

	// Receipt fast path. Consumed (one-shot) and validated BEFORE the worker
	// pass; whatever it vouches for — intersected with the candidates the
	// scan actually claimed, so ownership decided above always outranks the
	// receipt — skips the paranoid rebuild and rejoins inventory after cheap
	// batched validation. Everything else, including vouched slots that fail
	// a check, takes the full path below unchanged.
	indexes, fastAdopted := p.adoptFromReceipt(ctx, indexes)
	adopted += fastAdopted

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
					// Metered by the shared background budget; a failed
					// acquire means shutdown — the slot stays claimed in
					// the kernel, the same abandoned state a mid-pass
					// shutdown leaves for the next boot to adopt.
					if !p.acquireBGSlot(ctx) {
						nSkipped.Add(1)
						continue
					}
					p.adoptOne(ctx, idx, &nAdopted, &nInvalid, &nSkipped, &nTimeouts)
					p.releaseBGSlot()
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
		// Accumulate — adopted already carries the receipt fast path's count.
		adopted += nAdopted.Load()
		invalid, skipped = nInvalid.Load(), nSkipped.Load()
	}

	p.adoptPhase.Store(adoptPhaseIdle)
	p.signalProgress()
	p.mgr.SweepStrayHostVeths()
	// Emitted on every completion path — including the receipt fast path
	// adopting all slots, or no orphans at all — so startup timing always has
	// an adoption duration, not only when the worker pass ran.
	p.log.Info().Int64("adopted", adopted).Int64("torn_down", invalid).
		Int64("skipped", skipped).Dur("duration_ms", time.Since(tStart)).
		Msg("pool: adoption pass complete")
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
	// A gated pass enters pending, not scanning: it holds the duplicate-start
	// guard, but producing()/adoptionTrusted() ignore it, so no claimant
	// spends its wait budget on work parked behind the gate. The pass
	// promotes itself to scanning only once it is genuinely running.
	claimed := adoptPhaseScanning
	if p.startGate != nil {
		claimed = adoptPhasePending
	}
	if !p.adoptPhase.CompareAndSwap(adoptPhaseIdle, claimed) {
		p.log.Warn().Msg("pool: adoption already running — duplicate start ignored")
		return false
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer sentrylog.Recover("netpool-adopt")
		if !p.waitForStart(ctx) {
			// Nothing was scanned, so the phase must not stay latched — a
			// later StartAdoption (or direct pass) must find it idle.
			p.adoptPhase.Store(adoptPhaseIdle)
			p.signalProgress()
			return
		}
		p.adoptPhase.CompareAndSwap(adoptPhasePending, adoptPhaseScanning)
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
		// Bounded wait for every mutation source (refill, verify, adoption)
		// to observe stopCh and join. Slots stay in the kernel either way —
		// an expired wait abandons nothing that boot-time adoption doesn't
		// already cover — but only a COMPLETE join permits the receipt
		// snapshot below: a worker still running could deliver or tear down
		// a slot after we recorded it, and a receipt must vouch only for
		// settled state.
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
			// Fully quiesced: nothing else touches the channels, so their
			// membership is a fact, not a race. Drain them into the snapshot
			// (the structs are abandoned regardless; only indexes matter).
			for {
				select {
				case slot := <-p.fresh:
					p.receiptFresh = append(p.receiptFresh, slot.idx)
					continue
				default:
				}
				break
			}
			for {
				select {
				case slot := <-p.recycled:
					p.receiptRecycled = append(p.receiptRecycled, slot.idx)
					continue
				default:
				}
				break
			}
			p.quiesced = true
		case <-time.After(abandonStopWait):
			p.log.Warn().Msg("pool: in-flight workers still settling at exit — slots remain adoptable, no receipt will be written")
		}
		p.log.Info().Int("fresh", len(p.receiptFresh)).Int("recycled", len(p.receiptRecycled)).
			Bool("quiesced", p.quiesced).Msg("network pool stopped (slots abandoned for adoption)")
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

// CommitReceipt writes the pool receipt as the caller's final shutdown act.
// It refuses — silently falling back to full adoption on next boot — unless
// this was an abandon-mode stop that fully quiesced, and the start-generation
// mechanism is installed. Call only after every other shutdown step has
// completed successfully; an aborted or failing shutdown must not vouch.
func (p *Pool) CommitReceipt() {
	if !p.abandonOnStop || !p.quiesced {
		return
	}
	gen, ok := readGeneration()
	if !ok {
		p.log.Info().Msg("pool: start-generation mechanism not installed — no receipt written")
		return
	}
	bootID, err := readBootID()
	if err != nil {
		p.log.Warn().Err(err).Msg("pool: boot id unreadable — no receipt written")
		return
	}
	r := &poolReceipt{
		BootID:      bootID,
		Generation:  gen,
		Fingerprint: slotPolicyFingerprint(),
		Fresh:       p.receiptFresh,
		Recycled:    p.receiptRecycled,
	}
	if err := writePoolReceipt(r); err != nil {
		p.log.Warn().Err(err).Msg("pool: receipt write failed — next boot takes the full adoption path")
		return
	}
	p.log.Info().Int("fresh", len(r.Fresh)).Int("recycled", len(r.Recycled)).
		Uint64("generation", gen).Msg("pool: receipt committed for next boot")
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
	if !p.waitForStart(ctx) {
		return
	}
	// Past the gate the worker is genuinely producing, so it publishes the
	// declaration StartPool skipped (see there for why a gated pool must not
	// declare it up front). Ungated, StartPool already published it.
	if p.startGate != nil {
		p.refillActive.Add(1)
	}
	// The worker's active declaration is continuous across successful
	// iterations — decrementing between two builds would let a delivery
	// broadcast wake claimants into the instant where the count reads zero,
	// and they would bail to inline builds against a producer that is
	// committed to its next slot. Zero is exposed only at backoff, pause,
	// and shutdown, when the pool genuinely promises nothing. The initial
	// declaration was published synchronously by StartPool (or, when gated,
	// just above); this loop only ever relinquishes and re-acquires it.
	active := true
	deactivate := func() {
		if active {
			active = false
			p.refillActive.Add(-1)
			p.signalProgress()
		}
	}
	defer deactivate()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		if p.refillIsPaused() {
			deactivate()
			select {
			case <-time.After(refillFailureBackoff):
			case <-p.stopCh:
				return
			case <-ctx.Done():
				return
			}
			continue
		}
		if !active {
			active = true
			p.refillActive.Add(1)
		}
		switch p.refillStep(ctx, deactivate) {
		case refillStopped:
			return
		case refillOK:
			p.signalProgress()
		case refillFailed:
			deactivate()
			if !p.pauseAfterFailure(ctx) {
				return
			}
		}
	}
}

// refillStep builds and delivers (or discards) one slot. The caller owns the
// worker's active declaration (continuous across successful iterations) and
// the post-delivery wakeup; every retry backoff also happens in the caller,
// outside the active span, so a pool whose workers are all backing off — or
// spinning on an unsatisfiable allocation, like an exhausted slot range —
// reads as inactive and releases claimants immediately. A full pool parks
// the worker on the send with finished inventory in hand (bounded overshoot
// of one slot per worker); parked-active is truthful, and claimants never
// wait on a full pool anyway. Built outside the select so a shutdown while
// parked can dispose of the slot instead of dropping it.
//
// deactivate is the caller's declaration-release: the paused/drain arms call
// it before tearing the doomed slot down, because cleanup can block for
// seconds and a discarding worker is not a producer anyone should wait on.
func (p *Pool) refillStep(ctx context.Context, deactivate func()) refillOutcome {
	// Metered: the build is the RTNL-heavy part. The token is returned
	// before the delivery send below — a worker parked on a full pool must
	// not hold concurrency budget the other producers could use.
	if !p.acquireBGSlot(ctx) {
		return refillStopped
	}
	slot, err := p.allocate(ctx)
	p.releaseBGSlot()
	if err != nil {
		if ctx.Err() != nil {
			return refillStopped
		}
		p.log.Error().Err(err).Msg("pool refill failed")
		return refillFailed
	}
	if p.refillIsPaused() {
		deactivate()
		p.cleanup(slot)
		return refillOK
	}
	select {
	case <-p.refillDrainCh():
		deactivate()
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
