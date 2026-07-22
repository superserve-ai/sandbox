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

	// verifyPollInterval/verifyMaxWait tune Return's pre-recycle liveness
	// check (see verifyAndRecycle). Zero means use the package defaults;
	// tests override these to run the timeout path without a real 20s wait.
	verifyPollInterval time.Duration
	verifyMaxWait      time.Duration

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
		resetTapOnRecycle: cfg.ResetTapOnRecycle,
		abandonOnStop:     cfg.AbandonOnStop,
		resetSem:          make(chan struct{}, resetTapConcurrency),
	}
	m.pool = p

	p.log.Info().Int("target", newSize).Int("recycle_cap", recycleSize).
		Bool("reset_tap_on_recycle", p.resetTapOnRecycle).Msg("network pool starting (filling in background)")
	p.wg.Add(1)
	go func() { defer sentrylog.Recover("netpool-refill"); p.refillLoop(ctx) }()

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
			// mustAllocate returns nil at shutdown and the refill select can
			// still win the send arm — fall back to on-demand setup.
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

// verifyAndRecycle blocks (in its own goroutine, never the caller's) until
// slot's namespace has no attached processes, then makes it claimable. It
// re-kills defensively first — this is also the backstop for the DestroyVM
// paths that skip or race their own kill (an untracked VM after a vmd
// restart, or a reconciler markStale that never sent a signal at all).
//
// A namespace still occupied after verifyMaxWait isn't a slow teardown, it's
// stuck — recycling it would poison the pool, so it's torn down for real
// instead of being handed to the next VM.
func (p *Pool) verifyAndRecycle(slot *preallocSlot) {
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
			return
		}
		select {
		case <-time.After(pollInterval):
		case <-p.stopCh:
			p.stopSlot(slot)
			return
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
			return
		}
		// The semaphore is acquired before the deadline starts, so queueing
		// behind a backlog doesn't eat into a rebuild's own budget.
		select {
		case p.resetSem <- struct{}{}:
		case <-p.stopCh:
			p.stopSlot(slot)
			return
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
			return
		}
		if err != nil {
			p.log.Error().Err(err).Str("namespace", ns).Int("slot", slot.idx).
				Msg("pool: tap reset failed on recycle — tearing down instead of recycling")
			p.cleanup(slot)
			return
		}
	}

	select {
	case p.recycled <- slot:
	case <-p.stopCh:
		// Stop() closes p.recycled only after p.wg.Wait() returns, and this
		// goroutine holds a wg slot until it returns — so stopCh firing here
		// (pool shutting down mid-verify) can't race a send on a closed channel.
		p.stopSlot(slot)
	default:
		// Recycle pool full. An adopted slot is fully built, so it counts as
		// fresh inventory instead of being destroyed while the refill loop
		// rebuilds its twin from scratch; otherwise tear down (cleanup
		// releases the pool's ownership).
		if slot.adopted {
			select {
			case p.fresh <- slot:
				return
			default:
			}
		}
		p.cleanup(slot)
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
func (p *Pool) AdoptOrphanSlots(ctx context.Context) (adopted, invalid, skipped int64) {
	indexes := p.mgr.claimOrphanSlots()
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

	p.mgr.SweepStrayHostVeths()
	return adopted, invalid, skipped
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
		}
		return
	}
	p.verifyAndRecycle(&preallocSlot{
		idx:      idx,
		info:     info,
		vethName: vethName,
		adopted:  true,
	})
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

		if len(p.fresh) >= p.newSize {
			// Pool full — block until a slot is consumed or shutdown.
			select {
			case <-p.stopCh:
				return
			case <-ctx.Done():
				return
			case p.fresh <- p.mustAllocate(ctx):
			}
			continue
		}

		slot, err := p.allocate(ctx)
		if err != nil {
			p.log.Error().Err(err).Msg("pool refill failed")
			continue
		}
		select {
		case p.fresh <- slot:
		case <-p.stopCh:
			p.stopSlot(slot)
			return
		case <-ctx.Done():
			p.stopSlot(slot)
			return
		}
	}
}

func (p *Pool) mustAllocate(ctx context.Context) *preallocSlot {
	for {
		slot, err := p.allocate(ctx)
		if err == nil {
			return slot
		}
		p.log.Error().Err(err).Msg("pool allocate retry")
		select {
		case <-p.stopCh:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}
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
