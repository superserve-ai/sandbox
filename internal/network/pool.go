package network

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
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
}

// preallocSlot holds a fully configured network namespace ready to be
// assigned to a VM.
type preallocSlot struct {
	idx  int
	info *VMNetInfo
	// vethName is needed for cleanup if the slot is never claimed.
	vethName string
}

// StartPool creates and starts the network slot pool. Blocks until the
// initial batch of fresh slots is filled, then refills in the background.
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
		mgr:      m,
		log:      m.log.With().Str("component", "net_pool").Logger(),
		newSize:  newSize,
		fresh:    make(chan *preallocSlot, newSize),
		recycled: make(chan *preallocSlot, recycleSize),
		stopCh:   make(chan struct{}),
	}

	// Fill initial batch synchronously so the pool is warm on first create.
	// Transient slot failures don't abort — the refill loop catches up.
	filled := 0
	for i := 0; i < newSize; i++ {
		slot, err := p.allocate(ctx)
		if err != nil {
			p.log.Warn().Err(err).Int("attempt", i+1).Msg("initial pool slot failed; continuing")
			continue
		}
		p.fresh <- slot
		filled++
	}
	p.log.Info().Int("fresh", filled).Int("target", newSize).Int("recycle_cap", recycleSize).Msg("network pool ready")

	p.wg.Add(1)
	go p.refillLoop(ctx)

	m.pool = p
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
	for {
		var slot *preallocSlot

		// Prefer recycled slots — they already have host firewall rules
		// from the previous owner, which get replaced below.
		select {
		case slot = <-p.recycled:
		default:
			select {
			case slot = <-p.fresh:
			default:
				return nil
			}
		}

		// Race: ns can vanish between this check and AddVM; fc startup catches it.
		if !nsExists(slot.info.Namespace) {
			p.log.Warn().
				Str("vm_id", vmID).
				Str("namespace", slot.info.Namespace).
				Int("slot", slot.idx).
				Msg("pool: discarded phantom slot (kernel netns missing)")
			p.cleanup(slot)
			continue
		}

		// Add host-level firewall rules (requires vmID).
		hostCIDR := slot.info.HostIP + "/32"
		if err := p.mgr.hostFW.AddVM(vmID, slot.vethName, hostCIDR); err != nil {
			p.log.Error().Err(err).Str("vm_id", vmID).Msg("claim: AddVM firewall failed")
			p.cleanup(slot)
			return nil
		}

		p.mgr.mu.Lock()
		p.mgr.devices[vmID] = slot.info
		p.mgr.mu.Unlock()

		return slot.info
	}
}

// Return puts a slot back into the recycled pool after a sandbox is
// destroyed. The network namespace, veth, TAP, and nftables stay
// configured — the next Claim reuses them with zero setup cost.
// If the recycled pool is full, the slot is torn down instead.
func (p *Pool) Return(slot *preallocSlot) {
	select {
	case p.recycled <- slot:
	default:
		// Recycle pool full — tear down.
		p.cleanup(slot)
	}
}

// Stop drains both pools and cleans up unclaimed slots.
func (p *Pool) Stop() {
	close(p.stopCh)
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
			p.cleanup(slot)
			return
		case <-ctx.Done():
			p.cleanup(slot)
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
	idx, err := p.mgr.claimSlotIndex()
	if err != nil {
		return nil, err
	}

	// Run the full network setup (namespace, veth, TAP, nftables).
	// This is the expensive part we're moving off the hot path.
	info, vethName, err := p.mgr.setupSlot(ctx, idx)
	if err != nil {
		// idx stays consumed — reusing a colliding idx would loop.
		return nil, err
	}

	return &preallocSlot{idx: idx, info: info, vethName: vethName}, nil
}

func (p *Pool) cleanup(slot *preallocSlot) {
	if slot == nil || slot.info == nil {
		return
	}
	nsName := slot.info.Namespace
	p.mgr.cleanupFull(nsName, slot.vethName)
	p.mgr.mu.Lock()
	p.mgr.freeSlots = append(p.mgr.freeSlots, slot.idx)
	p.mgr.mu.Unlock()
}
