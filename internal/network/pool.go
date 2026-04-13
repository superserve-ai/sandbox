package network

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

// PoolConfig controls the pre-allocated network slot pool.
type PoolConfig struct {
	// Size is the number of slots to keep ready. When a slot is claimed,
	// the pool refills in the background. Default: 5.
	Size int
}

// Pool pre-allocates network namespaces, veth pairs, TAP devices, and
// firewall rules so that SetupVM can claim a ready slot in microseconds
// instead of running ~11 shell commands on the hot path (~10-30ms).
//
// The pool is optional — if not started, SetupVM falls back to on-demand
// setup (the original behavior). Call StartPool after NewManager to enable.
type Pool struct {
	mgr    *Manager
	log    zerolog.Logger
	size   int
	ready  chan *preallocSlot
	stopCh chan struct{}
	wg     sync.WaitGroup
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
// initial batch is filled, then refills in the background.
func (m *Manager) StartPool(ctx context.Context, cfg PoolConfig) *Pool {
	size := cfg.Size
	if size <= 0 {
		size = 5
	}

	p := &Pool{
		mgr:    m,
		log:    m.log.With().Str("component", "net_pool").Logger(),
		size:   size,
		ready:  make(chan *preallocSlot, size),
		stopCh: make(chan struct{}),
	}

	// Fill initial batch synchronously so the pool is warm on first create.
	for i := 0; i < size; i++ {
		slot, err := p.allocate(ctx)
		if err != nil {
			p.log.Error().Err(err).Int("filled", i).Msg("initial pool fill incomplete")
			break
		}
		p.ready <- slot
	}
	p.log.Info().Int("size", len(p.ready)).Msg("network pool ready")

	// Background refill goroutine.
	p.wg.Add(1)
	go p.refillLoop(ctx)

	m.pool = p
	return p
}

// Claim takes a pre-allocated slot from the pool and assigns it to the
// given VM ID. Returns nil if the pool is empty (caller should fall back
// to on-demand SetupVM).
func (p *Pool) Claim(vmID string) *VMNetInfo {
	select {
	case slot := <-p.ready:
		// Add host-level firewall rules (requires vmID, so done at claim
		// time rather than pre-allocation time). This is one nftables call
		// (~1ms), far cheaper than the ~10-30ms full setup.
		hostCIDR := slot.info.HostIP + "/32"
		if err := p.mgr.hostFW.AddVM(vmID, slot.vethName, hostCIDR); err != nil {
			p.log.Error().Err(err).Str("vm_id", vmID).Msg("claim: AddVM firewall failed, cleaning up slot")
			p.cleanup(slot)
			return nil
		}

		p.mgr.mu.Lock()
		p.mgr.devices[vmID] = slot.info
		p.mgr.mu.Unlock()

		p.log.Debug().Str("vm_id", vmID).Int("slot", slot.idx).Msg("claimed pre-allocated slot")
		return slot.info
	default:
		return nil
	}
}

// Stop drains the pool and cleans up unclaimed slots.
func (p *Pool) Stop() {
	close(p.stopCh)
	p.wg.Wait()

	// Clean up unclaimed slots.
	close(p.ready)
	for slot := range p.ready {
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
			if len(p.ready) >= p.size {
				// Pool is full — wait for a claim before allocating more.
				select {
				case <-p.stopCh:
					return
				case <-ctx.Done():
					return
				case p.ready <- p.mustAllocate(ctx):
					// Slot consumed, loop to check if we need another.
				}
				continue
			}
			slot, err := p.allocate(ctx)
			if err != nil {
				p.log.Error().Err(err).Msg("pool refill failed")
				continue
			}
			select {
			case p.ready <- slot:
			case <-p.stopCh:
				p.cleanup(slot)
				return
			case <-ctx.Done():
				p.cleanup(slot)
				return
			}
		}
	}
}

func (p *Pool) mustAllocate(ctx context.Context) *preallocSlot {
	for {
		slot, err := p.allocate(ctx)
		if err == nil {
			return slot
		}
		p.log.Error().Err(err).Msg("pool allocate failed, retrying")
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
	// Grab a slot index from the manager's free list.
	p.mgr.mu.Lock()
	var idx int
	if len(p.mgr.freeSlots) > 0 {
		idx = p.mgr.freeSlots[len(p.mgr.freeSlots)-1]
		p.mgr.freeSlots = p.mgr.freeSlots[:len(p.mgr.freeSlots)-1]
	} else {
		if p.mgr.nextSlot > MaxSlots {
			p.mgr.mu.Unlock()
			return nil, ErrNoSlots
		}
		idx = p.mgr.nextSlot
		p.mgr.nextSlot++
	}
	p.mgr.mu.Unlock()

	// Run the full network setup (namespace, veth, TAP, nftables).
	// This is the expensive part we're moving off the hot path.
	info, vethName, err := p.mgr.setupSlot(ctx, idx)
	if err != nil {
		// Return the slot index so it can be reused.
		p.mgr.mu.Lock()
		p.mgr.freeSlots = append(p.mgr.freeSlots, idx)
		p.mgr.mu.Unlock()
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
