package network

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestPoolClaim_DiscardsPhantomReturnsNil(t *testing.T) {
	withTestNetnsDir(t) // no fake ns-1 → ns-1 looks gone from kernel
	m := newTestManager()

	p := &Pool{
		mgr:      m,
		log:      zerolog.Nop(),
		newSize:  4,
		fresh:    make(chan *preallocSlot, 4),
		recycled: make(chan *preallocSlot, 4),
		stopCh:   make(chan struct{}),
	}

	p.fresh <- &preallocSlot{
		idx:      1,
		info:     &VMNetInfo{Namespace: "ns-1", HostIP: "10.11.0.1"},
		vethName: "veth-1",
	}

	got := p.Claim("vm-x")
	if got != nil {
		t.Fatalf("expected nil (only phantom available), got %+v", got)
	}
	if len(m.freeSlots) != 1 || m.freeSlots[0] != 1 {
		t.Errorf("freeSlots = %v, want [1] (phantom idx returned)", m.freeSlots)
	}
}

func TestPoolClaim_EmptyChannelsReturnsNil(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()

	p := &Pool{
		mgr:      m,
		log:      zerolog.Nop(),
		newSize:  4,
		fresh:    make(chan *preallocSlot, 4),
		recycled: make(chan *preallocSlot, 4),
		stopCh:   make(chan struct{}),
	}

	if got := p.Claim("vm-x"); got != nil {
		t.Errorf("expected nil from empty pool, got %+v", got)
	}
}
