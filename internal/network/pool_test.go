package network

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// stubPidsInNs overrides pidsInNsFunc for the duration of the test and
// restores it on cleanup — the seam Return's verifyAndRecycle uses instead
// of the real /proc scan, so tests can simulate an occupied or clear
// namespace without a real kernel netns/process.
func stubPidsInNs(t *testing.T, fn func(ns string) ([]int, bool)) {
	t.Helper()
	old := pidsInNsFunc
	pidsInNsFunc = fn
	t.Cleanup(func() { pidsInNsFunc = old })
}

func newTestPool(t *testing.T, m *Manager) *Pool {
	t.Helper()
	p := &Pool{
		mgr:                m,
		log:                zerolog.Nop(),
		newSize:            4,
		fresh:              make(chan *preallocSlot, 4),
		recycled:           make(chan *preallocSlot, 4),
		stopCh:             make(chan struct{}),
		verifyPollInterval: time.Millisecond,
		verifyMaxWait:      50 * time.Millisecond,
	}
	t.Cleanup(func() {
		select {
		case <-p.stopCh:
		default:
			close(p.stopCh)
		}
	})
	return p
}

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

	// A slot in the pool is owned by poolOwner (allocate → claimSlotIndex).
	// cleanup releases it back to freeSlots only because that ownership holds.
	m.assignSlotLocked(1, poolOwner)
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

// TestPoolReturn_RecyclesOnceNamespaceIsClear pins the happy path: when the
// previous occupant is already gone (the common case — its own kill already
// finished), Return still routes through verification, and the slot becomes
// claimable once that confirms the namespace is empty.
func TestPoolReturn_RecyclesOnceNamespaceIsClear(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })

	m := newTestManager()
	p := newTestPool(t, m)
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	select {
	case slot := <-p.recycled:
		if slot.idx != 1 {
			t.Errorf("recycled slot idx = %d, want 1", slot.idx)
		}
	case <-time.After(time.Second):
		t.Fatal("slot never appeared in recycled — verifyAndRecycle did not run or hung")
	}

	// Claimable means the pool, not the old VM, owns it in the meantime.
	m.mu.Lock()
	owner := m.slotOwner[1]
	m.mu.Unlock()
	if owner != poolOwner {
		t.Errorf("slotOwner[1] = %q, want poolOwner", owner)
	}
}

// TestPoolReturn_WaitsForNamespaceToClearBeforeRecycling pins the actual bug
// fix: a slot whose namespace still has an attached process (the old VM's
// Firecracker mid-death) must NOT be claimable yet, even though Return()
// already returned to its caller. It only becomes claimable once the
// namespace verifiably clears.
func TestPoolReturn_WaitsForNamespaceToClearBeforeRecycling(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")

	// 20 occupied responses at a 5ms poll interval is a ~100ms minimum before
	// verifyAndRecycle can possibly clear — comfortably longer than the
	// "not recycled yet" check below, so that check can't pass by luck of
	// goroutine scheduling.
	var calls atomic.Int32
	stubPidsInNs(t, func(string) ([]int, bool) {
		if calls.Add(1) <= 20 {
			return []int{999999}, true // still occupied for the first few checks
		}
		return nil, true
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.verifyPollInterval = 5 * time.Millisecond
	p.verifyMaxWait = 500 * time.Millisecond // > the ~100ms the stub takes to clear
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	// Return() must not hand the slot to Claim() synchronously or on the
	// first few (still-occupied) checks.
	select {
	case slot := <-p.recycled:
		t.Fatalf("slot %+v recycled while namespace still reported occupied", slot)
	case <-time.After(30 * time.Millisecond):
	}

	// Once the namespace clears, it must eventually show up.
	select {
	case slot := <-p.recycled:
		if slot.idx != 1 {
			t.Errorf("recycled slot idx = %d, want 1", slot.idx)
		}
	case <-time.After(time.Second):
		t.Fatal("slot never recycled after namespace cleared")
	}
	if got := calls.Load(); got < 4 {
		t.Errorf("pidsInNsFunc called %d times, want at least 4 (polled past the occupied checks)", got)
	}
}

// TestPoolReturn_TearsDownInsteadOfRecyclingIfNamespaceNeverClears covers the
// stuck case: a namespace that never reports clear within verifyMaxWait must
// never be handed out — it's torn down for real instead of poisoning the
// pool for the next Claim.
func TestPoolReturn_TearsDownInsteadOfRecyclingIfNamespaceNeverClears(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return []int{999999}, true }) // never clears

	m := newTestManager()
	p := newTestPool(t, m)
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	// Wait well past the (short, test-configured) verifyMaxWait=50ms for
	// verifyAndRecycle to give up and tear down instead of recycling.
	time.Sleep(300 * time.Millisecond)

	select {
	case slot := <-p.recycled:
		t.Fatalf("slot %+v recycled despite namespace never clearing", slot)
	default:
	}

	m.mu.Lock()
	_, stillOwned := m.slotOwner[1]
	freed := false
	for _, idx := range m.freeSlots {
		if idx == 1 {
			freed = true
		}
	}
	m.mu.Unlock()
	if stillOwned || !freed {
		t.Errorf("slot 1 not released to freeSlots after giving up on recycling (owned=%v freed=%v)", stillOwned, freed)
	}
}

// TestPoolReturn_FailedScanIsNotTreatedAsClear pins pidsInNs's ok=false
// contract: a transient /proc scan failure must not read as "namespace
// empty," or a still-occupied slot would get recycled — the exact race this
// whole mechanism exists to prevent. Only a successful, empty scan clears.
func TestPoolReturn_FailedScanIsNotTreatedAsClear(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")

	// 20 failed scans at a 5ms poll interval is a ~100ms minimum before
	// verifyAndRecycle can possibly clear — comfortably longer than the
	// "not recycled yet" check below.
	var calls atomic.Int32
	stubPidsInNs(t, func(string) ([]int, bool) {
		if calls.Add(1) <= 20 {
			return nil, false // scan failed — pids empty, but NOT confirmed clear
		}
		return nil, true
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.verifyPollInterval = 5 * time.Millisecond
	p.verifyMaxWait = 500 * time.Millisecond
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	select {
	case slot := <-p.recycled:
		t.Fatalf("slot %+v recycled on a failed (ok=false) scan — should have kept polling", slot)
	case <-time.After(30 * time.Millisecond):
	}

	select {
	case slot := <-p.recycled:
		if slot.idx != 1 {
			t.Errorf("recycled slot idx = %d, want 1", slot.idx)
		}
	case <-time.After(time.Second):
		t.Fatal("slot never recycled once scans started succeeding")
	}
}
