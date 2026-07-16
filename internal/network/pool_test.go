package network

import (
	"context"
	"errors"
	"fmt"
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

// stubResetTap overrides resetTapFunc for the duration of the test and restores
// it on cleanup, so the recycle path's tap0 rebuild is driven without a real
// netns/tap device.
func stubResetTap(t *testing.T, fn func(m *Manager, ctx context.Context, ns string) error) {
	t.Helper()
	old := resetTapFunc
	resetTapFunc = fn
	t.Cleanup(func() { resetTapFunc = old })
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
		resetSem:           make(chan struct{}, resetTapConcurrency),
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

// TestPoolReturn_ResetsTapBeforeRecycling: with the reset enabled, a cleared
// namespace has its tap0 rebuilt before the slot is made claimable.
func TestPoolReturn_ResetsTapBeforeRecycling(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })

	var resetNS atomic.Value
	stubResetTap(t, func(_ *Manager, _ context.Context, ns string) error {
		resetNS.Store(ns)
		return nil
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.resetTapOnRecycle = true
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	select {
	case slot := <-p.recycled:
		if slot.idx != 1 {
			t.Errorf("recycled slot idx = %d, want 1", slot.idx)
		}
	case <-time.After(time.Second):
		t.Fatal("slot never appeared in recycled — reset-then-recycle did not complete")
	}
	if got, _ := resetNS.Load().(string); got != "ns-1" {
		t.Errorf("resetTap called with ns %q, want ns-1", got)
	}
}

// TestPoolReturn_BoundsConcurrentTapResets: a mass return drives many verify
// goroutines at once, but at most resetTapConcurrency tap rebuilds may be in
// flight — the rest queue on the semaphore instead of fork-storming the host.
func TestPoolReturn_BoundsConcurrentTapResets(t *testing.T) {
	dir := withTestNetnsDir(t)
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })

	var cur, peak atomic.Int32
	stubResetTap(t, func(_ *Manager, _ context.Context, _ string) error {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		cur.Add(-1)
		return nil
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.resetTapOnRecycle = true
	p.recycled = make(chan *preallocSlot, 64) // don't trip the overflow skip

	const n = 32
	for i := 0; i < n; i++ {
		ns := fmt.Sprintf("ns-%d", i)
		touchNS(t, dir, ns)
		m.assignSlotLocked(i, "old-vm")
		p.Return(&preallocSlot{idx: i, info: &VMNetInfo{Namespace: ns}, vethName: fmt.Sprintf("veth-%d", i)})
	}
	for i := 0; i < n; i++ {
		select {
		case <-p.recycled:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d slots recycled", i, n)
		}
	}
	if got := peak.Load(); got > resetTapConcurrency {
		t.Errorf("concurrent tap resets peaked at %d, want <= %d", got, resetTapConcurrency)
	}
}

// TestPoolReturn_ReleasesResetTokenOnPanic: a panicking rebuild must release
// its semaphore token — Return's goroutine recovers panics, so a leaked token
// would permanently shrink the reset window.
func TestPoolReturn_ReleasesResetTokenOnPanic(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(_ *Manager, _ context.Context, _ string) error { panic("rebuild blew up") })

	m := newTestManager()
	p := newTestPool(t, m)
	p.resetTapOnRecycle = true
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	// Wait for the verify goroutine (it holds a wg slot through the panic
	// recovery) so the assertion — and the test's stub cleanup — can't race it.
	p.wg.Wait()
	if got := len(p.resetSem); got != 0 {
		t.Errorf("resetSem holds %d token(s) after a panicking rebuild, want 0", got)
	}
}

// TestPoolReturn_SkipsTapResetWhenRecycleFull: a slot that would overflow the
// recycle pool is torn down without paying the tap rebuild first.
func TestPoolReturn_SkipsTapResetWhenRecycleFull(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(_ *Manager, _ context.Context, _ string) error {
		t.Error("resetTap ran for a slot the full recycle pool was about to discard")
		return nil
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.resetTapOnRecycle = true
	for i := 0; i < cap(p.recycled); i++ {
		p.recycled <- &preallocSlot{idx: 100 + i, info: &VMNetInfo{Namespace: "ns-x"}}
	}
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	// Synchronize with the verify goroutine via the slot release under m.mu.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		_, owned := m.slotOwner[1]
		m.mu.Unlock()
		if !owned || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.mu.Lock()
	_, stillOwned := m.slotOwner[1]
	m.mu.Unlock()
	if stillOwned {
		t.Error("slot 1 never released — overflow cleanup did not run")
	}
}

// TestPoolReturn_TearsDownWhenTapResetFails: if tap0 can't be rebuilt, the slot
// is torn down instead of recycled — never handed to the next VM.
func TestPoolReturn_TearsDownWhenTapResetFails(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(_ *Manager, _ context.Context, _ string) error {
		return errors.New("tap busy")
	})

	m := newTestManager()
	p := newTestPool(t, m)
	p.resetTapOnRecycle = true
	m.assignSlotLocked(1, "old-vm")

	p.Return(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}, vethName: "veth-1"})

	// Let verifyAndRecycle run: it clears the namespace, fails the tap reset, and
	// tears down instead of recycling.
	time.Sleep(200 * time.Millisecond)

	select {
	case slot := <-p.recycled:
		t.Fatalf("slot idx %d was recycled despite tap reset failure", slot.idx)
	default:
	}

	// Reading the released slot under m.mu synchronizes with verifyAndRecycle's
	// teardown so the test doesn't race its goroutine on the stub globals.
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
		t.Errorf("slot 1 not released after tap reset failure (owned=%v freed=%v)", stillOwned, freed)
	}
}

// TestTeardownVM_ReclaimsSlotWithoutRecycling: a forced teardown of a suspect
// slot reclaims its index to freeSlots and never hands it to the pool, so a
// failed create's slot can't be immediately re-claimed with the same bad tap.
func TestTeardownVM_ReclaimsSlotWithoutRecycling(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	m.pool = p
	m.devices["vm-t"] = &VMNetInfo{Namespace: "ns-7", HostIP: "10.11.0.7"}
	m.assignSlotLocked(7, "vm-t")

	m.TeardownVM("vm-t")

	if _, tracked := m.devices["vm-t"]; tracked {
		t.Error("vm-t still tracked after TeardownVM")
	}
	freed := false
	for _, idx := range m.freeSlots {
		if idx == 7 {
			freed = true
		}
	}
	if !freed {
		t.Errorf("slot 7 not reclaimed to freeSlots = %v", m.freeSlots)
	}
	select {
	case slot := <-p.recycled:
		t.Fatalf("slot %+v was recycled; TeardownVM must never recycle", slot)
	default:
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
