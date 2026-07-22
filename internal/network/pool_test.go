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

// stubAdoptSlot overrides adoptSlotFunc for the duration of the test, so
// adoption runs without real kernel namespaces.
func stubAdoptSlot(t *testing.T, fn func(m *Manager, ctx context.Context, idx int) (*VMNetInfo, string, error)) {
	t.Helper()
	old := adoptSlotFunc
	adoptSlotFunc = fn
	t.Cleanup(func() { adoptSlotFunc = old })
}

func TestPoolStop_AbandonLeavesSlotsOwnedAndIntact(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	// A verify goroutine is parked on an occupied namespace when Stop fires.
	stubPidsInNs(t, func(string) ([]int, bool) { return []int{1234}, true })
	m.mu.Lock()
	m.assignSlotLocked(3, poolOwner)
	m.mu.Unlock()
	p.Return(&preallocSlot{idx: 3, info: &VMNetInfo{Namespace: "ns-3"}, vethName: "veth-3"})

	// A warm slot is sitting in the fresh channel.
	m.mu.Lock()
	m.assignSlotLocked(4, poolOwner)
	m.mu.Unlock()
	p.fresh <- &preallocSlot{idx: 4, info: &VMNetInfo{Namespace: "ns-4"}, vethName: "veth-4"}

	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("abandon-on-stop Stop did not return promptly")
	}

	// Both slots must remain pool-owned (abandoned, not torn down) so the
	// next process's adoption pass finds a consistent kernel state.
	m.mu.Lock()
	o3, o4 := m.slotOwner[3], m.slotOwner[4]
	m.mu.Unlock()
	if o3 != poolOwner || o4 != poolOwner {
		t.Fatalf("abandoned slots must stay owned: slot3=%q slot4=%q", o3, o4)
	}
}

func TestPoolStop_LegacyTearsDownParkedVerify(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	stubPidsInNs(t, func(string) ([]int, bool) { return []int{1234}, true })
	m.mu.Lock()
	m.assignSlotLocked(3, poolOwner)
	m.mu.Unlock()
	p.Return(&preallocSlot{idx: 3, info: &VMNetInfo{Namespace: "ns-3"}, vethName: "veth-3"})

	p.Stop()

	m.mu.Lock()
	_, owned := m.slotOwner[3]
	m.mu.Unlock()
	if owned {
		t.Fatal("legacy Stop must tear down and release the parked slot")
	}
}

func TestAdoptOrphanSlots_ValidSlotBecomesClaimable(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	var resets atomic.Int64
	stubResetTap(t, func(*Manager, context.Context, string) error { resets.Add(1); return nil })
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	p.AdoptOrphanSlots(context.Background())

	// Adoption must force the tap rebuild even with resetTapOnRecycle off.
	if resets.Load() != 1 {
		t.Fatalf("adopted slot must rebuild its tap, got %d resets", resets.Load())
	}
	info := p.Claim("vm-new")
	if info == nil || info.Namespace != "ns-7" {
		t.Fatalf("adopted slot must be claimable, got %+v", info)
	}
	m.mu.Lock()
	owner := m.slotOwner[7]
	m.mu.Unlock()
	if owner != "vm-new" {
		t.Fatalf("claimed adopted slot must transfer ownership, got %q", owner)
	}
}

func TestAdoptOrphanSlots_InvalidSlotTornDown(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubAdoptSlot(t, func(*Manager, context.Context, int) (*VMNetInfo, string, error) {
		return nil, "", errors.New("host veth missing")
	})

	p.AdoptOrphanSlots(context.Background())

	m.mu.Lock()
	_, owned := m.slotOwner[7]
	m.mu.Unlock()
	if owned {
		t.Fatal("invalid orphan must be torn down and its index released")
	}
	if got := p.Claim("vm-new"); got != nil {
		t.Fatalf("nothing should be claimable, got %+v", got)
	}
}

func TestClaimOrphanSlots_SkipsOwnedAndBumpsHighWater(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	touchNS(t, dir, "ns-6")
	touchNS(t, dir, "not-a-slot")
	m := newTestManager()
	m.mu.Lock()
	m.assignSlotLocked(1, "vm-live") // reserved by a record: not adoptable
	m.mu.Unlock()

	got := m.claimOrphanSlots()
	if len(got) != 1 || got[0] != 6 {
		t.Fatalf("expected exactly slot 6 claimed, got %v", got)
	}
	m.mu.Lock()
	owner := m.slotOwner[6]
	next := m.nextSlot
	m.mu.Unlock()
	if owner != poolOwner {
		t.Fatalf("claimed orphan must be pool-owned, got %q", owner)
	}
	if next <= 6 {
		t.Fatalf("nextSlot must advance past adopted indexes, got %d", next)
	}
}

func TestClaimOrphanSlots_RejectsOutOfRangeIndex(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-99999999") // beyond MaxSlots: must never enter the allocator
	touchNS(t, dir, "ns-0")        // below it: the allocator starts at 1
	touchNS(t, dir, "ns-9999999999999999999999") // overflows the parse negative
	touchNS(t, dir, "ns-2")
	m := newTestManager()

	got := m.claimOrphanSlots()
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("expected only slot 2 claimed, got %v", got)
	}
	m.mu.Lock()
	_, owned := m.slotOwner[99999999]
	next := m.nextSlot
	m.mu.Unlock()
	if owned {
		t.Fatal("out-of-range index must not be claimed")
	}
	if next > MaxSlots {
		t.Fatalf("high-water mark must stay within the allocator range, got %d", next)
	}
}

func TestClaimOrphanSlots_CeilingIndexIsAdoptable(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, fmt.Sprintf("ns-%d", MaxSlots)) // the allocator hands out MaxSlots itself
	m := newTestManager()

	got := m.claimOrphanSlots()
	if len(got) != 1 || got[0] != MaxSlots {
		t.Fatalf("the inclusive ceiling index must be adoptable, got %v", got)
	}
}

func TestClaimOrphanSlots_OwnedOutOfRangeSurvives(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-99999998")
	m := newTestManager()
	m.mu.Lock()
	m.assignSlotLocked(99999998, "vm-live") // e.g. a record above a lowered ceiling
	m.mu.Unlock()

	if got := m.claimOrphanSlots(); len(got) != 0 {
		t.Fatalf("owned namespace must never be a candidate, got %v", got)
	}
	m.mu.Lock()
	owner := m.slotOwner[99999998]
	m.mu.Unlock()
	if owner != "vm-live" {
		t.Fatalf("ownership must be untouched, got %q", owner)
	}
}

func TestAdoptOrphanSlots_OverflowLandsInFresh(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	// Recycle channel already full: the adopted slot must become fresh
	// inventory, not be destroyed while refill would rebuild its twin.
	for i := 0; i < cap(p.recycled); i++ {
		p.recycled <- &preallocSlot{idx: 100 + i, info: &VMNetInfo{Namespace: "ns-x"}}
	}
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		return &VMNetInfo{Namespace: nsNameForSlot(idx)}, vethNameForSlot(idx), nil
	})

	adopted, invalid, _ := p.AdoptOrphanSlots(context.Background())
	if adopted != 1 || invalid != 0 {
		t.Fatalf("expected 1 adopted / 0 torn down, got %d/%d", adopted, invalid)
	}
	if len(p.fresh) != 1 {
		t.Fatalf("overflow adoptee must land in the fresh channel, got %d", len(p.fresh))
	}
}

func TestAdoptOrphanSlots_TimeoutSkipsAndReleases(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubAdoptSlot(t, func(*Manager, context.Context, int) (*VMNetInfo, string, error) {
		return nil, "", fmt.Errorf("host veth check: %w", context.DeadlineExceeded)
	})

	adopted, invalid, skipped := p.AdoptOrphanSlots(context.Background())
	if adopted != 0 || invalid != 0 || skipped != 1 {
		t.Fatalf("timeout must skip, not tear down: adopted=%d invalid=%d skipped=%d", adopted, invalid, skipped)
	}
	// Released for a later pass, namespace left intact for the leak gauge
	// and the next boot.
	m.mu.Lock()
	_, owned := m.slotOwner[7]
	m.mu.Unlock()
	if owned {
		t.Fatal("timed-out slot must be released, not held")
	}
}

func TestAdoptOrphanSlots_WorkerPanicReleasesAndContinues(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	touchNS(t, dir, "ns-8")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		if idx == 7 {
			panic("unexpected kernel state")
		}
		return &VMNetInfo{Namespace: nsNameForSlot(idx)}, vethNameForSlot(idx), nil
	})

	adopted, _, skipped := p.AdoptOrphanSlots(context.Background())
	if adopted != 1 || skipped != 1 {
		t.Fatalf("panic must be contained per slot: adopted=%d skipped=%d", adopted, skipped)
	}
	m.mu.Lock()
	_, owned7 := m.slotOwner[7]
	m.mu.Unlock()
	if owned7 {
		t.Fatal("panicked slot must be released so it isn't stranded invisibly")
	}
}

// Systemic validation timeouts (a wedged host) must abort the pass instead of
// stranding one pinned thread per candidate; the remainder is released so
// nothing stays pool-owned and invisible.
func TestAdoptOrphanSlots_SystemicTimeoutsAbortPass(t *testing.T) {
	dir := withTestNetnsDir(t)
	for i := 1; i <= 12; i++ {
		touchNS(t, dir, fmt.Sprintf("ns-%d", i))
	}
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubAdoptSlot(t, func(*Manager, context.Context, int) (*VMNetInfo, string, error) {
		return nil, "", fmt.Errorf("wedged: %w", context.DeadlineExceeded)
	})

	adopted, invalid, skipped := p.AdoptOrphanSlots(context.Background())
	if adopted != 0 || invalid != 0 {
		t.Fatalf("wedged host must not adopt or tear down: adopted=%d invalid=%d", adopted, invalid)
	}
	if skipped != 12 {
		t.Fatalf("every candidate must end up skipped (judged or released), got %d", skipped)
	}
	m.mu.Lock()
	stranded := 0
	for idx, owner := range m.slotOwner {
		if owner == poolOwner {
			stranded++
			t.Logf("stranded slot %d", idx)
		}
	}
	m.mu.Unlock()
	if stranded != 0 {
		t.Fatalf("aborted pass must release every claimed index, %d stranded", stranded)
	}
}
