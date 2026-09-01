package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
		refillDrainGate:    make(chan struct{}),
		verifyPollInterval: time.Millisecond,
		verifyMaxWait:      50 * time.Millisecond,
		resetSem:           make(chan struct{}, resetTapConcurrency),
		adoptEscapeStreak:  defaultAdoptEscapeStreak,
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

// A refill worker that was already blocked on a full pool must observe a
// drain and drop the built slot instead of replacing the one the controller
// just removed.
func TestPoolDrainRejectsBlockedRefillSend(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	for i := 0; i < cap(p.fresh); i++ {
		p.fresh <- &preallocSlot{}
	}

	dropped := make(chan struct{})
	errCh := make(chan string, 1)
	started := make(chan struct{})
	go func() {
		slot := &preallocSlot{}
		close(started)
		select {
		case p.fresh <- slot:
			errCh <- "blocked refill send should not succeed once drain starts"
		case <-p.refillDrainCh():
			close(dropped)
		case <-p.stopCh:
		}
	}()
	<-started
	time.Sleep(25 * time.Millisecond)

	if drained := p.drain(1); drained != 1 {
		t.Fatalf("drain = %d, want 1", drained)
	}

	select {
	case <-dropped:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked refill send did not observe drain")
	}
	select {
	case msg := <-errCh:
		t.Fatal(msg)
	default:
	}
	if got := len(p.fresh); got != 3 {
		t.Fatalf("fresh pool depth = %d, want 3 after draining one slot", got)
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
	touchNS(t, dir, "ns-99999999")               // beyond MaxSlots: must never enter the allocator
	touchNS(t, dir, "ns-0")                      // below it: the allocator starts at 1
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

// TestClaimWait_ConsumesProducedSlot pins the deploy-window contract: a
// claimant that finds the pool momentarily empty while producers are running
// waits and consumes their next slot instead of falling back to an inline
// build — the fallback commitment is what turned restart windows into
// tens-of-seconds creates.
func TestClaimWait_ConsumesProducedSlot(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	p.adoptPhase.Store(adoptPhaseScanning) // producers active, nothing delivered yet
	touchNS(t, dir, "ns-1")
	m.assignSlotLocked(1, poolOwner)
	go func() {
		time.Sleep(60 * time.Millisecond) // slot lands mid-wait
		p.fresh <- &preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1", HostIP: "10.11.0.1"}, vethName: "veth-1"}
		p.signalProgress()
	}()

	tStart := time.Now()
	got := p.ClaimWait(context.Background(), "vm-x")
	if got == nil {
		t.Fatal("ClaimWait returned nil while a producer was delivering")
	}
	if got.Namespace != "ns-1" {
		t.Fatalf("claimed %q, want ns-1", got.Namespace)
	}
	if waited := time.Since(tStart); waited > time.Second {
		t.Fatalf("took %v, want roughly the producer's 60ms delivery", waited)
	}
}

// TestClaimWait_NoDeclaredProducersReturnsImmediately pins the no-regression
// contract: when no producer has declared itself active — refill workers all
// idle or backing off, no adoption pass — ClaimWait must not burn its budget.
// The pool being below target is NOT evidence of production; only a declared
// worker is.
func TestClaimWait_NoDeclaredProducersReturnsImmediately(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m) // empty, below target, but zero declared producers

	tStart := time.Now()
	if got := p.ClaimWait(context.Background(), "vm-x"); got != nil {
		t.Fatalf("expected nil from a pool with no active producers, got %+v", got)
	}
	if waited := time.Since(tStart); waited > 500*time.Millisecond {
		t.Fatalf("producerless pool held the claimant %v; must return without waiting", waited)
	}
}

// TestClaimWait_SlowProducerStillWins pins the fix for the false-stall
// regression: a single healthy build that takes longer than any polling
// heuristic (here 900ms) must still be consumed by the waiting claimant,
// because the worker's declared active state — not elapsed silence — is what
// claimants trust.
func TestClaimWait_SlowProducerStillWins(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	p.refillActive.Add(1) // one worker declared mid-build
	touchNS(t, dir, "ns-2")
	m.assignSlotLocked(2, poolOwner)
	go func() {
		time.Sleep(900 * time.Millisecond) // slow but healthy build
		p.fresh <- &preallocSlot{idx: 2, info: &VMNetInfo{Namespace: "ns-2", HostIP: "10.11.0.2"}, vethName: "veth-2"}
		p.refillActive.Add(-1)
		p.signalProgress()
	}()

	got := p.ClaimWait(context.Background(), "vm-x")
	if got == nil {
		t.Fatal("ClaimWait gave up on a declared, delivering producer")
	}
	if got.Namespace != "ns-2" {
		t.Fatalf("claimed %q, want ns-2", got.Namespace)
	}
}

// TestClaimWait_FinalClaimBeatsDeactivationRace pins the handoff edge: a slot
// present in the pool must be won even when every producer reads inactive —
// a producer can publish immediately before clearing its active state, and
// the final Claim is what keeps that slot from being orphaned to an inline
// build.
func TestClaimWait_FinalClaimBeatsDeactivationRace(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	touchNS(t, dir, "ns-3")
	m.assignSlotLocked(3, poolOwner)
	p.fresh <- &preallocSlot{idx: 3, info: &VMNetInfo{Namespace: "ns-3", HostIP: "10.11.0.3"}, vethName: "veth-3"}

	if got := p.ClaimWait(context.Background(), "vm-x"); got == nil || got.Namespace != "ns-3" {
		t.Fatalf("delivered slot must be claimed even with all producers inactive, got %+v", got)
	}
}

// TestClaimWait_BurstConsumesExactlyWhatProducersDeliver pins the storm
// contract this path exists for: a burst of claimants against a producing
// pool must drain the producers' output exactly — every delivered slot
// claimed by exactly one claimant, every unlucky claimant falling back once
// production ends — with no slot lost and no double-claim.
func TestClaimWait_BurstConsumesExactlyWhatProducersDeliver(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.fresh = make(chan *preallocSlot, 32)  // room for the whole delivery
	p.adoptPhase.Store(adoptPhaseVerifying) // boot-shaped: adoption producing

	const claimants, delivered = 20, 10
	for i := 1; i <= delivered; i++ {
		touchNS(t, dir, fmt.Sprintf("ns-%d", i))
		m.assignSlotLocked(i, poolOwner)
	}
	go func() {
		for i := 1; i <= delivered; i++ {
			time.Sleep(15 * time.Millisecond) // trickle in mid-wait
			p.fresh <- &preallocSlot{idx: i, info: &VMNetInfo{Namespace: fmt.Sprintf("ns-%d", i)}, vethName: fmt.Sprintf("veth-%d", i)}
			p.signalProgress()
		}
		p.adoptPhase.Store(adoptPhaseIdle) // pass over — losers must stop waiting
		p.signalProgress()
	}()

	results := make(chan *VMNetInfo, claimants)
	for i := 0; i < claimants; i++ {
		go func(n int) {
			results <- p.ClaimWait(context.Background(), fmt.Sprintf("vm-%d", n))
		}(i)
	}

	won := map[string]bool{}
	var lost int
	for i := 0; i < claimants; i++ {
		if info := <-results; info == nil {
			lost++
		} else if won[info.Namespace] {
			t.Fatalf("namespace %s claimed twice", info.Namespace)
		} else {
			won[info.Namespace] = true
		}
	}
	if len(won) != delivered || lost != claimants-delivered {
		t.Fatalf("won=%d lost=%d, want %d/%d", len(won), lost, delivered, claimants-delivered)
	}
}

// TestClaimWait_BudgetFollowsTrust pins the escape contract: a claimant that
// began waiting on a trusted adoption pass must be released promptly — not
// after the full adoption budget — when the pass trips its no-yield escape
// mid-wait.
func TestClaimWait_BudgetFollowsTrust(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.adoptEscapeStreak = 1
	p.adoptPhase.Store(adoptPhaseVerifying) // trusted at wait start

	go func() {
		time.Sleep(150 * time.Millisecond)
		p.adoptYieldedNothing() // trips the escape at streak 1
	}()

	tStart := time.Now()
	got := p.ClaimWait(context.Background(), "vm-x")
	waited := time.Since(tStart)
	if got != nil {
		t.Fatalf("expected nil from an escaping pass, got %+v", got)
	}
	if waited >= poolClaimWaitBudget {
		t.Fatalf("claimant held %v after trust was lost; must release well before the %v normal budget",
			waited, poolClaimWaitBudget)
	}
}

// TestAdoptTrust_EscapeIsReversible pins the trust state machine: the streak
// trips the escape at the configured limit, any delivery resets both streak
// and escape, and a fresh streak can trip it again.
func TestAdoptTrust_EscapeIsReversible(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.adoptEscapeStreak = 3
	p.adoptPhase.Store(adoptPhaseVerifying)

	for i := 0; i < 2; i++ {
		p.adoptYieldedNothing()
	}
	if !p.adoptionTrusted() {
		t.Fatal("trust lost before the streak limit")
	}
	p.adoptYieldedNothing()
	if p.adoptionTrusted() {
		t.Fatal("streak limit reached but trust not suspended")
	}
	p.adoptDelivered()
	if !p.adoptionTrusted() {
		t.Fatal("delivery must restore trust")
	}
	if p.adoptStreak.Load() != 0 {
		t.Fatalf("delivery must reset the streak, got %d", p.adoptStreak.Load())
	}
}

// TestStartAdoption_PhaseVisibleBeforeReturn pins the startup-race fix: the
// pass must be observable as underway the moment StartAdoption returns —
// before its goroutine is ever scheduled — and a duplicate start must not
// spawn a second pass.
func TestStartAdoption_PhaseVisibleBeforeReturn(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-5")
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	var passes atomic.Int64
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		passes.Add(1)
		time.Sleep(100 * time.Millisecond) // hold the pass open for the assertions
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	if !p.StartAdoption(context.Background()) {
		t.Fatal("first StartAdoption must begin a pass")
	}
	if p.adoptPhase.Load() == adoptPhaseIdle {
		t.Fatal("pass must be visible before StartAdoption returns")
	}
	if p.StartAdoption(context.Background()) {
		t.Fatal("duplicate StartAdoption must no-op")
	}

	// Wait on the goroutine, not the phase: idle is set before the final veth
	// sweep, so a phase poll can release the test while the pass still runs.
	p.wg.Wait()
	if p.adoptPhase.Load() != adoptPhaseIdle {
		t.Fatal("pass never returned to idle")
	}
	if got := passes.Load(); got != 1 {
		t.Fatalf("adopted %d times, want exactly 1 candidate processed by exactly 1 pass", got)
	}
}

// BenchmarkClaimWaitBurst measures the broadcast-wakeup storm the design
// accepts: every delivered slot wakes every waiter. One iteration is a full
// burst — all claimants are parked in the wait loop BEFORE the timer starts
// (untimed settle sleep), and the fresh channel has capacity one so each
// delivery must be consumed before the next lands. Losers therefore really
// sleep and really wake per delivery; ns/op and allocs/op quantify exactly
// the churn a wake-one design would remove.
func BenchmarkClaimWaitBurst(b *testing.B) {
	const claimants, delivered = 200, 100

	oldNs, oldHost := netnsDir, hostNetDir
	defer func() { netnsDir, hostNetDir = oldNs, oldHost }()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		netnsDir, hostNetDir = b.TempDir(), b.TempDir()
		m := newTestManager()
		p := &Pool{
			mgr:               m,
			log:               zerolog.Nop(),
			newSize:           delivered,
			fresh:             make(chan *preallocSlot, 1), // forces paced, per-delivery consumption
			recycled:          make(chan *preallocSlot, 1),
			stopCh:            make(chan struct{}),
			refillDrainGate:   make(chan struct{}),
			resetSem:          make(chan struct{}, resetTapConcurrency),
			adoptEscapeStreak: defaultAdoptEscapeStreak,
		}
		p.adoptPhase.Store(adoptPhaseVerifying)
		for j := 1; j <= delivered; j++ {
			f, err := os.Create(filepath.Join(netnsDir, fmt.Sprintf("ns-%d", j)))
			if err != nil {
				b.Fatal(err)
			}
			_ = f.Close()
			m.assignSlotLocked(j, poolOwner)
		}

		var wg sync.WaitGroup
		for c := 0; c < claimants; c++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				p.ClaimWait(context.Background(), fmt.Sprintf("vm-%d", n))
			}(c)
		}
		// Untimed settle: every claimant finds the pool empty and parks in
		// the wait select before the first delivery is timed.
		time.Sleep(50 * time.Millisecond)
		b.StartTimer()

		for j := 1; j <= delivered; j++ {
			p.fresh <- &preallocSlot{idx: j, info: &VMNetInfo{Namespace: fmt.Sprintf("ns-%d", j)}, vethName: fmt.Sprintf("veth-%d", j)}
			p.signalProgress()
		}
		p.adoptPhase.Store(adoptPhaseIdle)
		p.signalProgress()
		wg.Wait()
		b.StopTimer()
		close(p.stopCh)
	}
}

// The start gate holds fleet-sized background work until the daemon is ready
// to serve. It must release on the gate, and it must not strand a worker when
// the daemon shuts down before readiness is ever announced.
func TestPoolWaitForStart(t *testing.T) {
	newPool := func(gate <-chan struct{}) *Pool {
		return &Pool{log: zerolog.Nop(), stopCh: make(chan struct{}), startGate: gate}
	}

	t.Run("nil gate is already open", func(t *testing.T) {
		if !newPool(nil).waitForStart(context.Background()) {
			t.Fatal("nil gate must not block")
		}
	})

	t.Run("closed gate releases", func(t *testing.T) {
		gate := make(chan struct{})
		close(gate)
		if !newPool(gate).waitForStart(context.Background()) {
			t.Fatal("closed gate must release")
		}
	})

	t.Run("releases when the gate opens later", func(t *testing.T) {
		gate := make(chan struct{})
		p := newPool(gate)
		done := make(chan bool, 1)
		go func() { done <- p.waitForStart(context.Background()) }()
		select {
		case <-done:
			t.Fatal("released before the gate opened")
		case <-time.After(20 * time.Millisecond):
		}
		close(gate)
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("waitForStart reported failure after the gate opened")
			}
		case <-time.After(time.Second):
			t.Fatal("still parked after the gate opened")
		}
	})

	t.Run("stop releases the waiter", func(t *testing.T) {
		p := newPool(make(chan struct{})) // never opened
		done := make(chan bool, 1)
		go func() { done <- p.waitForStart(context.Background()) }()
		close(p.stopCh)
		select {
		case ok := <-done:
			if ok {
				t.Fatal("stop must report the gate never opened")
			}
		case <-time.After(time.Second):
			t.Fatal("shutdown before readiness stranded a worker")
		}
	})

	t.Run("context cancellation releases the waiter", func(t *testing.T) {
		p := newPool(make(chan struct{})) // never opened
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool, 1)
		go func() { done <- p.waitForStart(ctx) }()
		cancel()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("cancellation must report the gate never opened")
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation stranded a worker")
		}
	})
}

// A gated pool must not advertise itself as producing before it can produce:
// a claimant that sees a producer waits for it, and nothing is built until
// the gate opens. Declaring early would trade a bounded inline build for a
// stall on a worker that has not started.
func TestGatedRefillDeclaresNoProducerBeforeRelease(t *testing.T) {
	p := &Pool{log: zerolog.Nop(), stopCh: make(chan struct{}), startGate: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	p.wg.Add(1)
	go p.refillLoop(ctx)

	time.Sleep(20 * time.Millisecond)
	if got := p.refillActive.Load(); got != 0 {
		t.Fatalf("refillActive = %d while gated, want 0", got)
	}

	cancel()
	waited := make(chan struct{})
	go func() { p.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("gated worker did not exit on cancellation")
	}
	if got := p.refillActive.Load(); got != 0 {
		t.Fatalf("refillActive = %d after exit, want 0", got)
	}
}

// A gated adoption pass holds the duplicate-start guard but must not read as
// a producer while parked: a claimant that trusts it waits out the adoption
// budget on work that has not begun.
func TestGatedAdoptionNotProducingBeforeRelease(t *testing.T) {
	gate := make(chan struct{})
	p := &Pool{
		log:               zerolog.Nop(),
		stopCh:            make(chan struct{}),
		startGate:         gate,
		adoptEscapeStreak: defaultAdoptEscapeStreak,
	}

	if !p.StartAdoption(context.Background()) {
		t.Fatal("first StartAdoption must claim the pass")
	}
	if p.StartAdoption(context.Background()) {
		t.Fatal("duplicate StartAdoption must be refused while parked")
	}
	if p.adoptionTrusted() {
		t.Fatal("a parked adoption pass must not be trusted")
	}
	if p.producing() {
		t.Fatal("a parked adoption pass must not read as producing")
	}

	// Shutdown before the gate ever opens: the pass must resolve to idle so
	// nothing later waits on it — and a fresh start must be claimable again.
	close(p.stopCh)
	waited := make(chan struct{})
	go func() { p.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("parked adoption did not exit on stop")
	}
	if got := p.adoptPhase.Load(); got != adoptPhaseIdle {
		t.Fatalf("adoptPhase = %d after stop, want idle", got)
	}
}

// The background concurrency budget stays at zero while the gate is closed,
// grants its first token promptly on release, and its feeder joins cleanly on
// stop mid-ramp.
func TestBGSlotBudgetRampsAfterGate(t *testing.T) {
	gate := make(chan struct{})
	p := &Pool{
		log:       zerolog.Nop(),
		stopCh:    make(chan struct{}),
		startGate: gate,
		bgSlotSem: make(chan struct{}, 3),
	}
	p.wg.Add(1)
	go p.rampBGSlots(context.Background(), 3)

	time.Sleep(20 * time.Millisecond)
	if got := len(p.bgSlotSem); got != 0 {
		t.Fatalf("budget = %d tokens while gated, want 0", got)
	}

	close(gate)
	select {
	case <-p.bgSlotSem:
	case <-time.After(time.Second):
		t.Fatal("no token granted after the gate opened")
	}

	close(p.stopCh)
	waited := make(chan struct{})
	go func() { p.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("ramp feeder did not exit on stop")
	}
}

// A panic inside metered work must not leak the token: the workers' panic
// recovery keeps the daemon alive, and a leaked token would shrink the
// background budget for the rest of the process's life.
func TestWithBGSlotReturnsTokenOnPanic(t *testing.T) {
	p := &Pool{
		mgr:       &Manager{}, // yieldToForeground reads its counters
		log:       zerolog.Nop(),
		stopCh:    make(chan struct{}),
		bgSlotSem: make(chan struct{}, 1),
	}
	p.bgSlotSem <- struct{}{} // full budget: one token

	ran := false
	func() {
		defer func() {
			// Specifically fn's panic — anything else means the panic fired
			// before the token was even acquired and the test proved nothing.
			if r := recover(); r != "boom" {
				t.Fatalf("recovered %v, want the fn panic", r)
			}
		}()
		p.withBGSlot(context.Background(), func() { ran = true; panic("boom") })
	}()
	if !ran {
		t.Fatal("fn never ran — the token was never at risk")
	}

	select {
	case <-p.bgSlotSem:
	default:
		t.Fatal("token not returned after panic")
	}
}

// Adoption owns the startup deficit; refill is the fallback. While a boot
// adoption pass is planned but unresolved, a refill worker must not get past
// the handoff — otherwise both producers solve the same deficit and refill
// rebuilds, at full cost, the very slots adoption is restoring.
func TestRefillDefersToStartupAdoption(t *testing.T) {
	newPool := func() *Pool {
		return &Pool{
			log:                 zerolog.Nop(),
			stopCh:              make(chan struct{}),
			startGate:           make(chan struct{}),
			startupAdoptionDone: make(chan struct{}),
			adoptEscapeStreak:   defaultAdoptEscapeStreak,
		}
	}

	t.Run("no pass planned: immediate", func(t *testing.T) {
		p := newPool()
		if !p.waitForStartupAdoption(context.Background()) {
			t.Fatal("refill must proceed when no boot adoption was planned")
		}
	})

	t.Run("nil handoff channel: immediate", func(t *testing.T) {
		p := &Pool{log: zerolog.Nop(), stopCh: make(chan struct{})}
		p.startupAdoptionPlanned.Store(true)
		if !p.waitForStartupAdoption(context.Background()) {
			t.Fatal("a pool without a handoff channel has no waiters to hold")
		}
	})

	t.Run("planned pass holds refill until resolved", func(t *testing.T) {
		p := newPool()
		if !p.StartAdoption(context.Background()) {
			t.Fatal("StartAdoption must claim the pass")
		}
		done := make(chan bool, 1)
		go func() { done <- p.waitForStartupAdoption(context.Background()) }()
		select {
		case <-done:
			t.Fatal("refill released while the pass was still parked")
		case <-time.After(20 * time.Millisecond):
		}
		// The pass is parked behind the never-opened gate; stopping resolves
		// the handoff through the unconditional defer.
		close(p.stopCh)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handoff never resolved after the pass exited")
		}
	})

	t.Run("refill worker allocates nothing before handoff", func(t *testing.T) {
		gate := make(chan struct{})
		p := newPool()
		p.startGate = gate
		p.startupAdoptionPlanned.Store(true)
		ctx, cancel := context.WithCancel(context.Background())
		p.wg.Add(1)
		go p.refillLoop(ctx)

		close(gate) // gate opens; handoff still unresolved
		time.Sleep(20 * time.Millisecond)
		// Past the handoff the worker's first act is declaring refillActive;
		// zero means it never reached the build loop, so no allocation was
		// possible.
		if got := p.refillActive.Load(); got != 0 {
			t.Fatalf("refillActive = %d while adoption unresolved, want 0", got)
		}

		cancel()
		waited := make(chan struct{})
		go func() { p.wg.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(time.Second):
			t.Fatal("parked refill worker did not exit on cancellation")
		}
	})

	t.Run("cancellation resolves the handoff", func(t *testing.T) {
		p := newPool()
		ctx, cancel := context.WithCancel(context.Background())
		if !p.StartAdoption(ctx) {
			t.Fatal("StartAdoption must claim the pass")
		}
		cancel() // pass parked behind the gate exits via ctx
		select {
		case <-p.startupAdoptionDone:
		case <-time.After(time.Second):
			t.Fatal("handoff unresolved after cancellation")
		}
		// Idempotent: repeated finishes must not panic.
		p.finishStartupAdoption()
		p.finishStartupAdoption()
	})
}

// stubPoolAllocate replaces fresh slot construction with a counter that
// returns inert slots (nil info short-circuits every cleanup path), so tests
// can measure exactly how many builds refill performs.
func stubPoolAllocate(t *testing.T) *atomic.Int64 {
	t.Helper()
	var builds atomic.Int64
	old := poolAllocateFunc
	poolAllocateFunc = func(p *Pool, ctx context.Context) (*preallocSlot, error) {
		builds.Add(1)
		return &preallocSlot{idx: int(builds.Load())}, nil
	}
	t.Cleanup(func() { poolAllocateFunc = old })
	return &builds
}

// The incident regression: after a recovery pass that restores the whole
// pool, refill must build at most one in-hand slot per worker — never the
// pool-sized burst the producer race caused. With K slots consumed during
// recovery, the bound is K plus the worker count.
func TestRefillBuildsOnlyTheDeficitAfterAdoption(t *testing.T) {
	const capacity, workers, claimed = 8, 4, 3
	for _, tc := range []struct {
		name     string
		consume  int
		maxBuild int64
	}{
		{"perfect recovery, no claims", 0, workers},
		{"perfect recovery, K claims", claimed, claimed + workers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builds := stubPoolAllocate(t)
			gate := make(chan struct{})
			p := &Pool{
				mgr:                 &Manager{}, // yieldToForeground reads its counters
				log:                 zerolog.Nop(),
				newSize:             capacity,
				fresh:               make(chan *preallocSlot, capacity),
				recycled:            make(chan *preallocSlot, capacity),
				stopCh:              make(chan struct{}),
				startGate:           gate,
				startupAdoptionDone: make(chan struct{}),
				refillDrainGate:     make(chan struct{}),
				adoptEscapeStreak:   defaultAdoptEscapeStreak,
			}
			p.startupAdoptionPlanned.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for i := 0; i < workers; i++ {
				p.wg.Add(1)
				go p.refillLoop(ctx)
			}

			close(gate)
			time.Sleep(20 * time.Millisecond)
			if got := builds.Load(); got != 0 {
				t.Fatalf("refill built %d slots before the handoff, want 0", got)
			}

			// The recovery pass restores the full pool, minus what claims
			// consumed while it ran, then hands off.
			for i := 0; i < capacity-tc.consume; i++ {
				p.fresh <- &preallocSlot{idx: 1000 + i}
			}
			p.finishStartupAdoption()

			deadline := time.After(2 * time.Second)
			for len(p.fresh) < capacity {
				select {
				case <-deadline:
					t.Fatalf("pool never refilled: fresh=%d builds=%d", len(p.fresh), builds.Load())
				case <-time.After(5 * time.Millisecond):
				}
			}
			time.Sleep(50 * time.Millisecond) // let parked overshoot settle
			if got := builds.Load(); got > tc.maxBuild {
				t.Fatalf("refill built %d slots, want <= %d", got, tc.maxBuild)
			}

			close(p.stopCh)
			waited := make(chan struct{})
			go func() { p.wg.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(2 * time.Second):
				t.Fatal("workers did not join after stop")
			}
		})
	}
}

// StartAdoption's planned-flag write must be race-safe against concurrent
// handoff readers — the interleaving an ungated pool's already-running
// workers produce. The readers here call waitForStartupAdoption directly
// (the adoption pass itself stays parked behind an unopened gate), so this
// validates the concurrent flag access, not the full ungated StartPool flow.
func TestStartAdoptionPlannedFlagIsRaceSafe(t *testing.T) {
	p := &Pool{
		log:                 zerolog.Nop(),
		stopCh:              make(chan struct{}),
		startGate:           make(chan struct{}), // never opened: the pass parks harmlessly
		startupAdoptionDone: make(chan struct{}),
		adoptEscapeStreak:   defaultAdoptEscapeStreak,
	}
	ctx, cancel := context.WithCancel(context.Background())

	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			p.waitForStartupAdoption(ctx) // races the Store below
		}()
	}
	if !p.StartAdoption(ctx) {
		t.Fatal("StartAdoption must claim the pass")
	}
	cancel() // releases any reader that observed the flag set
	readers.Wait()

	close(p.stopCh)
	waited := make(chan struct{})
	go func() { p.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("parked adoption did not join after stop")
	}
}
