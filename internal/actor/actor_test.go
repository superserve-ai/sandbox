package actor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic lease-expiry tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newReg() (*Registry, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return NewRegistry(NewMemStore(), clk.now), clk
}

func TestGetActorWakeOnReference(t *testing.T) {
	reg, _ := newReg()
	a1, created1, err := reg.GetActor("team-1", "support/ticket-4821", Actor{Template: "base"})
	if err != nil || !created1 {
		t.Fatalf("first GetActor: created=%v err=%v", created1, err)
	}
	a2, created2, err := reg.GetActor("team-1", "support/ticket-4821", Actor{})
	if err != nil || created2 {
		t.Fatalf("second GetActor should resolve existing: created=%v err=%v", created2, err)
	}
	if a1.ID != a2.ID {
		t.Fatalf("same name resolved to different ids: %s vs %s", a1.ID, a2.ID)
	}
	if a1.Tier != TierCold {
		t.Errorf("new actor should start cold, got %s", a1.Tier)
	}
	// Same name, different team → different actor (per-team isolation).
	b, createdB, _ := reg.GetActor("team-2", "support/ticket-4821", Actor{})
	if !createdB || b.ID == a1.ID {
		t.Errorf("name collision across teams must not alias: %s vs %s (created=%v)", b.ID, a1.ID, createdB)
	}
}

func TestLeaseSingleWriter(t *testing.T) {
	reg, _ := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})

	l1, err := reg.Acquire(a.ID, "host-A", time.Second)
	if err != nil {
		t.Fatalf("first acquire should win: %v", err)
	}
	if l1.Token() != 1 {
		t.Errorf("first token should be 1, got %d", l1.Token())
	}

	// A second, different holder must be refused while the lease is valid.
	if _, err := reg.Acquire(a.ID, "host-B", time.Second); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second holder should get ErrLeaseHeld, got %v", err)
	}

	// The holder can still fence writes.
	if err := l1.CheckFence(); err != nil {
		t.Errorf("holder fence check should pass: %v", err)
	}
}

func TestLeaseExpiryAndFencing(t *testing.T) {
	reg, clk := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})

	l1, _ := reg.Acquire(a.ID, "host-A", 10*time.Second)
	tok1 := l1.Token()

	// Let the lease lapse.
	clk.advance(11 * time.Second)

	// host-A's fence is now invalid (lease expired).
	if err := l1.CheckFence(); !errors.Is(err, ErrFenced) {
		t.Fatalf("expired lease should fence the old holder, got %v", err)
	}
	// host-A's renew must also fail — it cannot resurrect a lapsed lease.
	if err := l1.Renew(10 * time.Second); !errors.Is(err, ErrFenced) {
		t.Fatalf("renew of lapsed lease should be fenced, got %v", err)
	}

	// host-B now takes over and gets a NEW, higher token (the fence).
	l2, err := reg.Acquire(a.ID, "host-B", 10*time.Second)
	if err != nil {
		t.Fatalf("host-B should acquire after expiry: %v", err)
	}
	if l2.Token() <= tok1 {
		t.Fatalf("new holder's fence token must increase: got %d, old %d", l2.Token(), tok1)
	}
	// Critical safety: the OLD holder, even if it wakes up confused, is fenced.
	if err := l1.CheckFence(); !errors.Is(err, ErrFenced) {
		t.Fatalf("old holder must stay fenced after takeover, got %v", err)
	}
	// The new holder writes safely.
	if err := l2.CheckFence(); err != nil {
		t.Errorf("new holder fence should pass: %v", err)
	}
}

func TestLeaseRenewKeepsToken(t *testing.T) {
	reg, clk := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})
	l, _ := reg.Acquire(a.ID, "host-A", 10*time.Second)
	tok := l.Token()
	clk.advance(5 * time.Second)
	if err := l.Renew(10 * time.Second); err != nil {
		t.Fatalf("renew should succeed: %v", err)
	}
	if l.Token() != tok {
		t.Errorf("renew must NOT change the fence token: %d -> %d", tok, l.Token())
	}
	clk.advance(8 * time.Second) // would have expired at +10 without the renew
	if err := l.CheckFence(); err != nil {
		t.Errorf("renewed lease should still be valid: %v", err)
	}
}

func TestLeaseReleaseHandoff(t *testing.T) {
	reg, _ := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})
	l1, _ := reg.Acquire(a.ID, "host-A", time.Hour)
	// Clean handoff: release lets another host take over immediately (no TTL wait).
	if err := l1.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := l1.CheckFence(); !errors.Is(err, ErrFenced) {
		t.Errorf("released holder should be fenced, got %v", err)
	}
	if _, err := reg.Acquire(a.ID, "host-B", time.Hour); err != nil {
		t.Fatalf("host-B should acquire after release: %v", err)
	}
}

func TestLeaseReleaseByNonHolderIsNoop(t *testing.T) {
	reg, _ := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})
	l1, _ := reg.Acquire(a.ID, "host-A", time.Hour)
	// Forge a release from a different holder/token — must not free host-A's lease.
	stale := &Lease{reg: reg, actorID: a.ID, holder: "host-B", token: 999}
	_ = stale.Release()
	if err := l1.CheckFence(); err != nil {
		t.Errorf("non-holder release must not drop the real lease: %v", err)
	}
}

// TestLeaseConcurrentAcquire is the single-writer invariant under contention:
// many instances race to acquire; exactly one wins.
func TestLeaseConcurrentAcquire(t *testing.T) {
	reg, _ := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})

	const n = 64
	var winners int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			if _, err := reg.Acquire(a.ID, "host-"+itoa(int64(id)), time.Hour); err == nil {
				atomic.AddInt64(&winners, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if winners != 1 {
		t.Fatalf("exactly one instance must win the lease, got %d", winners)
	}
}

func TestSetTier(t *testing.T) {
	reg, _ := newReg()
	a, _, _ := reg.GetActor("t", "a", Actor{})
	if err := reg.SetTier(a.ID, TierPaused1, "host-A"); err != nil {
		t.Fatal(err)
	}
	got, _ := reg.store.Get(a.ID)
	if got.Tier != TierPaused1 || got.HomeHost != "host-A" {
		t.Errorf("tier/host = %s/%s", got.Tier, got.HomeHost)
	}
}
