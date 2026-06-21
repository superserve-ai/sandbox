package actor

import (
	"sync"
	"testing"
	"time"
)

type recordDemoter struct {
	mu    sync.Mutex
	calls []string // "<id>:<tier>"
}

func (d *recordDemoter) Demote(id string, to Tier) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, id+":"+string(to))
	return nil
}

func (d *recordDemoter) last() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return ""
	}
	return d.calls[len(d.calls)-1]
}

func (d *recordDemoter) count() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.calls) }

func TestTierStaircase(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	dem := &recordDemoter{}
	policy := TierPolicy{ToTier1: 2 * time.Second, ToTier2: 10 * time.Second, ToTier3: 60 * time.Second}
	c := NewTierController(policy, dem, clk.now)

	c.Touch("a")
	if c.Tier("a") != TierLive {
		t.Fatal("touch should promote to Live")
	}

	// Before ToTier1: no demotion.
	clk.advance(1 * time.Second)
	if n := c.Tick(); n != 0 {
		t.Fatalf("no demotion before ToTier1, got %d", n)
	}

	// Past ToTier1 → Tier1.
	clk.advance(2 * time.Second) // total idle 3s >= 2s
	c.Tick()
	if c.Tier("a") != TierPaused1 || dem.last() != "a:tier1" {
		t.Fatalf("expected demote to tier1, tier=%s last=%s", c.Tier("a"), dem.last())
	}

	// Past ToTier1+ToTier2 (12s) → Tier2.
	clk.advance(10 * time.Second) // total idle 13s >= 12s
	c.Tick()
	if c.Tier("a") != TierPaused2 || dem.last() != "a:tier2" {
		t.Fatalf("expected demote to tier2, tier=%s last=%s", c.Tier("a"), dem.last())
	}

	// Past ToTier1+ToTier2+ToTier3 (72s) → Tier3.
	clk.advance(60 * time.Second) // total idle 73s >= 72s
	c.Tick()
	if c.Tier("a") != TierPaused3 || dem.last() != "a:tier3" {
		t.Fatalf("expected demote to tier3, tier=%s last=%s", c.Tier("a"), dem.last())
	}

	// Already deepest: no further demotion.
	clk.advance(time.Hour)
	if n := c.Tick(); n != 0 {
		t.Fatalf("no demotion past tier3, got %d", n)
	}
}

// TestTierPromoteResetsAndPreventsThrash: activity keeps an Actor Live and a
// post-demotion Touch promotes it back — rapid turns never demote.
func TestTierPromoteResetsAndPreventsThrash(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	dem := &recordDemoter{}
	c := NewTierController(TierPolicy{ToTier1: 5 * time.Second}, dem, clk.now)

	// Frequent touches: never idle long enough to demote.
	for i := 0; i < 10; i++ {
		c.Touch("a")
		clk.advance(1 * time.Second)
		c.Tick()
	}
	if dem.count() != 0 {
		t.Fatalf("active Actor must not demote, got %d demotions", dem.count())
	}

	// Go idle → demote to Tier1.
	clk.advance(6 * time.Second)
	c.Tick()
	if c.Tier("a") != TierPaused1 {
		t.Fatalf("idle Actor should demote, tier=%s", c.Tier("a"))
	}

	// A new event promotes back to Live (the Router wakes it; controller resets).
	c.Touch("a")
	if c.Tier("a") != TierLive {
		t.Fatalf("event should promote back to Live, tier=%s", c.Tier("a"))
	}
	clk.advance(1 * time.Second)
	if n := c.Tick(); n != 0 {
		t.Fatalf("freshly-promoted Actor must not immediately re-demote, got %d", n)
	}
}

func TestTierOneStepPerTick(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	dem := &recordDemoter{}
	c := NewTierController(TierPolicy{ToTier1: time.Second, ToTier2: time.Second, ToTier3: time.Second}, dem, clk.now)
	c.Touch("a")
	clk.advance(time.Hour) // way past all thresholds at once

	// Each Tick advances exactly one tier, so observers see every transition.
	c.Tick()
	if c.Tier("a") != TierPaused1 {
		t.Fatalf("first tick → tier1, got %s", c.Tier("a"))
	}
	c.Tick()
	if c.Tier("a") != TierPaused2 {
		t.Fatalf("second tick → tier2, got %s", c.Tier("a"))
	}
	c.Tick()
	if c.Tier("a") != TierPaused3 {
		t.Fatalf("third tick → tier3, got %s", c.Tier("a"))
	}
}
