package actor

import (
	"context"
	"sync"
	"time"
)

// Demoter performs the actual tier transition for an Actor (the mechanism). In
// production this is backed by the Router + vmd: Tier1 = bare Firecracker pause
// (validated sub-ms wake, see cmd/latencybench/RESULTS.md), Tier2 = local
// snapshot + UFFD, Tier3 = push to object storage and free the host. The
// TierController owns only the WHEN policy, so it's testable with a fake clock.
type Demoter interface {
	Demote(actorID string, to Tier) error
}

// DemoterFunc adapts a function to Demoter.
type DemoterFunc func(actorID string, to Tier) error

// Demote calls f.
func (f DemoterFunc) Demote(actorID string, to Tier) error { return f(actorID, to) }

// TierPolicy is the idle-driven demotion schedule. Durations are measured from
// the last activity: an Actor demotes to Tier1 after ToTier1 of idleness, to
// Tier2 after an additional ToTier2, and to Tier3 after a further ToTier3. The
// staircase means a present user (frequent Touch) keeps the Actor hot/Tier1,
// while the cost-saving deep tiers only kick in behind real idleness.
type TierPolicy struct {
	ToTier1 time.Duration
	ToTier2 time.Duration
	ToTier3 time.Duration
}

// DefaultTierPolicy: pause-in-RAM quickly (Tier-1 wake is sub-ms so it's nearly
// free to re-promote), snapshot after a minute of idleness, go cold after ~15m.
var DefaultTierPolicy = TierPolicy{
	ToTier1: 2 * time.Second,
	ToTier2: 60 * time.Second,
	ToTier3: 15 * time.Minute,
}

type tierState struct {
	tier       Tier
	lastActive time.Time
}

// TierController drives Actors through hibernation tiers based on idleness and
// promotes them to Live on activity. Touch is called on every event (promote +
// reset idle); Tick is called periodically (e.g. by the reaper) to demote
// Actors that have crossed their idle thresholds. Anti-thrash is inherent: a
// Touch resets to Live, so rapid turns never demote, and demotion only advances
// one tier per threshold crossed.
type TierController struct {
	policy  TierPolicy
	demoter Demoter
	now     func() time.Time

	mu    sync.Mutex
	state map[string]*tierState
}

// NewTierController builds a controller. clock may be nil (time.Now).
func NewTierController(policy TierPolicy, demoter Demoter, clock func() time.Time) *TierController {
	if clock == nil {
		clock = time.Now
	}
	return &TierController{policy: policy, demoter: demoter, now: clock, state: map[string]*tierState{}}
}

// Touch records activity for an Actor: it (re)promotes to Live and resets the
// idle clock. Call on every inbound event, before processing.
func (c *TierController) Touch(actorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state[actorID]
	if st == nil {
		st = &tierState{}
		c.state[actorID] = st
	}
	st.tier = TierLive
	st.lastActive = c.now()
}

// Forget drops an Actor from tracking (e.g. when destroyed).
func (c *TierController) Forget(actorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.state, actorID)
}

// Tier reports the controller's view of an Actor's tier.
func (c *TierController) Tier(actorID string) Tier {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.state[actorID]; st != nil {
		return st.tier
	}
	return TierCold
}

// Run is the background trigger that actually demotes idle Actors: it calls Tick
// on a fixed interval until ctx is cancelled. Without it, Touch/Tick are inert —
// nothing advances an idle Actor down the tiers. Returns ctx.Err() on cancel.
func (c *TierController) Run(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	return c.runLoop(ctx, t.C)
}

// runLoop drives Tick off a tick channel until ctx is done. Split from Run so a
// test can drive ticks deterministically (no wall-clock sleeps).
func (c *TierController) runLoop(ctx context.Context, ticks <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			c.Tick()
		}
	}
}

// Tick advances demotions for all tracked Actors whose idleness has crossed the
// next threshold. It demotes at most one tier per Actor per Tick (so the wake
// path and observers see each transition); call it on a steady cadence. Returns
// the number of demotions performed.
func (c *TierController) Tick() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	demotions := 0
	for id, st := range c.state {
		next := c.nextTier(st.tier, now.Sub(st.lastActive))
		if next == st.tier {
			continue
		}
		if err := c.demoter.Demote(id, next); err != nil {
			// Leave the state as-is so the next Tick retries the transition.
			continue
		}
		st.tier = next
		demotions++
	}
	return demotions
}

// nextTier returns the deepest tier the Actor is eligible for given idle time,
// advancing at most one step from cur (the staircase).
func (c *TierController) nextTier(cur Tier, idle time.Duration) Tier {
	switch cur {
	case TierLive:
		if idle >= c.policy.ToTier1 {
			return TierPaused1
		}
	case TierPaused1:
		if idle >= c.policy.ToTier1+c.policy.ToTier2 {
			return TierPaused2
		}
	case TierPaused2:
		if idle >= c.policy.ToTier1+c.policy.ToTier2+c.policy.ToTier3 {
			return TierPaused3
		}
	}
	return cur
}
