package api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"golang.org/x/sync/singleflight"
)

// billingEligCache is an in-process, TTL-bounded cache of per-team sandbox
// billing eligibility, fronting IsTeamSandboxBillingEligible on the
// create/resume request paths. The synchronous check is a fast-fail gate,
// not the enforcement — trialEligibilityLoop and reconcileActivatedSandbox
// pause ineligible teams on their own cadence regardless — so a
// bounded-stale answer here loses nothing while removing a DB round trip
// from every create.
//
// Both verdicts are cached, with asymmetric TTLs. Invalidation is
// deliberately TTL-only: a Stripe webhook lands on ONE control-plane
// replica, so an in-process invalidation hook could never reach the
// others — the short ineligible TTL is what actually bounds the
// "just paid, still blocked" window on every replica.
const (
	// billingEligibleTTL bounds how long an ineligible-turning team can keep
	// passing the gate; the enforcement loops reclaim its sandboxes on the
	// same order of delay, so the gate never outlives the safety net by much.
	billingEligibleTTL = 30 * time.Second
	// billingIneligibleTTL is short so a team that just paid stops seeing
	// 402s within a few seconds on every replica, webhook or not.
	billingIneligibleTTL = 3 * time.Second
	// billingEligQueryTimeout bounds the shared flight's read; the query is
	// three indexed lookups, so anything slower is the DB misbehaving.
	billingEligQueryTimeout = 5 * time.Second
)

type billingEligEntry struct {
	eligible bool
	checked  time.Time // stamped from query start, so a slow read can't stretch the window
}

// billingEligCache's zero value is ready to use.
type billingEligCache struct {
	group singleflight.Group
	mu    sync.Mutex
	m     map[uuid.UUID]billingEligEntry
}

func (e billingEligEntry) ttl() time.Duration {
	if e.eligible {
		return billingEligibleTTL
	}
	return billingIneligibleTTL
}

func (c *billingEligCache) get(teamID uuid.UUID, now time.Time) (eligible, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.m[teamID]
	if !exists || now.Sub(e.checked) > e.ttl() {
		return false, false
	}
	return e.eligible, true
}

func (c *billingEligCache) put(teamID uuid.UUID, eligible bool, checked time.Time) {
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[uuid.UUID]billingEligEntry)
	}
	// Lazy sweep: teams that stop creating are never read again, so puts
	// evict their expired entries. At most one put per team per TTL and the
	// map is one entry per recently-active team, so this stays cheap.
	for k, e := range c.m {
		if checked.Sub(e.checked) > e.ttl() {
			delete(c.m, k)
		}
	}
	c.m[teamID] = billingEligEntry{eligible: eligible, checked: checked}
	c.mu.Unlock()
}

// teamBillingEligibleCached answers from the cache when fresh, else runs one
// shared read per team: the flight is detached and bounded (it may outlive
// its caller and must not inherit a long request deadline), while each
// waiter still selects on its own ctx so a hung-up client returns
// immediately. Errors are never cached.
func (h *Handlers) teamBillingEligibleCached(ctx context.Context, teamID uuid.UUID) (bool, error) {
	c := &h.billingElig
	if eligible, ok := c.get(teamID, time.Now()); ok {
		return eligible, nil
	}
	ch := c.group.DoChan(teamID.String(), func() (interface{}, error) {
		start := time.Now()
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), billingEligQueryTimeout)
		defer cancel()
		eligible, err := h.DB.IsTeamSandboxBillingEligible(qctx, teamID)
		if err == nil {
			c.put(teamID, eligible, start)
		}
		return eligible, err
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return false, res.Err
		}
		return res.Val.(bool), nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
