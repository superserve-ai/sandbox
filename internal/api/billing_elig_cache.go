package api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"golang.org/x/sync/singleflight"
)

const (
	// billingEligibleTTL bounds how long an ineligible-turning team can keep
	// passing the gate; the enforcement loops reclaim its sandboxes on the
	// same order of delay, so the gate never outlives the safety net by much.
	billingEligibleTTL = 30 * time.Second
	// billingIneligibleTTL is short so a team that just paid stops seeing
	// 402s within a few seconds on every replica, webhook or not.
	billingIneligibleTTL = 3 * time.Second
	// billingEligQueryTimeout bounds the shared flight's read; the query is
	// bounded local indexed lookups, with no provider calls.
	billingEligQueryTimeout = 5 * time.Second
	// evictSamplePerPut caps how many entries a put inspects for expiry, so
	// eviction cost never scales with team cardinality on the request path.
	evictSamplePerPut = 8
	// billingEligCacheMaxEntries is a hard memory bound: teams actively
	// creating within one TTL window number in the hundreds, so thousands of
	// live entries means churn the sampled eviction hasn't caught up with.
	// Evicting an arbitrary entry is safe — this cache only saves a read.
	billingEligCacheMaxEntries = 4096
)

type sandboxShapeLimit struct {
	vcpu, memoryMib, diskMib int32
}

type sandboxAdmission struct {
	eligible          bool
	allowanceResetsAt *time.Time
}

type billingEligEntry struct {
	admission sandboxAdmission
	checked   time.Time // stamped from query start, so a slow read can't stretch the window
}

// billingEligCache's zero value is ready to use.
type billingEligCache struct {
	group singleflight.Group
	mu    sync.Mutex
	m     map[uuid.UUID]billingEligEntry
}

func (e billingEligEntry) ttl() time.Duration {
	if e.admission.eligible {
		return billingEligibleTTL
	}
	return billingIneligibleTTL
}

func (c *billingEligCache) get(teamID uuid.UUID, now time.Time) (sandboxAdmission, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.m[teamID]
	if !exists || now.Sub(e.checked) > e.ttl() {
		return sandboxAdmission{}, false
	}
	return e.admission, true
}

func (c *billingEligCache) put(teamID uuid.UUID, admission sandboxAdmission, checked time.Time) {
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[uuid.UUID]billingEligEntry)
	}
	// Bounded lazy eviction: teams that stop creating are never read again,
	// so puts reclaim expired entries — but only a small random sample each
	// (map iteration order is random), keeping this critical section O(1)
	// no matter how many teams churn through. Puts outnumber expiries in
	// steady state (at most one put per active team per TTL), so sampled
	// reclamation keeps the map proportional to recently-active teams.
	sampled := 0
	for k, e := range c.m {
		if sampled++; sampled > evictSamplePerPut {
			break
		}
		if checked.Sub(e.checked) > e.ttl() {
			delete(c.m, k)
		}
	}
	// Hard cap, enforced after the expiry sample: drop arbitrary entries
	// (random map order) until the insert fits. O(1) amortized — the map can
	// exceed the cap by at most one entry per put.
	for k := range c.m {
		if len(c.m) < billingEligCacheMaxEntries {
			break
		}
		delete(c.m, k)
	}
	c.m[teamID] = billingEligEntry{admission: admission, checked: checked}
	c.mu.Unlock()
}

// shared read per team: the flight is detached and bounded (it may outlive
// its caller and must not inherit a long request deadline), while each
// waiter still selects on its own ctx so a hung-up client returns
// immediately. Errors are never cached.
func (h *Handlers) teamSandboxAdmissionCached(ctx context.Context, teamID uuid.UUID) (sandboxAdmission, error) {
	c := &h.billingElig
	if admission, ok := c.get(teamID, time.Now()); ok {
		return admission, nil
	}
	ch := c.group.DoChan(teamID.String(), func() (interface{}, error) {
		// Re-check under the flight: a caller that missed while a previous
		// flight was completing enters a fresh flight after it — without
		// this, back-to-back flights double-read what the first just cached.
		if admission, ok := c.get(teamID, time.Now()); ok {
			return admission, nil
		}
		start := time.Now()
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), billingEligQueryTimeout)
		defer cancel()
		row, err := h.DB.GetTeamSandboxAdmission(qctx, teamID)
		if err != nil {
			return sandboxAdmission{}, err
		}
		admission := sandboxAdmission{eligible: row.Eligible}
		if row.AllowanceBlocked {
			admission.allowanceResetsAt = &row.AllowanceResetsAt
		}
		c.put(teamID, admission, start)
		return admission, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return sandboxAdmission{}, res.Err
		}
		return res.Val.(sandboxAdmission), nil
	case <-ctx.Done():
		return sandboxAdmission{}, ctx.Err()
	}
}
