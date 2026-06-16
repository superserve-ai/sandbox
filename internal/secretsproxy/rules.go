package secretsproxy

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// EgressRules is a sandbox's egress allow/deny policy, fetched live rather than
// carried in the JWT so a PATCH takes effect without re-minting.
type EgressRules struct {
	Allow               []string
	Deny                []string
	UnmatchedHostPolicy string
}

// RulesClient resolves a sandbox's current egress rules.
type RulesClient interface {
	FetchRules(ctx context.Context, sandboxID string) (EgressRules, error)
}

// RulesCacheOptions configures cachedRules. Zero values fall back to defaults.
type RulesCacheOptions struct {
	TTL      time.Duration // freshness before re-fetch (default 30s)
	IdleTTL  time.Duration // evict entries idle this long (default 10m)
	Capacity int           // LRU bound (default 1024)
}

// cachedRules wraps a RulesClient with an LRU + TTL cache. On a fetch error it
// serves the last-known-good value if one is cached, so a control-plane blip
// never silently drops policy; only a cold cache + fetch failure returns an
// error (the caller then fails the request closed, never open).
type cachedRules struct {
	upstream RulesClient
	ttl      time.Duration
	idleTTL  time.Duration
	capacity int
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
}

type rulesEntry struct {
	sandboxID string
	rules     EgressRules
	expires   time.Time
	lastUsed  time.Time
}

// NewCachedRules wraps client with an LRU + TTL cache.
func NewCachedRules(client RulesClient, opts RulesCacheOptions) *cachedRules {
	if opts.TTL <= 0 {
		opts.TTL = 30 * time.Second
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = 10 * time.Minute
	}
	if opts.Capacity <= 0 {
		opts.Capacity = 1024
	}
	return &cachedRules{
		upstream: client,
		ttl:      opts.TTL,
		idleTTL:  opts.IdleTTL,
		capacity: opts.Capacity,
		now:      time.Now,
		entries:  make(map[string]*list.Element, opts.Capacity),
		order:    list.New(),
	}
}

// FetchRules returns fresh cached rules, re-fetches when stale, and serves the
// last-known-good value if the re-fetch fails.
func (c *cachedRules) FetchRules(ctx context.Context, sandboxID string) (EgressRules, error) {
	now := c.now()

	c.mu.Lock()
	if el, ok := c.entries[sandboxID]; ok {
		e := el.Value.(*rulesEntry)
		switch {
		case now.Sub(e.lastUsed) >= c.idleTTL:
			c.removeRules(el) // idle: drop, no longer worth keeping
		case now.Before(e.expires):
			e.lastUsed = now
			c.order.MoveToFront(el)
			r := e.rules
			c.mu.Unlock()
			return r, nil
		}
		// else: expired but not idle — keep it for last-known-good below.
	}
	c.mu.Unlock()

	r, err := c.upstream.FetchRules(ctx, sandboxID)
	if err != nil {
		c.mu.Lock()
		if el, ok := c.entries[sandboxID]; ok {
			e := el.Value.(*rulesEntry)
			e.lastUsed = now
			c.order.MoveToFront(el)
			stale := e.rules
			c.mu.Unlock()
			return stale, nil // last-known-good; caller logs the underlying error
		}
		c.mu.Unlock()
		return EgressRules{}, err // cold cache + fetch failure
	}

	c.mu.Lock()
	now = c.now()
	if el, ok := c.entries[sandboxID]; ok {
		e := el.Value.(*rulesEntry)
		e.rules = r
		e.expires = now.Add(c.ttl)
		e.lastUsed = now
		c.order.MoveToFront(el)
	} else {
		el := c.order.PushFront(&rulesEntry{
			sandboxID: sandboxID,
			rules:     r,
			expires:   now.Add(c.ttl),
			lastUsed:  now,
		})
		c.entries[sandboxID] = el
		for c.order.Len() > c.capacity {
			c.removeRules(c.order.Back())
		}
	}
	c.mu.Unlock()
	return r, nil
}

// Invalidate drops the cached entry for sandboxID so the next request re-fetches.
func (c *cachedRules) Invalidate(sandboxID string) {
	c.mu.Lock()
	if el, ok := c.entries[sandboxID]; ok {
		c.removeRules(el)
	}
	c.mu.Unlock()
}

// Warm fetches and caches the rules for sandboxID so a later request hits a warm
// cache. Used to prime at create and re-warm after a PATCH, so the first proxied
// request never needs a live fetch (which would fail if the control plane were
// briefly unreachable). Best-effort — a fetch failure leaves the cache cold.
func (c *cachedRules) Warm(ctx context.Context, sandboxID string) {
	_, _ = c.FetchRules(ctx, sandboxID)
}

// removeRules removes an element from both the map and the list. Caller holds c.mu.
func (c *cachedRules) removeRules(el *list.Element) {
	e := el.Value.(*rulesEntry)
	delete(c.entries, e.sandboxID)
	c.order.Remove(el)
}
