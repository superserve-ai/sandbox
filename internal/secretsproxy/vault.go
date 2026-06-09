package secretsproxy

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// VaultClient fetches credential values for the daemon.
type VaultClient interface {
	FetchCredential(ctx context.Context, teamID, secretID string) (string, error)
}

// ErrCredentialRevoked indicates the secret has been soft-deleted or is no longer valid.
var ErrCredentialRevoked = errors.New("secretsproxy: credential revoked or not found")

// VaultCacheOptions configures cachedVault. Zero values fall back to defaults.
type VaultCacheOptions struct {
	// TTL is how long a cached value is treated as fresh before re-fetching
	// from the upstream. Defaults to 60s.
	TTL time.Duration
	// IdleTTL evicts entries that haven't been accessed in this long, even
	// when the cache isn't full. Defaults to 10m.
	IdleTTL time.Duration
	// Capacity bounds the cache size. LRU evicts the least-recently-used
	// entry once the bound is reached. Defaults to 1024.
	Capacity int
}

// cachedVault wraps a VaultClient with an LRU cache plus freshness and idle TTLs.
type cachedVault struct {
	upstream VaultClient
	ttl      time.Duration
	idleTTL  time.Duration
	capacity int
	now      func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]*list.Element
	order   *list.List
}

type cacheKey struct {
	teamID   string
	secretID string
}

type cachedEntry struct {
	key      cacheKey
	value    string
	expires  time.Time // freshness deadline — past this, refetch
	lastUsed time.Time // for idle-TTL eviction
}

// NewCachedVault wraps client with an LRU + TTL cache.
func NewCachedVault(client VaultClient, opts VaultCacheOptions) *cachedVault {
	if opts.TTL <= 0 {
		opts.TTL = 60 * time.Second
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = 10 * time.Minute
	}
	if opts.Capacity <= 0 {
		opts.Capacity = 1024
	}
	return &cachedVault{
		upstream: client,
		ttl:      opts.TTL,
		idleTTL:  opts.IdleTTL,
		capacity: opts.Capacity,
		now:      time.Now,
		entries:  make(map[cacheKey]*list.Element, opts.Capacity),
		order:    list.New(),
	}
}

// FetchCredential returns the cached value when fresh and not idle-evicted,
// otherwise hits the upstream. On insert, evicts LRU tail if over capacity.
func (c *cachedVault) FetchCredential(ctx context.Context, teamID, secretID string) (string, error) {
	key := cacheKey{teamID: teamID, secretID: secretID}
	now := c.now()

	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*cachedEntry)
		if now.Before(e.expires) && now.Sub(e.lastUsed) < c.idleTTL {
			e.lastUsed = now
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return e.value, nil
		}
		c.removeElement(el)
	}
	c.mu.Unlock()

	v, err := c.upstream.FetchCredential(ctx, teamID, secretID)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	now = c.now()
	if el, ok := c.entries[key]; ok {
		// A concurrent caller raced us to insert; refresh the existing entry
		// in place instead of duplicating.
		e := el.Value.(*cachedEntry)
		e.value = v
		e.expires = now.Add(c.ttl)
		e.lastUsed = now
		c.order.MoveToFront(el)
	} else {
		el := c.order.PushFront(&cachedEntry{
			key:      key,
			value:    v,
			expires:  now.Add(c.ttl),
			lastUsed: now,
		})
		c.entries[key] = el
		for c.order.Len() > c.capacity {
			c.removeElement(c.order.Back())
		}
	}
	c.mu.Unlock()
	return v, nil
}

// Invalidate drops every cached entry for secretID across all teams.
func (c *cachedVault) Invalidate(secretID string) {
	c.mu.Lock()
	for k, el := range c.entries {
		if k.secretID == secretID {
			c.removeElement(el)
		}
	}
	c.mu.Unlock()
}

// removeElement removes an LRU element from both the map and the list. The
// caller must hold c.mu.
func (c *cachedVault) removeElement(el *list.Element) {
	e := el.Value.(*cachedEntry)
	delete(c.entries, e.key)
	c.order.Remove(el)
}
