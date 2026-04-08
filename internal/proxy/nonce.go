package proxy

import (
	"container/list"
	"sync"
	"time"
)

// NonceCache is a bounded in-memory store of seen token nonces. It enforces
// single-use semantics on terminal tokens: once a nonce has been observed,
// any subsequent token carrying the same nonce is rejected, even if the
// token's signature and TTL would otherwise validate.
//
// Why this exists
//
// Tokens already have a 60-second TTL and an Ed25519 signature, so why also
// dedupe? Two reasons:
//
//  1. Defense in depth — if a token leaks (server logs, browser dev tools,
//     network capture) it should be useless after the legitimate browser
//     has consumed it. Without dedupe, an attacker who grabs the token
//     within the 60s window can establish their own session.
//
//  2. Bounding the leak window from "60 seconds of unrestricted use" to
//     "one shot, race the legitimate consumer." That's a meaningful
//     reduction in blast radius for free.
//
// Why in-memory and not Redis: the proxy is bare-metal-local and stateless
// per replica. Nonces are scoped to a 60s TTL so a per-replica cache is
// sufficient as long as the same client always lands on the same proxy
// during the lifetime of one terminal session — which it does, because the
// WS connection is sticky to a single TCP socket. Multi-replica edge
// deployments where requests can hop between replicas would need a shared
// store, but we don't have that yet.
//
// Memory bounds: max entries cap (default 100k) prevents unbounded growth
// even under nonce-spam attacks. LRU eviction means a flood of invalid
// nonces will push out legitimate ones, but legitimate ones get re-added
// on the next mint anyway because each mint produces a fresh nonce.
//
// Thread safety: all methods take the mutex; this is fine because nonce
// checks are O(1) hash lookups and the proxy throughput is bounded by VM
// IO, not by mutex contention here.
type NonceCache struct {
	mu       sync.Mutex
	max      int
	ttl      time.Duration
	items    map[string]*list.Element
	eviction *list.List // doubly-linked list, front = newest
}

// nonceEntry is the value stored in each list element.
type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// NewNonceCache constructs a NonceCache with the given size and TTL bounds.
// Both must be positive — pass DefaultNonceCacheConfig for sensible values.
func NewNonceCache(maxEntries int, ttl time.Duration) *NonceCache {
	if maxEntries <= 0 {
		panic("proxy: NonceCache maxEntries must be > 0")
	}
	if ttl <= 0 {
		panic("proxy: NonceCache ttl must be > 0")
	}
	return &NonceCache{
		max:      maxEntries,
		ttl:      ttl,
		items:    make(map[string]*list.Element, maxEntries),
		eviction: list.New(),
	}
}

// DefaultNonceCache returns a cache with reasonable production defaults:
//
//   - 100,000 entries — at ~64 bytes each that's ~6 MB, well under any
//     practical limit on a bare metal box
//   - 2 minute TTL — comfortably above the 60s token TTL plus clock skew
//     so a token that's accepted by the verifier is also tracked here
func DefaultNonceCache() *NonceCache {
	return NewNonceCache(100_000, 2*time.Minute)
}

// CheckAndStore is the only operation callers need. It atomically checks
// whether a nonce has been seen recently and, if not, records it.
//
// Returns true if the nonce is FRESH (not previously seen). Returns false if
// the nonce was already in the cache (replay attempt).
//
// The check-and-store is a single locked operation — splitting it into
// separate Has() and Store() calls would race under concurrent connections
// trying to consume the same leaked token.
func (c *NonceCache) CheckAndStore(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazily evict any entry whose TTL has elapsed. We only check the
	// requested key (not the whole cache) because cleanup-on-access is
	// cheap and full sweeps are O(n).
	if e, ok := c.items[nonce]; ok {
		entry := e.Value.(*nonceEntry)
		if now.Before(entry.expiresAt) {
			// Genuine replay — already in cache and not expired.
			return false
		}
		// Expired entry, evict and treat as fresh.
		c.eviction.Remove(e)
		delete(c.items, nonce)
	}

	// Make room if we're at the cap. Evict from the back of the list
	// (oldest) — single eviction per insert keeps insertion O(1).
	if c.eviction.Len() >= c.max {
		oldest := c.eviction.Back()
		if oldest != nil {
			c.eviction.Remove(oldest)
			delete(c.items, oldest.Value.(*nonceEntry).nonce)
		}
	}

	e := c.eviction.PushFront(&nonceEntry{
		nonce:     nonce,
		expiresAt: now.Add(c.ttl),
	})
	c.items[nonce] = e
	return true
}

// Len returns the number of entries currently in the cache. Test/observability
// only — production code should never make decisions based on this.
func (c *NonceCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eviction.Len()
}
