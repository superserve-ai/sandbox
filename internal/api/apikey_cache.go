package api

import (
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// apiKeyCache is an in-process, TTL-bounded cache of successful API-key
// lookups, keyed by the key's SHA-256 hash. It removes the per-request DB
// round trip from the auth middleware — the dominant hot-path cost when the
// control plane and database are in different regions.
//
// Only positive lookups are cached: an invalid or revoked key always misses
// and hits the DB, so revocation takes effect within one TTL and a flood of
// bad keys cannot grow the map. The key's own expires_at is stored and
// checked on every hit, so expiry is exact even inside the TTL window.
const (
	defaultAPIKeyCacheTTL = 30 * time.Second
	// apiKeyCacheMaxEntries bounds the map. Only valid keys enter the
	// cache, so this is effectively "number of live keys used within one
	// TTL" — the cap is a backstop, not an expected operating point.
	apiKeyCacheMaxEntries = 4096
	// lastUsedTouchInterval throttles the fire-and-forget last_used_at
	// UPDATE to at most one write per key per interval, instead of one
	// per request.
	lastUsedTouchInterval = time.Minute
)

// apiKeyCacheTTLFromEnv reads API_KEY_CACHE_TTL (a Go duration, e.g. "30s").
// Unset or unparsable values fall back to the default; "0" (or any
// non-positive duration) disables caching.
func apiKeyCacheTTLFromEnv() time.Duration {
	raw := os.Getenv("API_KEY_CACHE_TTL")
	if raw == "" {
		return defaultAPIKeyCacheTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return defaultAPIKeyCacheTTL
	}
	return d
}

type apiKeyCacheEntry struct {
	id        string
	teamID    string
	createdBy pgtype.UUID
	expiresAt pgtype.Timestamptz
	fetchedAt time.Time
	lastTouch time.Time
}

type apiKeyCache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]*apiKeyCacheEntry
}

func newAPIKeyCache(ttl time.Duration) *apiKeyCache {
	if ttl <= 0 {
		return nil // caching disabled; nil receiver is safe on get/put
	}
	return &apiKeyCache{ttl: ttl, m: make(map[string]*apiKeyCacheEntry)}
}

// get returns a copy of the cached entry for keyHash if it is still fresh
// and the key itself has not expired. needTouch reports whether the caller
// should update last_used_at (throttled to lastUsedTouchInterval).
func (c *apiKeyCache) get(keyHash string, now time.Time) (entry apiKeyCacheEntry, needTouch, ok bool) {
	if c == nil {
		return apiKeyCacheEntry{}, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.m[keyHash]
	if !exists {
		return apiKeyCacheEntry{}, false, false
	}
	if now.Sub(e.fetchedAt) > c.ttl || (e.expiresAt.Valid && !now.Before(e.expiresAt.Time)) {
		delete(c.m, keyHash)
		return apiKeyCacheEntry{}, false, false
	}
	if now.Sub(e.lastTouch) >= lastUsedTouchInterval {
		e.lastTouch = now
		needTouch = true
	}
	return *e, needTouch, true
}

// put stores a fresh lookup result. lastTouch starts at now because the
// caller just touched last_used_at on the miss path.
func (c *apiKeyCache) put(keyHash string, e apiKeyCacheEntry, now time.Time) {
	if c == nil {
		return
	}
	e.fetchedAt = now
	e.lastTouch = now
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= apiKeyCacheMaxEntries {
		for h, old := range c.m {
			if now.Sub(old.fetchedAt) > c.ttl {
				delete(c.m, h)
			}
		}
		// Still full after sweeping: reset rather than grow. Costs one
		// DB lookup per live key to refill; unreachable in practice.
		if len(c.m) >= apiKeyCacheMaxEntries {
			c.m = make(map[string]*apiKeyCacheEntry)
		}
	}
	c.m[keyHash] = &e
}
