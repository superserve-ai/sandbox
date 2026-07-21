package api

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/sync/singleflight"
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
	defaultAPIKeyCacheTTL = 10 * time.Second
	// apiKeyCacheMaxEntries bounds the map. Only valid keys enter the
	// cache, so this is effectively "number of live keys used within one
	// TTL" — the cap is a backstop, not an expected operating point.
	apiKeyCacheMaxEntries = 4096
	// lastUsedTouchInterval throttles the fire-and-forget last_used_at
	// UPDATE to at most one write per key per interval, instead of one
	// per request.
	lastUsedTouchInterval = time.Minute
	// apiKeyCacheStaleGrace: a TTL-expired entry is still served for this long
	// while one background flight refreshes it, so a burst landing on an
	// expired entry never queues behind the refresh. Widens the worst-case
	// revocation window from ttl to ttl+grace.
	apiKeyCacheStaleGrace = 2 * time.Second
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
	id         string
	teamID     string
	name       string
	scopes     []string
	createdBy  pgtype.UUID
	expiresAt  pgtype.Timestamptz
	fetchedAt  time.Time
	lastTouch  time.Time
	refreshing bool // a stale-serve refresh is in flight; armed by get, cleared by put/refreshFailed
}

type apiKeyCache struct {
	ttl   time.Duration
	group singleflight.Group // coalesces concurrent misses for the same key
	mu    sync.Mutex
	m     map[string]*apiKeyCacheEntry
}

func newAPIKeyCache(ttl time.Duration) *apiKeyCache {
	if ttl <= 0 {
		return nil // caching disabled; nil receiver is safe on get/put
	}
	return &apiKeyCache{ttl: ttl, m: make(map[string]*apiKeyCacheEntry)}
}

// get returns a copy of the cached entry for keyHash if the key itself has not
// expired and the entry is within ttl+grace. refresh reports that the entry is
// past its TTL and THIS caller should kick the background refresh — at most
// one is armed at a time; put and refreshFailed re-arm. Past the grace window
// it is a miss (kept only so put can carry the last_used_at throttle across
// refills). needTouch reports whether the caller should update last_used_at
// (throttled to lastUsedTouchInterval).
func (c *apiKeyCache) get(keyHash string, now time.Time) (entry apiKeyCacheEntry, needTouch, refresh, ok bool) {
	if c == nil {
		return apiKeyCacheEntry{}, false, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.m[keyHash]
	if !exists {
		return apiKeyCacheEntry{}, false, false, false
	}
	if e.expiresAt.Valid && !now.Before(e.expiresAt.Time) {
		delete(c.m, keyHash)
		return apiKeyCacheEntry{}, false, false, false
	}
	age := now.Sub(e.fetchedAt)
	if age > c.ttl+apiKeyCacheStaleGrace {
		return apiKeyCacheEntry{}, false, false, false
	}
	if now.Sub(e.lastTouch) >= lastUsedTouchInterval {
		e.lastTouch = now
		needTouch = true
	}
	if age > c.ttl && !e.refreshing {
		e.refreshing = true
		refresh = true
	}
	return *e, needTouch, refresh, true
}

// remove drops a cached entry. Used when a refresh returns a definitive
// not-found: the key was revoked, so its stale entry must stop being servable.
func (c *apiKeyCache) remove(keyHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.m, keyHash)
	c.mu.Unlock()
}

// refreshFailed re-arms the stale-refresh trigger after a transient refresh
// error, so a later request inside the grace window retries. (A successful
// refresh re-arms via put; a revoked key is removed outright.)
func (c *apiKeyCache) refreshFailed(keyHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if e, ok := c.m[keyHash]; ok {
		e.refreshing = false
	}
	c.mu.Unlock()
}

// fetch coalesces concurrent misses for the same key: one caller runs fn (the
// DB lookup) and every concurrent waiter shares its result, so a burst hitting
// an expired entry issues a single query instead of one per request.
//
// The shared flight runs under a detached, 5s-bounded context — it may outlive
// the request that triggered it, so it must not die when that caller
// disconnects. But each waiter still selects on its own ctx via DoChan, so a
// waiter whose client hangs up (or whose deadline fires) returns immediately
// instead of blocking on the flight; the flight itself keeps running for the
// remaining waiters. With caching disabled (nil receiver) there are no waiters,
// so fn runs directly under the caller's context.
func (c *apiKeyCache) fetch(ctx context.Context, keyHash string, fn func(context.Context) (apiKeyCacheEntry, error)) (apiKeyCacheEntry, error) {
	if c == nil {
		return fn(ctx)
	}
	ch := c.group.DoChan(keyHash, func() (interface{}, error) {
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return fn(qctx)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return apiKeyCacheEntry{}, res.Err
		}
		return res.Val.(apiKeyCacheEntry), nil
	case <-ctx.Done():
		return apiKeyCacheEntry{}, ctx.Err()
	}
}

// put stores a fresh lookup result and reports whether the caller should touch
// last_used_at. The prior entry's lastTouch (kept across TTL expiry by get)
// carries the throttle over refills, so the touch rate stays bounded by
// lastUsedTouchInterval no matter how short the TTL is.
func (c *apiKeyCache) put(keyHash string, e apiKeyCacheEntry, now time.Time) (needTouch bool) {
	if c == nil {
		return true
	}
	e.fetchedAt = now
	needTouch = true
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[keyHash]; ok && now.Sub(old.lastTouch) < lastUsedTouchInterval {
		e.lastTouch = old.lastTouch
		needTouch = false
	} else {
		e.lastTouch = now
	}
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
	return needTouch
}
