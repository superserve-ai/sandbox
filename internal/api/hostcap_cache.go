package api

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/db"
)

// hostCapCache is an in-process, TTL-bounded, positive-only cache of host
// capability attestations, fronting HostHasCapabilitiesUnlocked on the
// standalone pre-flight paths. Same shape as apiKeyCache: only affirmative
// results are cached (a missing capability or an error always re-reads, so a
// capability 409 is always fresh), an expired entry is served for a short
// grace while one background flight refreshes it, and concurrent misses
// coalesce. The fail-closed gates (transactional validation, VMD's post-boot
// attestation) do not go through this cache. Cardinality is hosts ×
// capability sets; puts sweep expired entries, so memory tracks the active
// fleet.
const (
	// The TTL also bounds how long a just-fenced host or dropped capability
	// can keep passing this pre-flight (the create path already tolerates the
	// scheduler cache's 30s for placement).
	defaultHostCapCacheTTL = 10 * time.Second
	hostCapCacheStaleGrace = 2 * time.Second
)

// hostCapCacheTTLFromEnv reads HOST_CAPABILITY_CACHE_TTL (a Go duration,
// e.g. "30s"). Unset or unparsable falls back to the default; a non-positive
// duration disables caching.
func hostCapCacheTTLFromEnv() time.Duration {
	raw := os.Getenv("HOST_CAPABILITY_CACHE_TTL")
	if raw == "" {
		return defaultHostCapCacheTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return defaultHostCapCacheTTL
	}
	return d
}

type hostCapEntry struct {
	attestedAt time.Time // stamped from query start, so a slow read can't stretch the window
	refreshing bool
}

// hostCapCache's zero value is ready to use; the first call reads the TTL and
// allocates the map.
type hostCapCache struct {
	once  sync.Once
	ttl   time.Duration
	group singleflight.Group
	mu    sync.Mutex
	m     map[string]*hostCapEntry
}

func (c *hostCapCache) init() {
	c.once.Do(func() {
		c.ttl = hostCapCacheTTLFromEnv()
		c.m = make(map[string]*hostCapEntry)
	})
}

// get reports whether key holds a servable positive. refresh reports that the
// entry is past its TTL and this caller should kick the background refresh —
// at most one is armed at a time; put and refreshFailed re-arm.
func (c *hostCapCache) get(key string, now time.Time) (refresh, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.m[key]
	if !exists {
		return false, false
	}
	age := now.Sub(e.attestedAt)
	if age > c.ttl+hostCapCacheStaleGrace {
		delete(c.m, key)
		return false, false
	}
	if age > c.ttl && !e.refreshing {
		e.refreshing = true
		refresh = true
	}
	return refresh, true
}

func (c *hostCapCache) put(key string, attestedAt time.Time) {
	c.mu.Lock()
	// Lazy sweep: drop entries past serving age (retired hosts are never read
	// again, so read-time deletion alone would retain them). puts are at most
	// one per key per TTL and the map is hosts × capability sets, so this is
	// cheap.
	for k, e := range c.m {
		if attestedAt.Sub(e.attestedAt) > c.ttl+hostCapCacheStaleGrace {
			delete(c.m, k)
		}
	}
	c.m[key] = &hostCapEntry{attestedAt: attestedAt}
	c.mu.Unlock()
}

func (c *hostCapCache) remove(key string) {
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

func (c *hostCapCache) refreshFailed(key string) {
	c.mu.Lock()
	if e, ok := c.m[key]; ok {
		e.refreshing = false
	}
	c.mu.Unlock()
}

// fetch coalesces concurrent misses: one flight runs the read under a
// detached, bounded context (it may outlive the caller), stores the outcome,
// and every waiter shares the result — but each waiter still selects on its
// own ctx, so a hung-up client returns immediately.
func (h *Handlers) fetchHostCaps(ctx context.Context, key string, params db.HostHasCapabilitiesUnlockedParams) (bool, error) {
	c := &h.hostCaps
	ch := c.group.DoChan(key, func() (interface{}, error) {
		start := time.Now()
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		has, err := h.DB.HostHasCapabilitiesUnlocked(qctx, params)
		switch {
		case err != nil:
		case has:
			c.put(key, start)
		default:
			c.remove(key)
		}
		return has, err
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

func (h *Handlers) hostHasCapabilitiesCached(ctx context.Context, hostID string, capabilities []string) (bool, error) {
	c := &h.hostCaps
	c.init()
	params := db.HostHasCapabilitiesUnlockedParams{HostID: hostID, RequiredCapabilities: capabilities}
	if c.ttl <= 0 {
		return h.DB.HostHasCapabilitiesUnlocked(ctx, params)
	}
	sorted := append([]string(nil), capabilities...)
	sort.Strings(sorted)
	key := hostID + "\x00" + strings.Join(sorted, "\x00")
	refresh, ok := c.get(key, time.Now())
	if ok {
		if refresh {
			go func() {
				_, err := h.fetchHostCaps(context.Background(), key, params)
				if err != nil {
					log.Warn().Err(err).Str("host_id", hostID).Strs("capabilities", capabilities).
						Msg("host capability refresh failed; serving stale until the grace window expires")
					c.refreshFailed(key)
				}
			}()
		}
		return true, nil
	}
	return h.fetchHostCaps(ctx, key, params)
}
