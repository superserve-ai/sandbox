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

// hostCapQueryTimeout bounds every capability lookup, cached-miss and
// cache-disabled alike. Part of hostctl's post-admission drain budget:
// admission → capability lookup (this bound) → registry resolve (2s) →
// bounded boot. Widening it widens what drain --wait must cover.
const hostCapQueryTimeout = 5 * time.Second

// hostCapCache is an in-process, TTL-bounded, positive-only cache of host
// capability attestations fronting HostHasCapabilitiesUnlocked on the
// pre-flight paths; the read behind it also hands the host's address to the
// registry as its verification. Same shape as apiKeyCache: only affirmative
// results are cached, an expired entry is served for a short grace while one
// flight refreshes it, and concurrent misses coalesce. Puts sweep expired
// entries, so memory tracks the active fleet.
const (
	// The TTL bounds how long a fenced host can keep passing this pre-flight
	// and feeds hostctl's drain convergence, hence the cap.
	defaultHostCapCacheTTL = 10 * time.Second
	maxHostCapCacheTTL     = 30 * time.Second
	hostCapCacheStaleGrace = 2 * time.Second
)

// hostCapCacheTTLFromEnv reads HOST_CAPABILITY_CACHE_TTL (a Go duration).
// Unset or unparsable falls back to the default, non-positive disables
// caching, and anything above maxHostCapCacheTTL is clamped to it.
func hostCapCacheTTLFromEnv() time.Duration {
	raw := os.Getenv("HOST_CAPABILITY_CACHE_TTL")
	if raw == "" {
		return defaultHostCapCacheTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return defaultHostCapCacheTTL
	}
	return min(d, maxHostCapCacheTTL)
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
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostCapQueryTimeout)
		defer cancel()
		has, err := h.readHostCaps(qctx, params)
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

// readHostCaps performs the pre-flight read and, on an affirmative answer,
// records the address it returned with the host registry. A registry
// resolution failure fails the pre-flight, so the create does not repeat
// that lookup at dispatch.
func (h *Handlers) readHostCaps(ctx context.Context, params db.HostHasCapabilitiesUnlockedParams) (bool, error) {
	var gen uint64
	if h.Hosts != nil {
		gen = h.Hosts.Generation(params.HostID) // before the read, so a reclaim during it is caught
	}
	row, err := h.DB.HostHasCapabilitiesUnlocked(ctx, params)
	if err != nil {
		return false, err
	}
	if row.HasCapabilities && h.Hosts != nil {
		if err := h.Hosts.MarkVerified(ctx, params.HostID, row.VmdAddr, gen); err != nil {
			return false, err
		}
	}
	return row.HasCapabilities, nil
}

func (h *Handlers) hostHasCapabilitiesCached(ctx context.Context, hostID string, capabilities []string) (bool, error) {
	c := &h.hostCaps
	c.init()
	params := db.HostHasCapabilitiesUnlockedParams{HostID: hostID, RequiredCapabilities: capabilities}
	if c.ttl <= 0 {
		// Same bound as the cached fetch: this lookup sits between scheduler
		// admission and the bounded boot work, and ops tooling (hostctl
		// --wait) budgets a fixed post-admission margin for it — an
		// unbounded read here would silently break that arithmetic.
		qctx, cancel := context.WithTimeout(ctx, hostCapQueryTimeout)
		defer cancel()
		return h.readHostCaps(qctx, params)
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
