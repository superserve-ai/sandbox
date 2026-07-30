package api

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/db"
)

// hostCapCache is an in-process, TTL-bounded, positive-only cache of host
// capability attestations, fronting HostHasCapabilitiesUnlocked on the
// standalone pre-flight paths. Capabilities are heartbeat-attested and
// placement already runs off the scheduler's candidate cache, so a short
// positive cache adds no staleness window placement does not already accept.
//
// Only affirmative results are cached: a missing capability (or any error)
// always re-reads the database, so a capability 409 is always fresh and a
// host that loses a capability stops being served within one TTL. The
// fail-closed gates (transactional validation, VMD's post-boot attestation)
// do not go through this cache. Cardinality is hosts × capability sets, so
// the map needs no eviction bound.
const defaultHostCapCacheTTL = 10 * time.Second

// hostCapCacheTTLFromEnv reads HOST_CAPABILITY_CACHE_TTL (a Go duration,
// e.g. "30s"). Unset or unparsable falls back to the default; a non-positive
// duration disables caching (every check reads the database).
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

// hostCapCache's zero value is ready to use (mirrors Handlers.authzOnce):
// the first call reads the TTL and allocates the map.
type hostCapCache struct {
	once  sync.Once
	ttl   time.Duration
	group singleflight.Group // coalesces concurrent misses for the same key
	mu    sync.Mutex
	m     map[string]time.Time // key -> attestedAt of the last positive read
}

func (c *hostCapCache) init() {
	c.once.Do(func() {
		c.ttl = hostCapCacheTTLFromEnv()
		c.m = make(map[string]time.Time)
	})
}

// hostHasCapabilitiesCached serves the pre-flight capability check from the
// positive cache when fresh, and otherwise reads the database (one flight per
// key under concurrent misses — a burst pays one read, not one per request).
func (h *Handlers) hostHasCapabilitiesCached(ctx context.Context, hostID string, capabilities []string) (bool, error) {
	c := &h.hostCaps
	c.init()
	params := db.HostHasCapabilitiesUnlockedParams{HostID: hostID, RequiredCapabilities: capabilities}
	if c.ttl <= 0 {
		return h.DB.HostHasCapabilitiesUnlocked(ctx, params)
	}
	key := hostID + "\x00" + strings.Join(capabilities, "\x00")
	c.mu.Lock()
	attested, hit := c.m[key]
	c.mu.Unlock()
	if hit && time.Since(attested) < c.ttl {
		return true, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		// One detached, bounded flight serves every coalesced caller; the
		// leader's request cancellation must not fail the followers.
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		ok, qerr := h.DB.HostHasCapabilitiesUnlocked(qctx, params)
		c.mu.Lock()
		if qerr == nil && ok {
			c.m[key] = time.Now()
		} else {
			delete(c.m, key) // an expired positive must not linger past a refuting read
		}
		c.mu.Unlock()
		return ok, qerr
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}
