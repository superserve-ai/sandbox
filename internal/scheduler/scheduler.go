package scheduler

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Scheduler selects a host for a new sandbox.
type Scheduler interface {
	SelectHost(ctx context.Context) (hostID string, err error)
}

const defaultCacheTTL = 30 * time.Second

// LeastLoaded picks the active host with the fewest running sandboxes
// using the "power of two random choices" algorithm. Instead of always
// picking the globally least-loaded host (which causes thundering herd
// when many creates arrive simultaneously), it samples two random hosts
// from the active set and picks the one with fewer sandboxes.
//
// With one host this degenerates to always picking that host. With two
// or more it spreads load naturally without coordination. The algorithm
// is proven to reduce max load from O(log n / log log n) to O(log log n).
//
// If no host rows exist in the table, SelectHost falls back to
// DefaultHostID so sandbox creation works without populating the host table.
type LeastLoaded struct {
	DB            *db.Queries
	DefaultHostID string        // fallback when no host rows exist
	TTL           time.Duration // 0 = use defaultCacheTTL

	mu         sync.RWMutex
	cached     []db.ListActiveHostsByLoadRow
	cachedAt   time.Time
	gen        uint64      // bumped by Invalidate and blocking reloads; discards refreshes that started earlier
	refreshing atomic.Bool // one background refresh at a time
}

func (s *LeastLoaded) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return defaultCacheTTL
}

func (s *LeastLoaded) SelectHost(ctx context.Context) (string, error) {
	hosts, err := s.loadHosts(ctx)
	if err != nil {
		return "", err
	}
	if len(hosts) == 0 {
		if s.DefaultHostID != "" {
			return s.DefaultHostID, nil
		}
		return "", fmt.Errorf("no active hosts available")
	}
	if len(hosts) == 1 {
		return hosts[0].ID, nil
	}

	// Power of two random choices: pick two random hosts, return the
	// one with fewer active sandboxes. This avoids the thundering-herd
	// problem where every concurrent create picks the same least-loaded
	// host from a globally-sorted list.
	a := rand.IntN(len(hosts))
	b := rand.IntN(len(hosts) - 1)
	if b >= a {
		b++ // ensures b != a
	}
	if hosts[a].ActiveSandboxCount <= hosts[b].ActiveSandboxCount {
		return hosts[a].ID, nil
	}
	return hosts[b].ID, nil
}

// hostsStaleGrace bounds how long an expired host list keeps being served
// while refreshes run (or fail) in the background. Host health flows through
// the DB — the detector marks missed-heartbeat hosts unhealthy and the next
// refresh drops them — so the worst case for routing to a dead host is
// ttl+grace, and persistent refresh failures degrade to blocking (erroring)
// loads instead of serving a dead list forever.
const hostsStaleGrace = 30 * time.Second

// loadHosts serves the cached list — stale included, up to hostsStaleGrace —
// and refreshes it in the background once the TTL lapses, so callers never
// queue behind the refresh. The very first call, a post-Invalidate call, and
// any call past the grace window block on a fresh load.
func (s *LeastLoaded) loadHosts(ctx context.Context) ([]db.ListActiveHostsByLoadRow, error) {
	s.mu.RLock()
	cached, cachedAt, startGen := s.cached, s.cachedAt, s.gen
	s.mu.RUnlock()
	if cached != nil && time.Since(cachedAt) >= s.ttl()+hostsStaleGrace {
		// Past the grace window (refreshes failing or never landing): stop
		// serving the old list and force a blocking reload below.
		cached = nil
	}
	if cached != nil {
		if time.Since(cachedAt) >= s.ttl() && s.refreshing.CompareAndSwap(false, true) {
			// Detached: the refresh outlives the triggering request. On error
			// the stale list stays servable and the next expired call retries.
			qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			go func() {
				defer cancel()
				defer s.refreshing.Store(false)
				hosts, err := s.DB.ListActiveHostsByLoad(qctx)
				if err != nil {
					log.Warn().Err(err).Msg("host list refresh failed; serving stale until the grace window expires")
					return
				}
				s.mu.Lock()
				// Discard results from before the latest Invalidate or blocking
				// reload: storing them would resurrect a host list a newer,
				// fresher load already replaced.
				if s.gen == startGen {
					s.cached = hosts
					s.cachedAt = time.Now()
				}
				s.mu.Unlock()
			}()
		}
		return cached, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: another blocked caller may have reloaded while we waited.
	// A past-grace list does not count — it is what we are here to replace.
	if s.cached != nil && time.Since(s.cachedAt) < s.ttl()+hostsStaleGrace {
		return s.cached, nil
	}
	hosts, err := s.DB.ListActiveHostsByLoad(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active hosts by load: %w", err)
	}
	// Bump the generation so an older in-flight background refresh cannot
	// land after this load and replace it with its earlier snapshot.
	s.gen++
	s.cached = hosts
	s.cachedAt = time.Now()
	return hosts, nil
}

// Invalidate drops the cached host list so the next SelectHost reflects
// changes immediately.
func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.gen++
	s.cached = nil
	s.cachedAt = time.Time{}
	s.mu.Unlock()
}
