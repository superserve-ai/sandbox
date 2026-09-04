package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Scheduler selects a host for a new sandbox.
type Scheduler interface {
	SelectHost(ctx context.Context, requiredCapabilities []string) (hostID string, err error)
}

const defaultCacheTTL = 30 * time.Second

// hostsFillTimeout bounds every candidate-set fill, blocking and background
// alike. The candidate set is a placement hint served at any age; what keeps
// a drained or retired host from taking a create is the per-create host
// pre-flight (status and capabilities read fresh within its own TTL), so
// this bound is hygiene for the fill itself rather than part of the drain
// convergence budget.
const hostsFillTimeout = 5 * time.Second

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
	cache      map[string]hostCacheEntry
	gen        uint64      // bumped by Invalidate and blocking reloads; discards refreshes that started earlier
	refreshing atomic.Bool // one background refresh at a time across capability sets
}

type hostCacheEntry struct {
	hosts    []db.ListActiveHostsByLoadRow
	cachedAt time.Time
	// defaultStatus is the DefaultHostID row's status, resolved at fill time
	// only when hosts is empty — so the fallback decision in SelectHost never
	// queries on the per-create path. "missing" = no row (bootstrap mode,
	// fallback allowed); "" = not resolved (candidates exist or no default).
	defaultStatus string
}

func (s *LeastLoaded) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return defaultCacheTTL
}

func (s *LeastLoaded) SelectHost(ctx context.Context, requiredCapabilities []string) (string, error) {
	entry, err := s.loadHosts(ctx, requiredCapabilities)
	if err != nil {
		return "", err
	}
	hosts := entry.hosts
	if len(hosts) == 0 {
		if s.DefaultHostID != "" {
			// The legacy fallback exists so creation works before the host
			// table is populated. It must not route to a row that exists in
			// a non-active state — a freshly self-registered 'provisioning'
			// host under the default ID would take traffic before an
			// operator activates it. The status was resolved at cache-fill
			// time (fillEntry); status changes invalidate the cache.
			switch entry.defaultStatus {
			case "missing": // unpopulated table: bootstrap path
				return s.DefaultHostID, nil
			case "active":
				// Present but filtered out by capabilities; the create-time
				// capability gate still enforces. Preserves prior behavior.
				return s.DefaultHostID, nil
			case "":
				return "", fmt.Errorf("no active hosts available")
			default:
				return "", fmt.Errorf("no active hosts available (default host is %s)", entry.defaultStatus)
			}
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

// fillEntry loads the candidate set and, when it comes back empty, resolves
// the default host's status in the same fill — one query per cache fill, not
// one per create. Status changes reach the cache through Invalidate.
func (s *LeastLoaded) fillEntry(ctx context.Context, normalized []string) (hostCacheEntry, error) {
	hosts, err := s.DB.ListActiveHostsByLoad(ctx, normalized)
	if err != nil {
		return hostCacheEntry{}, fmt.Errorf("list active hosts by load: %w", err)
	}
	entry := hostCacheEntry{hosts: hosts, cachedAt: time.Now()}
	if len(hosts) == 0 && s.DefaultHostID != "" {
		host, err := s.DB.GetHost(ctx, s.DefaultHostID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			entry.defaultStatus = "missing"
		case err != nil:
			return hostCacheEntry{}, fmt.Errorf("get default host %q: %w", s.DefaultHostID, err)
		default:
			entry.defaultStatus = host.Status
		}
	}
	return entry, nil
}

// loadHosts serves a cached capability-specific candidate set at any age and
// refreshes it in the background once the TTL lapses. Only the first call for
// a set and a post-Invalidate call block on a fresh load. A request that
// finds the set expired never waits for the DB: it serves what it has and
// the refresh rides along behind it. Serving a stale set is safe because the
// create path re-reads the chosen host's status and capabilities before
// dispatch and re-selects after an Invalidate when that read rejects it, so
// a host that left rotation is at most one bounded pre-flight away from
// being dropped, however old this cache is.
func (s *LeastLoaded) loadHosts(ctx context.Context, requiredCapabilities []string) (hostCacheEntry, error) {
	key, normalized := capabilityCacheKey(requiredCapabilities)
	s.mu.RLock()
	entry, cached := s.cache[key]
	startGen := s.gen
	s.mu.RUnlock()

	if cached {
		if time.Since(entry.cachedAt) >= s.ttl() && s.refreshing.CompareAndSwap(false, true) {
			// Detached: the refresh outlives the triggering request. On error the
			// stale set stays servable and the next expired call retries.
			qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostsFillTimeout)
			go func() {
				defer cancel()
				defer s.refreshing.Store(false)
				fresh, err := s.fillEntry(qctx, normalized)
				if err != nil {
					log.Warn().Err(err).Strs("required_capabilities", normalized).
						Msg("host list refresh failed; serving stale until the grace window expires")
					return
				}
				s.mu.Lock()
				// Discard results from before the latest Invalidate or blocking
				// reload so an older query cannot replace a newer candidate set.
				if s.gen == startGen {
					if s.cache == nil {
						s.cache = make(map[string]hostCacheEntry)
					}
					s.cache[key] = fresh
				}
				s.mu.Unlock()
			}()
		}
		return entry, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: another blocked caller may have loaded this capability
	// set while we waited.
	if entry, ok := s.cache[key]; ok {
		return entry, nil
	}
	fillCtx, fillCancel := context.WithTimeout(ctx, hostsFillTimeout)
	fresh, err := s.fillEntry(fillCtx, normalized)
	fillCancel()
	if err != nil {
		return hostCacheEntry{}, err
	}
	// Bump the generation so any older in-flight background refresh cannot
	// land after this blocking load and replace it with an earlier snapshot.
	s.gen++
	if s.cache == nil {
		s.cache = make(map[string]hostCacheEntry)
	}
	s.cache[key] = fresh
	return fresh, nil
}

func capabilityCacheKey(capabilities []string) (string, []string) {
	set := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability != "" {
			set[capability] = struct{}{}
		}
	}
	normalized := make([]string, 0, len(set))
	for capability := range set {
		normalized = append(normalized, capability)
	}
	sort.Strings(normalized)
	return strings.Join(normalized, "\x00"), normalized
}

// Invalidate drops all cached capability-specific candidate sets so the next
// SelectHost reflects status or capability changes immediately.
func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.gen++
	s.cache = nil
	s.mu.Unlock()
}
