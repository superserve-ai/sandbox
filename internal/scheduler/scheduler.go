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
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Scheduler selects a host for a new sandbox. gen identifies the candidate
// set the selection came from, for Reject.
type Scheduler interface {
	SelectHost(ctx context.Context, requiredCapabilities []string) (hostID string, gen uint64, err error)
}

const defaultCacheTTL = 30 * time.Second

// hostsFillTimeout bounds every candidate-set fill, blocking and background
// alike. The candidate set is a placement hint; the per-create host
// pre-flight is what keeps a drained host from taking a create, so this
// bound is not part of the drain convergence budget.
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

	mu            sync.RWMutex
	cache         map[string]hostCacheEntry
	gen           uint64             // stamped on every published set; a Reject carries the set's stamp
	invalidations uint64             // bumped by Invalidate; a load begun before it is not cached
	refreshing    atomic.Bool        // one background refresh at a time across capability sets
	fills         singleflight.Group // one blocking fill per capability set at a time
}

type hostCacheEntry struct {
	hosts    []db.ListActiveHostsByLoadRow
	cachedAt time.Time
	gen      uint64 // the generation this set was loaded at; a Reject must carry it
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

func (s *LeastLoaded) SelectHost(ctx context.Context, requiredCapabilities []string) (string, uint64, error) {
	entry, err := s.loadHosts(ctx, requiredCapabilities)
	if err != nil {
		return "", 0, err
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
				return s.DefaultHostID, entry.gen, nil
			case "active":
				// Present but filtered out by capabilities; the create-time
				// capability gate still enforces. Preserves prior behavior.
				return s.DefaultHostID, entry.gen, nil
			case "":
				return "", 0, fmt.Errorf("no active hosts available")
			default:
				return "", 0, fmt.Errorf("no active hosts available (default host is %s)", entry.defaultStatus)
			}
		}
		return "", 0, fmt.Errorf("no active hosts available")
	}
	if len(hosts) == 1 {
		return hosts[0].ID, entry.gen, nil
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
		return hosts[a].ID, entry.gen, nil
	}
	return hosts[b].ID, entry.gen, nil
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

// loadHosts serves the cached candidate set at any age and refreshes it in
// the background once the TTL lapses; only the first call for a set and a
// post-Invalidate call block on a load. Serving stale is safe because the
// create path re-reads the chosen host before dispatch and re-selects after
// an Invalidate when that read rejects it.
func (s *LeastLoaded) loadHosts(ctx context.Context, requiredCapabilities []string) (hostCacheEntry, error) {
	key, normalized := capabilityCacheKey(requiredCapabilities)
	s.mu.RLock()
	entry, cached := s.cache[key]
	inv := s.invalidations
	s.mu.RUnlock()

	// An expired set with nothing to place on is reloaded in line: serving
	// it would refuse a create the DB may already be able to place.
	if cached && time.Since(entry.cachedAt) >= s.ttl() && s.cannotPlace(entry) {
		cached = false
	}
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
				s.publish(key, fresh, inv)
			}()
		}
		return entry, nil
	}

	// Blocking load: one fill per capability set at a time, run outside the
	// mutex, so a slow fill for one set never stalls selects for the others.
	// The flight publishes on the leader's invalidation snapshot, the most
	// conservative one; every waiter shares its result.
	ch := s.fills.DoChan(key, func() (any, error) {
		fillCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostsFillTimeout)
		defer cancel()
		fresh, err := s.fillEntry(fillCtx, normalized)
		if err != nil {
			return nil, err
		}
		return s.publish(key, fresh, inv), nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return hostCacheEntry{}, res.Err
		}
		return res.Val.(hostCacheEntry), nil
	case <-ctx.Done():
		return hostCacheEntry{}, ctx.Err()
	}
}

// publish caches fresh for key under a new generation, unless an Invalidate
// landed after the load began (invalidations moved past inv): a set read
// before an invalidation may be what it invalidated, so it is served to the
// request that loaded it but not cached. Returns the entry as it should be
// served, stamped only if cached.
func (s *LeastLoaded) publish(key string, fresh hostCacheEntry, inv uint64) hostCacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalidations != inv {
		return fresh
	}
	s.gen++
	fresh.gen = s.gen
	if s.cache == nil {
		s.cache = make(map[string]hostCacheEntry)
	}
	s.cache[key] = fresh
	return fresh
}

// cannotPlace reports whether this entry has no candidates. An empty set is
// reloaded in line once expired even when the default-host fallback would
// apply: that fallback is a host the capability-filtered load excluded, the
// create pre-flight refuses it, and a rejection cannot evict it — so a reload
// is the only way a host that has since gained the capability gets found.
func (s *LeastLoaded) cannotPlace(e hostCacheEntry) bool {
	return len(e.hosts) == 0
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
// Reject drops the cached candidate set for requiredCapabilities if it is
// still the set (gen) that produced the selection and still lists hostID,
// because the create pre-flight for that set has just refused the host. A
// set loaded since is kept even if it lists the host again — it is fresh
// evidence, and the host is re-attested from it — so a burst of creates
// that all drew the same stale host reloads once, not once per create.
// Other capability sets are untouched, and a default-host fallback is never
// reloaded for this, see names.
func (s *LeastLoaded) Reject(hostID string, requiredCapabilities []string, gen uint64) {
	key, _ := capabilityCacheKey(requiredCapabilities)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.cache[key]; ok && entry.gen == gen && s.names(entry, hostID) {
		delete(s.cache, key)
	}
}

// names reports whether this entry's candidate set lists hostID. The
// default-host fallback (an empty set) deliberately does not count: that
// host is the one the capability-filtered load already excluded, so a
// reload cannot change the answer and would only repeat the query.
func (s *LeastLoaded) names(e hostCacheEntry, hostID string) bool {
	for _, h := range e.hosts {
		if h.ID == hostID {
			return true
		}
	}
	return false
}

func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.invalidations++
	s.cache = nil
	s.mu.Unlock()
}
