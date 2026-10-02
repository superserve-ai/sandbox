package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
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

// hostsFillTimeout bounds every candidate-set fill. The set is only a
// placement hint; the per-create pre-flight keeps drained hosts out.
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
	refreshing    sync.Map           // capability keys with a background refresh in flight
	fills         singleflight.Group // one blocking fill per capability set at a time
}

type hostCacheEntry struct {
	hosts    []db.ListActiveHostsByLoadRow
	ids      map[string]struct{} // hosts by ID, so Reject checks membership without scanning under the lock
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
	if len(hosts) > 0 {
		entry.ids = make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			entry.ids[h.ID] = struct{}{}
		}
	}
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
// the background once the TTL lapses; only a cold set, an expired empty set
// and a post-Invalidate call block on a load. Stale is safe: the create path
// re-attests the chosen host and re-selects when that rejects it.
func (s *LeastLoaded) loadHosts(ctx context.Context, requiredCapabilities []string) (hostCacheEntry, error) {
	key, normalized := capabilityCacheKey(requiredCapabilities)
	entry, cached, inv := s.snapshot(key)
	if cached {
		if time.Since(entry.cachedAt) >= s.ttl() && s.claimRefresh(key) {
			// Detached: the refresh outlives the triggering request. On error the
			// stale set stays servable and the next expired call retries.
			qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostsFillTimeout)
			go func() {
				defer cancel()
				defer s.refreshing.Delete(key)
				fresh, err := s.fillEntry(qctx, normalized)
				if err != nil {
					log.Warn().Err(err).Strs("required_capabilities", normalized).
						Msg("host list refresh failed; serving stale, the next expired call retries")
					return
				}
				s.publish(key, fresh, inv, entry.gen)
			}()
		}
		return entry, nil
	}

	// Blocking load, one flight per capability set and invalidation epoch,
	// run outside the mutex so a slow fill never stalls other sets. The epoch
	// keeps a caller arriving after an Invalidate off an older flight.
	ch := s.fills.DoChan(fmt.Sprintf("%s\x00%d", key, inv), func() (any, error) {
		return s.fill(ctx, key, normalized, inv)
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

// snapshot returns the servable cached set for key, if any, and the current
// invalidation epoch. An expired set with nothing to place on is not
// servable: serving it would refuse a create the DB may already be able to
// place, so it is reloaded in line instead.
func (s *LeastLoaded) snapshot(key string) (entry hostCacheEntry, ok bool, inv uint64) {
	s.mu.RLock()
	entry, ok = s.cache[key]
	inv = s.invalidations
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) >= s.ttl() && s.cannotPlace(entry) {
		ok = false
	}
	return entry, ok, inv
}

// fill is one blocking load: it serves what an earlier flight for this key
// published since the caller saw the miss, else reads the DB and publishes.
func (s *LeastLoaded) fill(ctx context.Context, key string, normalized []string, inv uint64) (hostCacheEntry, error) {
	if entry, ok, _ := s.snapshot(key); ok {
		return entry, nil
	}
	fillCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostsFillTimeout)
	defer cancel()
	fresh, err := s.fillEntry(fillCtx, normalized)
	if err != nil {
		return hostCacheEntry{}, err
	}
	return s.publish(key, fresh, inv, 0), nil
}

// claimRefresh reserves the refresh slot for key; false if one is running.
func (s *LeastLoaded) claimRefresh(key string) bool {
	_, busy := s.refreshing.LoadOrStore(key, struct{}{})
	return !busy
}

// publish caches fresh for key under a new generation unless it is stale: an
// Invalidate landed after the load began, or, for a background refresh of
// the set stamped refreshOf (0 for a blocking fill), that set has since been
// replaced. A stale set is still returned to the request that loaded it.
func (s *LeastLoaded) publish(key string, fresh hostCacheEntry, inv, refreshOf uint64) hostCacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalidations != inv {
		return fresh
	}
	if refreshOf != 0 {
		if cur, ok := s.cache[key]; !ok || cur.gen != refreshOf {
			return fresh
		}
	}
	s.gen++
	fresh.gen = s.gen
	if s.cache == nil {
		s.cache = make(map[string]hostCacheEntry)
	}
	s.cache[key] = fresh
	return fresh
}

// cannotPlace reports whether this entry has no candidates. Such a set is
// reloaded in line once expired even when the default-host fallback applies:
// a reload is the only way a host that has since gained the capability is found.
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
// whose pre-flight has just refused it. A set loaded since is kept, so a
// burst that all drew the same stale host reloads once, not once per create.
func (s *LeastLoaded) Reject(hostID string, requiredCapabilities []string, gen uint64) {
	key, _ := capabilityCacheKey(requiredCapabilities)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.cache[key]; ok && entry.gen == gen && s.names(entry, hostID) {
		delete(s.cache, key)
	}
}

// names reports whether this entry lists hostID. The default-host fallback
// (an empty set) does not count: a reload could not change that answer.
func (s *LeastLoaded) names(e hostCacheEntry, hostID string) bool {
	_, ok := e.ids[hostID]
	return ok
}

func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.invalidations++
	s.cache = nil
	s.mu.Unlock()
}
