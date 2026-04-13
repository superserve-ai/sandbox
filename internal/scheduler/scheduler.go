package scheduler

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

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

	mu       sync.RWMutex
	cached   []db.ListActiveHostsByLoadRow
	cachedAt time.Time
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

func (s *LeastLoaded) loadHosts(ctx context.Context) ([]db.ListActiveHostsByLoadRow, error) {
	s.mu.RLock()
	if s.cached != nil && time.Since(s.cachedAt) < s.ttl() {
		hosts := s.cached
		s.mu.RUnlock()
		return hosts, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && time.Since(s.cachedAt) < s.ttl() {
		return s.cached, nil
	}

	hosts, err := s.DB.ListActiveHostsByLoad(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active hosts by load: %w", err)
	}
	s.cached = hosts
	s.cachedAt = time.Now()
	return hosts, nil
}

// Invalidate drops the cached host list so the next SelectHost reflects
// changes immediately.
func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.cachedAt = time.Time{}
	s.mu.Unlock()
}
