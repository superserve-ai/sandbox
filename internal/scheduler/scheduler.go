package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Scheduler selects a host for a new sandbox.
type Scheduler interface {
	SelectHost(ctx context.Context) (hostID string, err error)
}

// defaultCacheTTL is how long the scheduler trusts a ListActiveHosts
// snapshot. Host rows change rarely (adding a host is an ops task), so
// a coarse TTL removes a DB roundtrip from the create hot path without
// introducing meaningful staleness. The Phase 4 heartbeat reconciler
// will catch any host that goes unhealthy within this window.
const defaultCacheTTL = 30 * time.Second

// PickFirst returns the first active host. Single-host today; upgrade
// to least-loaded when capacity tracking lands.
//
// SelectHost is on every sandbox create, so the result is cached with
// a short TTL to avoid hitting the DB per-request for a table that
// changes on the order of weeks.
type PickFirst struct {
	DB  *db.Queries
	TTL time.Duration // 0 = use defaultCacheTTL

	mu         sync.RWMutex
	cached     []db.Host
	cachedAt   time.Time
}

func (s *PickFirst) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return defaultCacheTTL
}

func (s *PickFirst) SelectHost(ctx context.Context) (string, error) {
	hosts, err := s.activeHosts(ctx)
	if err != nil {
		return "", err
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("no active hosts available")
	}
	return hosts[0].ID, nil
}

// activeHosts returns the active host list, hitting the DB only when the
// cache is empty or stale. Cache reads take an RLock; refreshes take the
// write lock.
func (s *PickFirst) activeHosts(ctx context.Context) ([]db.Host, error) {
	s.mu.RLock()
	if s.cached != nil && time.Since(s.cachedAt) < s.ttl() {
		hosts := s.cached
		s.mu.RUnlock()
		return hosts, nil
	}
	s.mu.RUnlock()

	// Cache miss — acquire the write lock, double-check, then refresh.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && time.Since(s.cachedAt) < s.ttl() {
		return s.cached, nil
	}

	hosts, err := s.DB.ListActiveHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active hosts: %w", err)
	}
	s.cached = hosts
	s.cachedAt = time.Now()
	return hosts, nil
}

// Invalidate drops the cached host list. Called by admin handlers when
// a host is added, removed, or marked unhealthy so the next SelectHost
// reflects the change immediately.
func (s *PickFirst) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.cachedAt = time.Time{}
	s.mu.Unlock()
}
