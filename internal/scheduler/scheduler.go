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

const defaultCacheTTL = 30 * time.Second

// LeastLoaded picks the active host with the fewest running sandboxes.
// Skips unhealthy and draining hosts. The result is cached with a short
// TTL so the DB isn't hit on every create.
type LeastLoaded struct {
	DB  *db.Queries
	TTL time.Duration // 0 = use defaultCacheTTL

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
		return "", fmt.Errorf("no active hosts available")
	}
	// Already sorted by active_sandbox_count ASC — first row is least loaded.
	return hosts[0].ID, nil
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
// changes immediately. Called when hosts are added, removed, or drained.
func (s *LeastLoaded) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.cachedAt = time.Time{}
	s.mu.Unlock()
}
