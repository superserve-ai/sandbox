package scheduler

import (
	"context"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/db"
)

// Scheduler selects a host for a new sandbox.
type Scheduler interface {
	SelectHost(ctx context.Context) (hostID string, err error)
}

// PickFirst returns the first active host. Single-host today; upgrade to
// least-loaded when we add capacity tracking in Phase 4.
type PickFirst struct {
	DB *db.Queries
}

func (s *PickFirst) SelectHost(ctx context.Context) (string, error) {
	hosts, err := s.DB.ListActiveHosts(ctx)
	if err != nil {
		return "", fmt.Errorf("list active hosts: %w", err)
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("no active hosts available")
	}
	return hosts[0].ID, nil
}
