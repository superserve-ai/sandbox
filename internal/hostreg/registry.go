package hostreg

import (
	"context"
	"fmt"
	"sync"

	"github.com/superserve-ai/sandbox/internal/db"
)

// DialFunc creates a client for the given gRPC address. The returned value
// must satisfy api.VMDClient — the concrete type is opaque to the registry.
type DialFunc func(addr string) (any, error)

// Registry maps host IDs to VMD clients. Clients are lazily created on
// first use and cached.
type Registry struct {
	db      *db.Queries
	dial    DialFunc
	mu      sync.RWMutex
	clients map[string]any
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:      queries,
		dial:    dial,
		clients: make(map[string]any),
	}
}

// ClientFor returns the VMD client for the given host. It looks up the host
// in the DB on first access, dials gRPC, and caches the result. The caller
// must type-assert the result to api.VMDClient.
func (r *Registry) ClientFor(ctx context.Context, hostID string) (any, error) {
	r.mu.RLock()
	c, ok := r.clients[hostID]
	r.mu.RUnlock()
	if ok {
		return c, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if c, ok := r.clients[hostID]; ok {
		return c, nil
	}

	host, err := r.db.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("get host %q: %w", hostID, err)
	}

	c, err = r.dial(host.VmdAddr)
	if err != nil {
		return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
	}

	r.clients[hostID] = c
	return c, nil
}
