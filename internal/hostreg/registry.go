package hostreg

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// ErrHostNotActive is returned by ActiveClientFor when a host must not accept
// new host-local work (for example a saved-snapshot fork on an unhealthy or
// draining host). Cleanup callers may still use ClientFor to reach that exact
// host without treating lifecycle status as a scheduling decision.
var ErrHostNotActive = errors.New("host is not active")

// DialFunc creates a VMD client for the given gRPC address. onDead is
// called when the transport reports the peer unreachable; the registry
// wires it to Invalidate.
type DialFunc func(hostID, addr string, onDead func()) (vmdclient.Client, error)

// Registry maps host IDs to VMD clients, cached on first use.
type Registry struct {
	db      *db.Queries
	dial    DialFunc
	mu      sync.RWMutex
	clients map[string]vmdclient.Client
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:      queries,
		dial:    dial,
		clients: make(map[string]vmdclient.Client),
	}
}

// ClientFor returns the VMD client for the given host. It looks up the host
// in the DB on first access, dials gRPC, and caches the result.
func (r *Registry) ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error) {
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

	c, err = r.dial(hostID, host.VmdAddr, func() { r.Invalidate(hostID) })
	if err != nil {
		return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
	}

	r.clients[hostID] = c
	return c, nil
}

// ActiveClientFor resolves hostID only when its current database status is
// active. Unlike ClientFor it performs the status read even when a client is
// cached, so an unhealthy transition cannot be bypassed by an old connection.
func (r *Registry) ActiveClientFor(ctx context.Context, hostID string) (vmdclient.Client, error) {
	host, err := r.db.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("get host %q: %w", hostID, err)
	}
	if host.Status != "active" {
		return nil, fmt.Errorf("%w: host %q status is %q", ErrHostNotActive, hostID, host.Status)
	}

	r.mu.RLock()
	c, ok := r.clients[hostID]
	r.mu.RUnlock()
	if ok {
		return c, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[hostID]; ok {
		return c, nil
	}
	c, err = r.dial(hostID, host.VmdAddr, func() { r.Invalidate(hostID) })
	if err != nil {
		return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
	}
	r.clients[hostID] = c
	return c, nil
}

// Invalidate drops the cached client for hostID so the next ClientFor
// call re-resolves the host's address.
func (r *Registry) Invalidate(hostID string) {
	r.mu.Lock()
	delete(r.clients, hostID)
	r.mu.Unlock()
}
