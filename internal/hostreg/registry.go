package hostreg

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// DialFunc creates a VMD client for the given gRPC address. onDead is
// called when the transport reports the peer unreachable; the registry
// wires it to Invalidate.
type DialFunc func(hostID, addr string, onDead func()) (vmdclient.Client, error)

// addrRecheckTTL bounds how long a cached client can go without its address
// being re-verified against the host row. An address change (a host identity
// reclaimed by a re-provisioned machine) is only observed directly by the
// control-plane replica that served the heartbeat; every other replica
// converges by this recheck instead of holding the old address forever —
// which would keep routing RPCs to the previous machine, silently if that
// machine is still alive.
const addrRecheckTTL = 30 * time.Second

type entry struct {
	client    vmdclient.Client
	addr      string
	checkedAt time.Time
}

// Registry maps host IDs to VMD clients, cached on first use.
type Registry struct {
	db      *db.Queries
	dial    DialFunc
	recheck time.Duration // 0 = addrRecheckTTL; tests shorten it

	mu       sync.RWMutex
	clients  map[string]entry
	checking sync.Map // hostID → struct{}: one address recheck in flight per host
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:      queries,
		dial:    dial,
		clients: make(map[string]entry),
	}
}

func (r *Registry) recheckTTL() time.Duration {
	if r.recheck > 0 {
		return r.recheck
	}
	return addrRecheckTTL
}

// ClientFor returns the VMD client for the given host. It looks up the host
// in the DB on first access, dials gRPC, and caches the result. Cached
// clients are served stale-while-revalidate: past the recheck TTL the
// current request still gets the cached client while the address is
// re-verified in the background.
func (r *Registry) ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error) {
	r.mu.RLock()
	e, ok := r.clients[hostID]
	r.mu.RUnlock()
	if ok {
		if time.Since(e.checkedAt) >= r.recheckTTL() {
			r.recheckAddr(ctx, hostID, e.addr)
		}
		return e.client, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if e, ok := r.clients[hostID]; ok {
		return e.client, nil
	}

	host, err := r.db.GetHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("get host %q: %w", hostID, err)
	}

	c, err := r.dial(hostID, host.VmdAddr, func() { r.Invalidate(hostID) })
	if err != nil {
		return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
	}

	r.clients[hostID] = entry{client: c, addr: host.VmdAddr, checkedAt: time.Now()}
	return c, nil
}

// recheckAddr re-reads the host row off the request path and evicts the
// cached client when its address no longer matches. One recheck per host at
// a time; on lookup failure the client is kept — RPC failures and the
// dead-peer callback remain the backstop.
func (r *Registry) recheckAddr(ctx context.Context, hostID, cachedAddr string) {
	if _, busy := r.checking.LoadOrStore(hostID, struct{}{}); busy {
		return
	}
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	go func() {
		defer cancel()
		defer r.checking.Delete(hostID)
		host, err := r.db.GetHost(qctx, hostID)
		if err != nil {
			return
		}
		if host.VmdAddr == cachedAddr {
			r.mu.Lock()
			if e, ok := r.clients[hostID]; ok && e.addr == cachedAddr {
				e.checkedAt = time.Now()
				r.clients[hostID] = e
			}
			r.mu.Unlock()
			return
		}
		log.Warn().Str("host_id", hostID).Str("old_addr", cachedAddr).
			Str("new_addr", host.VmdAddr).
			Msg("host address changed; evicting cached vmd client")
		r.Invalidate(hostID)
	}()
}

// Invalidate drops the cached client for hostID so the next ClientFor
// call re-resolves the host's address.
func (r *Registry) Invalidate(hostID string) {
	r.mu.Lock()
	delete(r.clients, hostID)
	r.mu.Unlock()
}
