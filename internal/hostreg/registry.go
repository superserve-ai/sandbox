package hostreg

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// DialFunc creates a VMD client for the given gRPC address. onDead is
// called when the transport reports the peer unreachable; the registry
// wires it to Invalidate.
type DialFunc func(hostID, addr string, onDead func()) (vmdclient.Client, error)

// addrRecheckTTL bounds how long a cached client can be dispatched through
// without its address being re-verified against the host row. An address
// change (a host identity reclaimed by a re-provisioned machine) is only
// observed directly by the control-plane replica that served the heartbeat;
// every other replica converges through this recheck. The verification is
// blocking, not stale-while-revalidate: the wrong-machine case — the old
// daemon still alive but no longer the identity's holder — fails silently,
// so an operation must never be dispatched through a client whose address is
// due. Cost: one row read per host per interval shared across all concurrent
// callers (singleflight), never one per operation.
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

	mu      sync.RWMutex
	clients map[string]entry
	// gens is bumped per host by Invalidate. A verification snapshots the
	// generation before reading the row and discards its result if the
	// generation moved — otherwise a dial finishing after a concurrent
	// invalidation would resurrect the just-invalidated address as freshly
	// verified. Grows one counter per host id ever seen (fleet-bounded).
	gens   map[string]uint64
	verify singleflight.Group // one address verification in flight per host
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:      queries,
		dial:    dial,
		clients: make(map[string]entry),
		gens:    make(map[string]uint64),
	}
}

func (r *Registry) recheckTTL() time.Duration {
	if r.recheck > 0 {
		return r.recheck
	}
	return addrRecheckTTL
}

// ClientFor returns the VMD client for the given host. It looks up the host
// in the DB on first access, dials gRPC, and caches the result. A cached
// client past the recheck TTL is re-verified against the host row before
// being returned; if the row's address changed, the new address is dialed
// and returned, so the caller never dispatches to the previous machine.
func (r *Registry) ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error) {
	r.mu.RLock()
	e, ok := r.clients[hostID]
	r.mu.RUnlock()
	if ok && time.Since(e.checkedAt) < r.recheckTTL() {
		return e.client, nil
	}
	if ok {
		return r.verifyAndGet(ctx, hostID, e)
	}
	return r.dialAndCache(ctx, hostID)
}

// verifyAndGet re-reads the host row for a due entry and returns a client
// for the row's current address — the cached one when unchanged, a freshly
// dialed one when the address moved. Concurrent callers share one
// verification. A failed row read returns the cached client: the hazard
// needs a reclaim and a DB failure in the same window, and refusing to
// dispatch on any read blip would trade it for routine unavailability.
func (r *Registry) verifyAndGet(ctx context.Context, hostID string, stale entry) (vmdclient.Client, error) {
	v, err, _ := r.verify.Do(hostID, func() (any, error) {
		// Detached context: singleflight followers share the leader's
		// result, so the leader's per-request cancellation must not decide
		// the verification for everyone behind it.
		vctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		// Bounded retry: if an invalidation (an address reclaim landing on
		// this replica) races the verification, the result is discarded and
		// the row re-read, so a verification started against an older row
		// version can never resurrect an invalidated address as verified.
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			r.mu.RLock()
			startGen := r.gens[hostID]
			r.mu.RUnlock()

			host, err := r.db.GetHost(vctx, hostID)
			if err != nil {
				// Falling back to the cached client is only safe while the
				// entry is demonstrably not invalidated: still present at
				// the same address. An invalidated entry with an unreadable
				// row retries, then fails closed — the invalidation had a
				// reason, and dispatching past it risks the wrong machine.
				r.mu.RLock()
				e, ok := r.clients[hostID]
				r.mu.RUnlock()
				if ok {
					// Whatever entry the cache holds now — the original or a
					// replacement — is the best available knowledge.
					log.Warn().Err(err).Str("host_id", hostID).
						Msg("host address verification failed; dispatching via cached client")
					return e.client, nil
				}
				lastErr = err
				continue
			}
			// If the cache already holds an entry at the row's address —
			// the common case, or a replacement another caller dialed after
			// an invalidation — that entry's client is the one to return.
			// Returning the snapshot instead could hand back a client whose
			// transport was already invalidated as dead.
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				r.mu.Unlock()
				continue // invalidated mid-verification; re-read the row
			}
			if e, ok := r.clients[hostID]; ok && e.addr == host.VmdAddr {
				e.checkedAt = time.Now()
				r.clients[hostID] = e
				r.mu.Unlock()
				return e.client, nil
			}
			r.mu.Unlock()

			// No usable entry for the row's address: dial it. This covers
			// both an address change and an invalidated-but-unmoved host.
			if host.VmdAddr != stale.addr {
				log.Warn().Str("host_id", hostID).Str("old_addr", stale.addr).
					Str("new_addr", host.VmdAddr).
					Msg("host address changed; re-dialing before dispatch")
			}
			c, err := r.dial(hostID, host.VmdAddr, func() { r.Invalidate(hostID) })
			if err != nil {
				// No falling back to the old-address client here: failing
				// loudly beats executing on the machine that lost this identity.
				r.Invalidate(hostID)
				return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
			}
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				// A reclaim landed while dialing: this address is already
				// old. Drop the dialed client and verify against the row
				// as it stands now.
				r.mu.Unlock()
				continue
			}
			r.clients[hostID] = entry{client: c, addr: host.VmdAddr, checkedAt: time.Now()}
			r.mu.Unlock()
			return c, nil
		}
		if lastErr != nil {
			return nil, fmt.Errorf("verify host %q after invalidation: %w", hostID, lastErr)
		}
		return nil, fmt.Errorf("host %q address changed repeatedly during verification; retry", hostID)
	})
	if err != nil {
		return nil, err
	}
	c, _ := v.(vmdclient.Client) // comma-ok: a nil client stays a plain nil
	return c, nil
}

func (r *Registry) dialAndCache(ctx context.Context, hostID string) (vmdclient.Client, error) {
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

// Invalidate drops the cached client for hostID so the next ClientFor
// call re-resolves the host's address, and bumps the host's generation so
// any in-flight verification discards its result instead of repopulating
// the entry it just removed.
func (r *Registry) Invalidate(hostID string) {
	r.mu.Lock()
	delete(r.clients, hostID)
	r.gens[hostID]++
	r.mu.Unlock()
}
