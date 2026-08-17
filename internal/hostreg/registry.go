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
	// gens is bumped per host by Invalidate. resolve snapshots the
	// generation before reading the row and discards its result if the
	// generation moved — otherwise a read or dial finishing after a
	// concurrent invalidation would return or cache the just-invalidated
	// address. The mutex is never held across I/O, so an invalidation can
	// always land mid-resolve and be observed. Grows one counter per host
	// id ever seen (fleet-bounded).
	gens    map[string]uint64
	resolve singleflight.Group // one row-read/dial resolution in flight per host
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

// verifyFailureBackoff paces re-verification while the host row is
// unreadable: capped at 5s so convergence after a reclaim stays quick once
// the DB recovers, and never longer than the recheck TTL itself.
func (r *Registry) verifyFailureBackoff() time.Duration {
	if ttl := r.recheckTTL(); ttl < 5*time.Second {
		return ttl
	}
	return 5 * time.Second
}

// ClientFor returns the VMD client for the given host. A cached client
// within its verification window is returned as-is; anything else — first
// use, or a client past the recheck TTL — resolves against the host row
// before dispatch, so the caller never receives a client for an address
// the row no longer holds.
func (r *Registry) ClientFor(ctx context.Context, hostID string) (vmdclient.Client, error) {
	r.mu.RLock()
	e, ok := r.clients[hostID]
	r.mu.RUnlock()
	if ok && time.Since(e.checkedAt) < r.recheckTTL() {
		return e.client, nil
	}
	return r.resolveClient(ctx, hostID)
}

// resolveClient is the single path for both first-use dials and due
// re-verifications: read the row, return the cache's entry when it already
// matches the row's address, dial otherwise — all generation-guarded, so a
// resolution raced by an Invalidate (an address reclaim committing on this
// replica mid-read or mid-dial) discards its result and re-reads instead of
// returning or caching the just-invalidated address. Concurrent callers for
// one host share a single resolution.
func (r *Registry) resolveClient(ctx context.Context, hostID string) (vmdclient.Client, error) {
	// DoChan rather than Do: the shared resolution keeps running on its
	// detached context and still fills the cache, but each caller waits only
	// as long as its own request lives — a canceled create/resume stops
	// holding its handler goroutine here.
	ch := r.resolve.DoChan(hostID, func() (any, error) {
		// Detached context: singleflight followers share the leader's
		// result, so the leader's per-request cancellation must not decide
		// the resolution for everyone behind it.
		vctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			r.mu.RLock()
			startGen := r.gens[hostID]
			prev, hadPrev := r.clients[hostID]
			r.mu.RUnlock()

			host, err := r.db.GetHost(vctx, hostID)
			if err != nil {
				// Dispatching a cached client on a failed read is only safe
				// while an entry exists NOW — checked after the read, not
				// via the pre-read snapshot, so an invalidation that landed
				// during the read is honored. Invalidated with an
				// unreadable row: retry, then fail closed — the
				// invalidation had a reason, and dispatching past it risks
				// the machine that lost the identity.
				r.mu.Lock()
				e, ok := r.clients[hostID]
				if ok {
					// Bounded backoff: leave the entry "fresh" for a short
					// window so a degraded DB is retried on a pace, not on
					// every call. An invalidation still cuts through — it
					// deletes the entry, and this bump only touches one
					// that survived.
					e.checkedAt = time.Now().Add(r.verifyFailureBackoff() - r.recheckTTL())
					r.clients[hostID] = e
				}
				r.mu.Unlock()
				if ok {
					log.Warn().Err(err).Str("host_id", hostID).
						Msg("host address verification failed; dispatching via cached client")
					return e.client, nil
				}
				lastErr = err
				continue
			}

			// If the cache holds an entry at the row's address — the common
			// case, or a replacement another caller dialed — return that
			// entry's client. Never a snapshot: it may predate an
			// invalidation.
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				r.mu.Unlock()
				continue // invalidated mid-read; re-read the row
			}
			if e, ok := r.clients[hostID]; ok && e.addr == host.VmdAddr {
				e.checkedAt = time.Now()
				r.clients[hostID] = e
				r.mu.Unlock()
				return e.client, nil
			}
			r.mu.Unlock()

			// No usable entry for the row's address: dial it. Covers first
			// use, an address change, and an invalidated-but-unmoved host.
			if hadPrev && prev.addr != host.VmdAddr {
				log.Warn().Str("host_id", hostID).Str("old_addr", prev.addr).
					Str("new_addr", host.VmdAddr).
					Msg("host address changed; re-dialing before dispatch")
			}
			c, err := r.dial(hostID, host.VmdAddr, func() { r.Invalidate(hostID) })
			if err != nil {
				// No falling back to a previous client: failing loudly
				// beats executing on a machine that may have lost the
				// identity.
				r.Invalidate(hostID)
				return nil, fmt.Errorf("dial VMD at %s for host %q: %w", host.VmdAddr, hostID, err)
			}
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				// A reclaim landed while dialing: this address is already
				// old. Drop the dialed client and resolve against the row
				// as it stands now.
				r.mu.Unlock()
				continue
			}
			r.clients[hostID] = entry{client: c, addr: host.VmdAddr, checkedAt: time.Now()}
			r.mu.Unlock()
			return c, nil
		}
		if lastErr != nil {
			return nil, fmt.Errorf("resolve host %q: %w", hostID, lastErr)
		}
		return nil, fmt.Errorf("host %q address changed repeatedly during resolution; retry", hostID)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		c, _ := res.Val.(vmdclient.Client) // comma-ok: a nil client stays a plain nil
		return c, nil
	}
}

// Invalidate drops the cached client for hostID so the next ClientFor
// call re-resolves the host's address, and bumps the host's generation so
// any in-flight resolution discards its result instead of returning or
// repopulating the entry this call just removed.
func (r *Registry) Invalidate(hostID string) {
	r.mu.Lock()
	delete(r.clients, hostID)
	r.gens[hostID]++
	r.mu.Unlock()
}
