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

// observation is one read of a host row's address and when that read began.
type observation struct {
	addr string
	at   time.Time
}

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
	client vmdclient.Client
	addr   string
	// verifiedAt records the last SUCCESSFUL row verification — the clock
	// the serve-stale lease runs on; it advances only on success, so
	// sustained read failures run the lease out and fail closed.
	verifiedAt time.Time
	// nextCheckAt is when verification becomes due: verifiedAt+TTL after a
	// success, now+backoff after a failure. Explicit state rather than
	// arithmetic on one clock, so the failure backoff can never place the
	// entry inside the refresh-ahead window and defeat its own pacing.
	nextCheckAt time.Time
	// degraded marks the last verification attempt as failed. It suppresses
	// refresh-ahead: while degraded, verification happens only at
	// nextCheckAt via the blocking path, paced by the backoff.
	degraded bool
}

// Registry maps host IDs to VMD clients, cached on first use.
type Registry struct {
	db      *db.Queries
	dial    DialFunc
	recheck time.Duration // 0 = addrRecheckTTL; tests shorten it
	// Observe, when set, records each EXECUTED resolution exactly once —
	// inside the shared singleflight flight, not per waiter, so a burst of
	// lifecycle requests on one cold/expired entry contributes one sample,
	// and a canceled waiter cannot record an error for a resolution that
	// succeeded behind it. kind is "cold" (no cached client at flight
	// start) or "due" (re-verification). A blocking resolution is a
	// bounded (~2s worst-case) component of create/resume tail latency and
	// must be attributable on its own.
	Observe func(kind string, d time.Duration, err error)
	// failBackoff overrides verifyFailureBackoff for tests, which need a
	// backoff strictly shorter than the TTL to reproduce the production
	// ratio (5s vs 30s) — equal values mask backoff/refresh interactions.
	failBackoff time.Duration

	mu      sync.RWMutex
	clients map[string]entry
	// gens is bumped per host by Invalidate. resolve snapshots the
	// generation before reading the row and discards its result if the
	// generation moved — otherwise a read or dial finishing after a
	// concurrent invalidation would return or cache the just-invalidated
	// address. The mutex is never held across I/O, so an invalidation can
	// always land mid-resolve and be observed. Grows one counter per host
	// id ever seen (fleet-bounded).
	gens map[string]uint64
	// latest is the newest observation of each host's row address, from a
	// resolution's own read or from a caller's MarkVerified, ordered by when
	// the read STARTED. A resolution publishes only what no newer read
	// contradicts, and a caller's report lands only if no newer read
	// contradicts it, so an older read can never overwrite a newer one
	// whichever side it came from — including when an address returns to
	// an earlier value. Equal addresses never conflict, so equivalent
	// reports cost a resolution in flight nothing.
	latest  map[string]observation
	resolve singleflight.Group // one row-read/dial resolution in flight per host
	// refreshing holds hosts with a refresh-ahead goroutine in flight.
	// Singleflight dedupes the underlying read but not the goroutines
	// waiting on it — without this guard, every warm call in the refresh
	// window would park a goroutine behind a slow (up to 2s) read.
	refreshing sync.Map // hostID → struct{}
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:      queries,
		dial:    dial,
		clients: make(map[string]entry),
		gens:    make(map[string]uint64),
		latest:  make(map[string]observation),
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
	if r.failBackoff > 0 {
		return r.failBackoff
	}
	if ttl := r.recheckTTL(); ttl < 5*time.Second {
		return ttl
	}
	return 5 * time.Second
}

// unverifiedLease bounds how long a client may be dispatched without a
// successful row verification when reads are failing. Within the lease a
// read blip serves the cached client (availability); past it dispatch fails
// closed — another replica may have reclaimed the identity, and "we could
// not check" must not mean "forever" (a sustained DB problem would
// otherwise keep routing to a machine that lost the identity indefinitely).
func (r *Registry) unverifiedLease() time.Duration {
	return 2 * r.recheckTTL()
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
	now := time.Now()
	// The fast path requires BOTH clocks: not yet due (nextCheckAt) and
	// still inside the verified lease. Without the lease check here, a
	// failure backoff could keep serving for its whole window after the
	// lease expired mid-backoff.
	if ok && now.Before(e.nextCheckAt) && now.Sub(e.verifiedAt) < r.unverifiedLease() {
		if !e.degraded && e.nextCheckAt.Sub(now) <= r.recheckTTL()/5 {
			// Refresh ahead of expiry: warm traffic re-verifies in the
			// background while still being served fresh, so the blocking
			// due-verification read almost never lands on a request.
			// Suppressed while degraded — after a failure, pacing belongs
			// to the backoff alone. One goroutine per host at a time; the
			// generation guard keeps the async result safe.
			if _, busy := r.refreshing.LoadOrStore(hostID, struct{}{}); !busy {
				go func() {
					defer r.refreshing.Delete(hostID)
					_, _ = r.resolveClient(context.WithoutCancel(ctx), hostID)
				}()
			}
		}
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
	ch := r.resolve.DoChan(hostID, func() (v any, err error) {
		// Detached context: singleflight followers share the leader's
		// result, so the leader's per-request cancellation must not decide
		// the resolution for everyone behind it.
		vctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()

		// One observation per executed flight: kind fixed at flight start,
		// duration and result those of the resolution itself, regardless
		// of how many callers share it or abandon their wait.
		if r.Observe != nil {
			r.mu.RLock()
			_, hadEntry := r.clients[hostID]
			r.mu.RUnlock()
			kind := "cold"
			if hadEntry {
				kind = "due"
			}
			started := time.Now()
			defer func() { r.Observe(kind, time.Since(started), err) }()
		}

		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			r.mu.RLock()
			startGen := r.gens[hostID]
			prev, hadPrev := r.clients[hostID]
			r.mu.RUnlock()

			readAt := time.Now()
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
				withinLease := ok && time.Since(e.verifiedAt) < r.unverifiedLease()
				if withinLease {
					// Bounded backoff: the next verification is due after
					// the backoff, not before, and degraded suppresses
					// refresh-ahead — so a failing DB is retried on the
					// backoff's pace, never per call. verifiedAt (the lease
					// clock) advances solely on successful reads, so
					// sustained failure runs the lease out and fails closed.
					e.nextCheckAt = time.Now().Add(r.verifyFailureBackoff())
					e.degraded = true
					r.clients[hostID] = e
				}
				r.mu.Unlock()
				if withinLease {
					log.Warn().Err(err).Str("host_id", hostID).
						Msg("host address verification failed; dispatching via cached client within lease")
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
			if r.contradictedLocked(hostID, host.VmdAddr, readAt) {
				r.mu.Unlock()
				continue // a newer read saw the host elsewhere; re-read the row
			}
			r.recordLocked(hostID, host.VmdAddr, readAt)
			if e, ok := r.clients[hostID]; ok && e.addr == host.VmdAddr {
				now := time.Now()
				e.verifiedAt, e.nextCheckAt, e.degraded = now, now.Add(r.recheckTTL()), false
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
			if r.contradictedLocked(hostID, host.VmdAddr, readAt) {
				r.mu.Unlock()
				continue // the address moved on while we dialed; re-read the row
			}
			now := time.Now()
			r.clients[hostID] = entry{
				client: c, addr: host.VmdAddr,
				verifiedAt: now, nextCheckAt: now.Add(r.recheckTTL()),
			}
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
	delete(r.latest, hostID)
	r.gens[hostID]++
	r.mu.Unlock()
}

// MarkVerified records a host row read the caller has just performed — the
// address it saw and when the read began — so the dispatch that follows
// finds a verified client instead of blocking on a row read of its own. A
// report a newer read already contradicts is dropped: that read governs. A
// cached client at the reported address has its lease renewed in place.
// Otherwise the host is resolved now (row read plus dial); a cached client
// at a DIFFERENT address is dropped first, since the row just said the host
// moved and that client must not survive as a within-lease fallback should
// the resolution fail to read. A resolution already in flight that read an
// older, different address re-reads before publishing (see latest), so this
// report is never overwritten by it. A resolution failure is logged and
// leaves ClientFor to fail closed.
func (r *Registry) MarkVerified(ctx context.Context, hostID, addr string, readAt time.Time) {
	if addr == "" {
		return
	}
	r.mu.Lock()
	if r.contradictedLocked(hostID, addr, readAt) {
		r.mu.Unlock()
		return
	}
	r.recordLocked(hostID, addr, readAt)
	if e, ok := r.clients[hostID]; ok {
		if e.addr == addr {
			now := time.Now()
			e.verifiedAt, e.nextCheckAt, e.degraded = now, now.Add(r.recheckTTL()), false
			r.clients[hostID] = e
			r.mu.Unlock()
			return
		}
		log.Warn().Str("host_id", hostID).Str("old_addr", e.addr).Str("new_addr", addr).
			Msg("host address changed; dropping the cached client before re-resolving")
		delete(r.clients, hostID)
	}
	r.mu.Unlock()
	if _, err := r.resolveClient(ctx, hostID); err != nil {
		log.Warn().Err(err).Str("host_id", hostID).Msg("host client resolution after row verification failed")
	}
}

// contradictedLocked reports whether a read of addr that began at readAt is
// contradicted by a newer read that saw a different address. Caller holds mu.
func (r *Registry) contradictedLocked(hostID, addr string, readAt time.Time) bool {
	l, ok := r.latest[hostID]
	return ok && l.at.After(readAt) && l.addr != addr
}

// recordLocked keeps an observation when it is at least as new as the one
// held. Caller holds mu.
func (r *Registry) recordLocked(hostID, addr string, readAt time.Time) {
	if l, ok := r.latest[hostID]; !ok || !readAt.Before(l.at) {
		r.latest[hostID] = observation{addr: addr, at: readAt}
	}
}
