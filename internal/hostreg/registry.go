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
	// reported is the address a caller last handed to MarkVerified, reportSeq
	// counts those reports, reportConflictSeq is the sequence of the latest
	// report that disagreed with the one before it, and confirmedSeq is the
	// report sequence as of the last row read that published. Reads cannot be
	// ordered by time, so a report that conflicts with an unconfirmed read or
	// with the cached client keeps the host in doubt: it is re-read before
	// anything publishes, never dialed or renewed unread.
	reported          map[string]string
	reportSeq         map[string]uint64
	reportConflictSeq map[string]uint64
	confirmedSeq      map[string]uint64
	resolve           singleflight.Group // one row-read/dial resolution in flight per host
	// refreshing holds hosts with a refresh-ahead goroutine in flight.
	// Singleflight dedupes the underlying read but not the goroutines
	// waiting on it — without this guard, every warm call in the refresh
	// window would park a goroutine behind a slow (up to 2s) read.
	refreshing sync.Map // hostID → struct{}
}

// New creates a Registry backed by the host table.
func New(queries *db.Queries, dial DialFunc) *Registry {
	return &Registry{
		db:                queries,
		dial:              dial,
		clients:           make(map[string]entry),
		gens:              make(map[string]uint64),
		reported:          make(map[string]string),
		reportSeq:         make(map[string]uint64),
		reportConflictSeq: make(map[string]uint64),
		confirmedSeq:      make(map[string]uint64),
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
	return r.resolveFrom(ctx, hostID, "", 0)
}

// Generation is the host's current invalidation generation; a caller
// captures it before reading the host row and hands it to MarkVerified.
func (r *Registry) Generation(hostID string) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gens[hostID]
}

// resolveFrom is resolveClient for a caller that has just reported knownAddr
// (valid while the host's generation is still knownGen). The report is never
// dialed unread; it only renews a client already cached at that address.
func (r *Registry) resolveFrom(ctx context.Context, hostID, knownAddr string, knownGen uint64) (vmdclient.Client, error) {
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

		// Two failed row reads end the resolution; the third attempt is
		// reserved for a conflict-driven re-read, which is not a failure.
		var lastErr error
		readFailures := 0
		for attempt := 0; attempt < 3 && readFailures < 2; attempt++ {
			r.mu.RLock()
			startGen := r.gens[hostID]
			prev, hadPrev := r.clients[hostID]
			seqAtRead := r.reportSeq[hostID]
			r.mu.RUnlock()
			if attempt == 0 && knownAddr != "" && startGen == knownGen {
				if c, ok := r.renewIfCachedAt(hostID, knownAddr); ok {
					return c, nil
				}
			}

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
				readFailures++
				continue
			}
			addr := host.VmdAddr

			// If the cache holds an entry at the row's address — the common
			// case, or a replacement another caller dialed — return that
			// entry's client. Never a snapshot: it may predate an
			// invalidation.
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				r.mu.Unlock()
				continue // invalidated mid-read; re-read the row
			}
			if r.reportedConflictLocked(hostID, seqAtRead, addr) {
				// In doubt: drop the cached client before the re-read so a
				// failed confirmation fails closed for every caller.
				delete(r.clients, hostID)
				r.mu.Unlock()
				continue
			}
			seqAtDial := r.reportSeq[hostID]
			if e, ok := r.clients[hostID]; ok && e.addr == addr {
				now := time.Now()
				e.verifiedAt, e.nextCheckAt, e.degraded = now, now.Add(r.recheckTTL()), false
				r.clients[hostID] = e
				r.confirmLocked(hostID, seqAtRead)
				r.mu.Unlock()
				return e.client, nil
			}
			r.mu.Unlock()

			// No usable entry for the row's address: dial it. Covers first
			// use, an address change, and an invalidated-but-unmoved host.
			if hadPrev && prev.addr != addr {
				log.Warn().Str("host_id", hostID).Str("old_addr", prev.addr).
					Str("new_addr", addr).
					Msg("host address changed; re-dialing before dispatch")
			}
			c, err := r.dial(hostID, addr, func() { r.Invalidate(hostID) })
			if err != nil {
				// No falling back to a previous client: failing loudly
				// beats executing on a machine that may have lost the
				// identity.
				r.Invalidate(hostID)
				return nil, fmt.Errorf("dial VMD at %s for host %q: %w", addr, hostID, err)
			}
			r.mu.Lock()
			if r.gens[hostID] != startGen {
				// A reclaim landed while dialing: this address is already
				// old. Drop the dialed client and resolve against the row
				// as it stands now.
				r.mu.Unlock()
				continue
			}
			if r.reportedConflictLocked(hostID, seqAtDial, addr) {
				// Same as above, for a report that landed during the dial.
				delete(r.clients, hostID)
				r.mu.Unlock()
				continue
			}
			now := time.Now()
			r.clients[hostID] = entry{
				client: c, addr: addr,
				verifiedAt: now, nextCheckAt: now.Add(r.recheckTTL()),
			}
			r.confirmLocked(hostID, seqAtRead)
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
	delete(r.reported, hostID)
	delete(r.reportConflictSeq, hostID)
	delete(r.confirmedSeq, hostID)
	r.gens[hostID]++
	r.mu.Unlock()
}

// MarkVerified records a host row read the caller has just performed (the
// address it saw, and the Generation captured before reading) so the dispatch
// that follows does not read the row again. A report older than the host's
// generation is discarded. A cached client at that address is renewed; every
// other case re-reads the row, since a reclaim committed on another replica
// after the caller's read is invisible here. Failures leave ClientFor to
// fail closed.
func (r *Registry) MarkVerified(ctx context.Context, hostID, addr string, readGen uint64) {
	if addr == "" {
		return
	}
	r.mu.Lock()
	if r.gens[hostID] != readGen {
		r.mu.Unlock()
		return
	}
	seq := r.reportSeq[hostID] + 1
	r.reportSeq[hostID] = seq
	last, seen := r.reported[hostID]
	r.reported[hostID] = addr
	e, ok := r.clients[hostID]
	if (seen && last != addr) || (ok && e.addr != addr) {
		r.reportConflictSeq[hostID] = seq
	}
	if ok && e.addr != addr {
		log.Warn().Str("host_id", hostID).Str("old_addr", e.addr).Str("new_addr", addr).
			Msg("host address changed; dropping the cached client before re-resolving")
		delete(r.clients, hostID)
		r.gens[hostID]++
	} else if ok && !r.unconfirmedConflictLocked(hostID) {
		// Renewing from the caller's read is as safe as from the recheck's
		// own: both are one row read that cannot be ordered against a
		// reclaim on another replica. Only a row version could order them.
		now := time.Now()
		e.verifiedAt, e.nextCheckAt, e.degraded = now, now.Add(r.recheckTTL()), false
		r.clients[hostID] = e
		r.mu.Unlock()
		return
	}
	gen := r.gens[hostID]
	r.mu.Unlock()
	if _, err := r.resolveFrom(ctx, hostID, addr, gen); err != nil {
		log.Warn().Err(err).Str("host_id", hostID).Msg("host client resolution after row verification failed")
	}
}

// renewIfCachedAt renews and returns the cached client at addr, if one is
// cached and no report conflict is unconfirmed. Takes mu.
func (r *Registry) renewIfCachedAt(hostID, addr string) (vmdclient.Client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.clients[hostID]
	if !ok || e.addr != addr || r.unconfirmedConflictLocked(hostID) {
		return nil, false
	}
	now := time.Now()
	e.verifiedAt, e.nextCheckAt, e.degraded = now, now.Add(r.recheckTTL()), false
	r.clients[hostID] = e
	return e.client, true
}

// unconfirmedConflictLocked reports whether the latest report conflict is
// newer than the last row read that published. Caller holds mu.
func (r *Registry) unconfirmedConflictLocked(hostID string) bool {
	return r.reportConflictSeq[hostID] > r.confirmedSeq[hostID]
}

// confirmLocked records that a row read whose report snapshot was seq has
// published: every conflict recorded at or before seq is settled by it.
// Caller holds mu.
func (r *Registry) confirmLocked(hostID string, seq uint64) {
	if seq > r.confirmedSeq[hostID] {
		r.confirmedSeq[hostID] = seq
	}
}

// reportedConflictLocked reports whether the MarkVerified reports that
// arrived since reportSeq was seq leave addr in doubt: the latest disagrees
// with it, or they disagreed among themselves. Caller holds mu.
func (r *Registry) reportedConflictLocked(hostID string, seq uint64, addr string) bool {
	if r.reportSeq[hostID] == seq {
		return false
	}
	return r.reported[hostID] != addr || r.reportConflictSeq[hostID] > seq
}
