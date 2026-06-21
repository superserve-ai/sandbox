package actor

import "time"

// DefaultLeaseTTL is the lease lifetime. A holder must renew within this window
// or lose the lease (and its fencing token). Short enough that a dead holder's
// Actor becomes reattachable quickly; long enough that renewal traffic is light.
const DefaultLeaseTTL = 15 * time.Second

// Registry is the high-level Actor API over a Store. It provides
// wake-on-reference resolution and the single-writer lease lifecycle. A Clock
// is injected so tests can drive time deterministically (lease expiry, fencing).
type Registry struct {
	store Store
	now   func() time.Time
}

// NewRegistry builds a Registry over the given Store. clock may be nil, in which
// case time.Now is used.
func NewRegistry(store Store, clock func() time.Time) *Registry {
	if clock == nil {
		clock = time.Now
	}
	return &Registry{store: store, now: clock}
}

// GetActor resolves (team, name) to an Actor, creating it on first reference.
// This is the "getActor(name) just works" primitive: callers never explicitly
// create an Actor — referencing it brings it into being. defaults supplies the
// template/state binding used only when the Actor is created.
func (r *Registry) GetActor(teamID, name string, defaults Actor) (Actor, bool, error) {
	return r.store.GetOrCreate(teamID, name, defaults, r.now())
}

// Lease is a held single-writer lease. Fence() returns the token to stamp on
// every /state write; the storage layer rejects stale tokens (ErrFenced).
type Lease struct {
	reg     *Registry
	actorID string
	holder  string
	token   int64
	expires time.Time
}

// Token returns the fencing token to present on writes.
func (l *Lease) Token() int64 { return l.token }

// ActorID returns the leased Actor's id.
func (l *Lease) ActorID() string { return l.actorID }

// Acquire attempts to take the single-writer lease for holder. On success it
// returns a Lease; if another live instance holds it, it returns ErrLeaseHeld.
func (r *Registry) Acquire(actorID, holder string, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	out, err := r.store.TryAcquireLease(actorID, holder, r.now(), ttl)
	if err != nil {
		return nil, err
	}
	if !out.Granted {
		return nil, ErrLeaseHeld
	}
	return &Lease{reg: r, actorID: actorID, holder: holder, token: out.Token, expires: out.Expires}, nil
}

// Renew extends the lease. It returns ErrFenced if the lease was lost (expired
// and stolen) in the meantime — the caller must then stop writing immediately.
func (l *Lease) Renew(ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	out, err := l.reg.store.RenewLease(l.actorID, l.holder, l.token, l.reg.now(), ttl)
	if err != nil {
		return err
	}
	l.expires = out.Expires
	return nil
}

// Release relinquishes the lease so another instance can wake the Actor on a
// different host without waiting for TTL expiry. Idempotent.
func (l *Lease) Release() error {
	return l.reg.store.ReleaseLease(l.actorID, l.holder, l.token)
}

// CheckFence verifies this lease's token is still current — the gate to call
// before a durable /state write. Returns ErrFenced if the lease was lost.
func (l *Lease) CheckFence() error {
	return l.reg.store.CheckFence(l.actorID, l.token, l.reg.now())
}

// SetTier records the Actor's hibernation tier + host (host stickiness).
func (r *Registry) SetTier(actorID string, tier Tier, host string) error {
	return r.store.SetTier(actorID, tier, host, r.now())
}
