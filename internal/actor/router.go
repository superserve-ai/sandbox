package actor

import (
	"context"
	"sync"
)

// Waker brings an Actor's compute live and returns the Handler that processes
// its events (one harness turn per event). This is the seam to the rest of the
// platform: in production it drives vmd tiered restore (cold → wake on the home
// host, mount /state, replay) and wires the harness's inbox/outbox; in tests it
// is mocked. Keeping it an interface is what lets the router's orchestration be
// unit-tested without a running VM.
type Waker interface {
	Wake(ctx context.Context, a Actor, lease *Lease) (Handler, error)
}

// WakerFunc adapts a function to Waker.
type WakerFunc func(ctx context.Context, a Actor, lease *Lease) (Handler, error)

// Wake calls f.
func (f WakerFunc) Wake(ctx context.Context, a Actor, lease *Lease) (Handler, error) {
	return f(ctx, a, lease)
}

// Router is the wake-on-reference entry point: it turns "deliver this event to
// Actor <name>" into resolve-identity → acquire the single-writer lease → wake
// the compute if cold → deliver to the Actor's serial inbox. It maintains one
// live instance per Actor on this host; concurrent routes to the same Actor
// share that instance (and thus the lease and the serial inbox).
type Router struct {
	reg        *Registry
	waker      Waker
	holder     string // this host/instance id — the lease holder
	inboxDepth int

	mu   sync.Mutex
	live map[string]*liveActor
}

type liveActor struct {
	inbox  *Inbox
	lease  *Lease
	cancel context.CancelFunc
}

// NewRouter builds a Router. holder identifies this host/instance for the lease;
// inboxDepth bounds each Actor's mailbox.
func NewRouter(reg *Registry, waker Waker, holder string, inboxDepth int) *Router {
	return &Router{reg: reg, waker: waker, holder: holder, inboxDepth: inboxDepth, live: map[string]*liveActor{}}
}

// Route delivers ev to the named Actor, creating it on first reference and
// waking its compute if cold. defaults supplies the template/state binding used
// only when the Actor is created. Returns ErrLeaseHeld if another live instance
// (another host) owns the Actor — the caller should forward to that host.
func (r *Router) Route(ctx context.Context, teamID, name string, defaults Actor, ev Event) error {
	a, _, err := r.reg.GetActor(teamID, name, defaults)
	if err != nil {
		return err
	}
	la, err := r.ensureLive(ctx, a)
	if err != nil {
		return err
	}
	return la.inbox.Send(ctx, ev)
}

// ensureLive returns the live instance for a, establishing it (lease + wake +
// inbox consumer) on first reference. Holds the router lock across the wake so
// two concurrent first-events don't double-wake the same Actor.
func (r *Router) ensureLive(ctx context.Context, a Actor) (*liveActor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if la, ok := r.live[a.ID]; ok {
		return la, nil
	}
	// Single-writer: take the lease before waking. If another host holds it,
	// surface ErrLeaseHeld so the caller forwards there.
	lease, err := r.reg.Acquire(a.ID, r.holder, 0)
	if err != nil {
		return nil, err
	}
	h, err := r.waker.Wake(ctx, a, lease)
	if err != nil {
		_ = lease.Release()
		return nil, err
	}
	inbox := NewInbox(r.inboxDepth)
	runCtx, cancel := context.WithCancel(context.Background())
	la := &liveActor{inbox: inbox, lease: lease, cancel: cancel}
	go inbox.Run(runCtx, h, nil)
	_ = r.reg.SetTier(a.ID, TierLive, r.holder)
	r.live[a.ID] = la
	return la, nil
}

// Hibernate stops the live instance for actorID: it closes the inbox (draining
// queued events), stops the consumer, releases the lease for a clean cross-host
// handoff, and records the tier. After this the next Route re-wakes the Actor.
// tier is the depth to record (TierPaused1/2/3). No-op if not live here.
func (r *Router) Hibernate(actorID string, tier Tier) {
	r.mu.Lock()
	la, ok := r.live[actorID]
	if ok {
		delete(r.live, actorID)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	la.inbox.Close()
	la.cancel()
	_ = r.reg.SetTier(actorID, tier, r.holder)
	_ = la.lease.Release()
}

// IsLive reports whether actorID has a live instance on this host.
func (r *Router) IsLive(actorID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.live[actorID]
	return ok
}

// Shutdown hibernates all live Actors (e.g. on host drain), releasing leases so
// they can wake elsewhere.
func (r *Router) Shutdown() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.live))
	for id := range r.live {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.Hibernate(id, TierCold)
	}
}
