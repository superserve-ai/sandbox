package actor

import (
	"context"
	"errors"
	"sync"
)

// maxRouteRewakes is a safety backstop on Route's re-wake retries when it loses a
// race with a concurrent demotion (inbox closed between ensureLive and Send). In
// production demotion is idle-triggered and rare, so a route retries 0–1 times;
// the high cap only guards against a pathological demote-storm livelock. ctx
// cancellation bounds it first.
const maxRouteRewakes = 64

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

	// activity, if set, is called with the Actor id on every routed event —
	// wired to TierController.Touch so a present user keeps the Actor promoted
	// and resets its idle clock. nil = no tiering (events still route normally).
	activity func(actorID string)

	mu   sync.Mutex
	live map[string]*liveActor
}

type liveActor struct {
	inbox  *Inbox
	lease  *Lease
	cancel context.CancelFunc

	// consumerDone is closed when the inbox consumer goroutine has fully exited
	// (drained its queue and finished any in-flight turn) — the signal Demote
	// waits on before running the VM-side tier op, so no harness delivery is in
	// flight when the VM is paused.
	consumerDone chan struct{}
	// teardownDone is closed when Demote/Hibernate has fully finished (lease
	// settled, removed from the live map). A concurrent ensureLive that observes
	// demoting waits on this before re-waking, so the Actor never has two live
	// instances or two leases.
	teardownDone chan struct{}
	demoting     bool
}

// NewRouter builds a Router. holder identifies this host/instance for the lease;
// inboxDepth bounds each Actor's mailbox.
func NewRouter(reg *Registry, waker Waker, holder string, inboxDepth int) *Router {
	return &Router{reg: reg, waker: waker, holder: holder, inboxDepth: inboxDepth, live: map[string]*liveActor{}}
}

// OnActivity registers a per-event activity callback (typically
// TierController.Touch) and returns the Router for chaining. Called once per
// routed event with the Actor id, before the event is enqueued.
func (r *Router) OnActivity(fn func(actorID string)) *Router {
	r.activity = fn
	return r
}

// Route delivers ev to the named Actor, creating it on first reference and
// waking its compute if cold. defaults supplies the template/state binding used
// only when the Actor is created. Returns ErrLeaseHeld if another live instance
// (another host) owns the Actor — the caller should forward to that host.
func (r *Router) Route(ctx context.Context, teamID, name string, defaults Actor, ev Event) error {
	a, _, err := r.reg.GetActor(ctx, teamID, name, defaults)
	if err != nil {
		return err
	}
	// Record activity (promote to Live + reset idle) before enqueuing, so a busy
	// Actor is never demoted out from under an in-flight turn.
	if r.activity != nil {
		r.activity(a.ID)
	}
	// Retry on ErrInboxClosed: a demotion can close the inbox between ensureLive
	// returning an instance and our Send. The next ensureLive re-wakes the Actor
	// (at its new tier), so the event is delivered rather than dropped.
	for attempt := 0; attempt < maxRouteRewakes; attempt++ {
		la, err := r.ensureLive(ctx, a)
		if err != nil {
			return err
		}
		err = la.inbox.Send(ctx, ev)
		if errors.Is(err, ErrInboxClosed) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		return err
	}
	return ErrInboxClosed
}

// ensureLive returns the live instance for a, establishing it (lease + wake +
// inbox consumer) on first reference. Holds the router lock across the wake so
// two concurrent first-events don't double-wake the same Actor. If a demotion is
// in progress for this Actor, it waits for that teardown to finish before
// re-waking, so the Actor never has two live instances (or two leases) at once.
func (r *Router) ensureLive(ctx context.Context, a Actor) (*liveActor, error) {
	for {
		r.mu.Lock()
		la, ok := r.live[a.ID]
		if ok && !la.demoting {
			r.mu.Unlock()
			return la, nil
		}
		if ok && la.demoting {
			// Teardown in progress: wait for it to settle the lease and clear the
			// map, then retry (it'll be a cold wake).
			done := la.teardownDone
			r.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		// Cold: take the single-writer lease before waking. Another host holding
		// it surfaces ErrLeaseHeld so the caller forwards there.
		lease, err := r.reg.Acquire(ctx, a.ID, r.holder, 0)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		h, err := r.waker.Wake(ctx, a, lease)
		if err != nil {
			_ = lease.Release(ctx)
			r.mu.Unlock()
			return nil, err
		}
		inbox := NewInbox(r.inboxDepth)
		runCtx, cancel := context.WithCancel(context.Background())
		consumerDone := make(chan struct{})
		la = &liveActor{inbox: inbox, lease: lease, cancel: cancel, consumerDone: consumerDone}
		go func() { defer close(consumerDone); inbox.Run(runCtx, h, nil) }()
		_ = r.reg.SetTier(ctx, a.ID, TierLive, r.holder)
		r.live[a.ID] = la
		r.mu.Unlock()
		return la, nil
	}
}

// Demote tears down the live instance for actorID at the given tier, running the
// VM-side tier op (vmDemote: bare-pause / snapshot / destroy; may be nil) at the
// one moment it is race-free: AFTER the inbox consumer has drained and stopped,
// so no harness delivery is in flight, and BEFORE the lease is settled. After it
// returns the next Route re-wakes the Actor at its new tier (Tier-1 →
// bare-resume, Tier-2/3 → snapshot restore).
//
// Single-writer invariant: the instance is marked `demoting` first, so a
// concurrent ensureLive waits on teardownDone before re-waking — the Actor never
// has two live instances or two leases. The lease is RELEASED for Tier-2/3/cold
// (clean cross-host handoff) but KEPT for Tier-1 (the VM is resident on this
// host, so the Actor stays pinned here and the next wake re-acquires our own
// lease and bare-resumes). No-op if not live here or already tearing down. If
// vmDemote errors the teardown still completes (the instance is gone); the error
// is returned so the TierController leaves its state for the next Tick to retry.
func (r *Router) Demote(ctx context.Context, actorID string, tier Tier, vmDemote func() error) error {
	r.mu.Lock()
	la, ok := r.live[actorID]
	if !ok || la.demoting {
		r.mu.Unlock()
		return nil
	}
	la.demoting = true
	la.teardownDone = make(chan struct{})
	r.mu.Unlock()

	// Quiesce: stop accepting events; the consumer drains its queue and finishes
	// any in-flight turn, then exits. Wait for that so the VM op below cannot race
	// a harness delivery.
	la.inbox.Close()
	<-la.consumerDone
	la.cancel() // consumer already exited; free its context

	// VM-side tier op — now race-free (no delivery in flight, instance still owned).
	var opErr error
	if vmDemote != nil {
		opErr = vmDemote()
	}
	if opErr == nil {
		_ = r.reg.SetTier(ctx, actorID, tier, r.holder)
	}
	// Keep the lease for Tier-1 stickiness; release it for deeper tiers so the
	// Actor can wake on another host.
	if tier != TierPaused1 {
		_ = la.lease.Release(ctx)
	}

	r.mu.Lock()
	delete(r.live, actorID)
	close(la.teardownDone)
	r.mu.Unlock()
	return opErr
}

// Hibernate is the vmDemote-less Demote: it tears down the live instance and
// records the tier without a VM-side op (used by Shutdown and tests). No-op if
// not live here.
func (r *Router) Hibernate(actorID string, tier Tier) {
	_ = r.Demote(context.Background(), actorID, tier, nil)
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
