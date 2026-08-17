// Package gateway is the stable front process that owns vmd's public ports
// (the control-plane gRPC port and the loopback resolver) and routes them to
// whichever vmd generation currently holds the host writer role, over that
// generation's private unix socket.
//
// The gateway is deliberately dumb: it forwards bytes and exposes a small
// control surface (set the active upstream, quiesce/resume). All handoff
// orchestration lives outside it, so the gateway itself is stable and almost
// never redeployed — it is the one component that must not blue-green.
package gateway

import "sync"

// Upstream identifies the vmd generation the gateway currently routes to.
type Upstream struct {
	// Generation is an opaque id for the vmd generation (for logging/metrics).
	Generation string
	// Socket is the generation's private unix socket path. Empty means no
	// active upstream yet (startup, or between generations).
	Socket string
}

// Router holds the gateway's routing state: the active upstream and whether new
// traffic is being quiesced during a cutover. It is safe for concurrent use.
type Router struct {
	mu        sync.RWMutex
	active    Upstream
	quiescing bool
	// resumed is closed when quiescing clears; a fresh (open) channel is
	// installed when quiescing begins. Waiters grab the current channel and
	// select on it to block for the duration of a cutover.
	resumed chan struct{}
}

// NewRouter returns a Router that starts un-quiesced with no upstream.
func NewRouter() *Router {
	ch := make(chan struct{})
	close(ch)
	return &Router{resumed: ch}
}

// SetActive atomically points the gateway at a new upstream generation. Callers
// (the handoff controller) set this only for a generation that already holds
// the writer lease.
func (r *Router) SetActive(u Upstream) {
	r.mu.Lock()
	r.active = u
	r.mu.Unlock()
}

// Quiesce turns the admission hold on or off. While quiescing, gRPC calls are
// refused with a retryable status and resolver requests are held (see the
// serving paths). Idempotent.
func (r *Router) Quiesce(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case on && !r.quiescing:
		r.quiescing = true
		r.resumed = make(chan struct{})
	case !on && r.quiescing:
		r.quiescing = false
		close(r.resumed)
	}
}

// Active returns the current upstream and whether the gateway is quiescing.
func (r *Router) Active() (Upstream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active, r.quiescing
}

// resumedChan returns the channel that closes when the current quiesce clears.
func (r *Router) resumedChan() chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resumed
}
