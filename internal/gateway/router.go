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

// Upstream identifies the vmd generation the gateway currently routes to. The
// gateway fronts two ports, so a generation exposes two private sockets: one
// for control-plane gRPC and one for the loopback resolver's HTTP.
type Upstream struct {
	// Generation is an opaque id for the vmd generation (for logging/metrics).
	Generation string
	// GRPCSocket is the generation's private control-plane gRPC socket. Empty
	// means no active upstream yet (startup, or between generations).
	GRPCSocket string
	// ResolverSocket is the generation's private resolver HTTP socket.
	ResolverSocket string
}

// Router holds the gateway's routing state: the active upstream and two
// independent admission holds. The gRPC hold covers the whole cutover (single
// writer; the control plane retries Unavailable). The resolver hold is separate
// and much shorter — the resolver is read-only, so the previous generation
// keeps answering it while it drains; only the brief activation window needs a
// hold, keeping resolver requests under the caller's short timeout.
type Router struct {
	mu           sync.RWMutex
	active       Upstream
	grpcHold     bool
	resolverHold bool
	// resolverResumed is closed when the resolver hold clears; a fresh channel
	// is installed when it begins. Resolver waiters select on it.
	resolverResumed chan struct{}
}

// NewRouter returns a Router that starts un-quiesced with no upstream.
func NewRouter() *Router {
	ch := make(chan struct{})
	close(ch)
	return &Router{resolverResumed: ch}
}

// SetActive atomically points the gateway at a new upstream generation. Callers
// (the handoff controller) set this only for a generation that already holds
// the writer lease.
func (r *Router) SetActive(u Upstream) {
	r.mu.Lock()
	r.active = u
	r.mu.Unlock()
}

// QuiesceGRPC turns the control-plane admission hold on or off. While held, gRPC
// calls are refused with a retryable status. Idempotent.
func (r *Router) QuiesceGRPC(on bool) {
	r.mu.Lock()
	r.grpcHold = on
	r.mu.Unlock()
}

// QuiesceResolver turns the resolver admission hold on or off. While held,
// resolver requests wait (bounded) for resume rather than 503-ing. Idempotent.
func (r *Router) QuiesceResolver(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case on && !r.resolverHold:
		r.resolverHold = true
		r.resolverResumed = make(chan struct{})
	case !on && r.resolverHold:
		r.resolverHold = false
		close(r.resolverResumed)
	}
}

// Active returns the current upstream and whether gRPC is being held.
func (r *Router) Active() (Upstream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active, r.grpcHold
}

// resolverState returns the current upstream, whether the resolver is held, and
// the channel that closes on resume.
func (r *Router) resolverState() (Upstream, bool, chan struct{}) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active, r.resolverHold, r.resolverResumed
}
