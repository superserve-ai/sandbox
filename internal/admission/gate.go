package admission

import (
	"fmt"
	"sync"
)

// State is the gate's lifecycle. The states exist because "is this
// host full?" is unanswerable until the daemon knows what it is already
// carrying, and a daemon that answers it anyway admits against an empty
// count — which is not a limit at all.
type State int

const (
	// StateDisabled is the default and the only state a daemon reaches
	// without the operator opting in. Every request is admitted; the
	// ledger is not consulted and not maintained.
	StateDisabled State = iota
	// StateReconstructing is where an enabled gate starts. The socket
	// is inherited across a restart and can deliver queued requests before
	// reattach finishes, so this state must be the initial one rather than
	// something entered later — there is no instant at which an enabled
	// gate is both open and ignorant.
	StateReconstructing
	// StateOpen admits within the operator's limits.
	StateOpen
	// StateDraining refuses new sandboxes while letting existing ones
	// go on being accounted, so a drain's own pending count means
	// something.
	StateDraining
)

func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateReconstructing:
		return "reconstructing"
	case StateOpen:
		return "open"
	case StateDraining:
		return "draining"
	}
	return "unknown"
}

// Intent is why a boot is happening, as the caller declared it.
// Mirrors the wire enum; the daemon never infers it. A sandbox that already
// exists can arrive through the create RPC (the caller's stateless fallback,
// taken precisely when this daemon has no record of it), so neither the RPC
// nor "do I remember this id" separates the two.
type Intent int

const (
	IntentUnspecified Intent = iota
	IntentCreate
	IntentResume
)

// ErrIntentRequired refuses a boot whose caller predates the
// intent field, rather than guessing. Guessing "create" double-charges a
// resuming sandbox; guessing "resume" lets a real create past the limit.
// Both are silent, so an enabled gate makes the skew loud instead.
var ErrIntentRequired = fmt.Errorf("admission intent required: caller must declare create or resume")

// ErrHostAtCapacity rejects a create the host has no room for. Distinct
// from every other failure on purpose: it is the one the control plane may
// answer by placing the sandbox somewhere else, and a generic error would
// either strand a placeable sandbox or invite retries of a genuine fault.
var ErrHostAtCapacity = fmt.Errorf("host at configured sandbox capacity")

// ErrNotReady rejects work that arrives before the gate knows what
// the host is carrying, or after a drain has closed it.
var ErrNotReady = fmt.Errorf("host not accepting new sandboxes")

// admissionToken is one host-owned charge. Tokens are keyed by id, which is
// what makes admission idempotent: a retried create finds its own token and
// re-admits rather than charging twice.
type admissionToken struct {
	// build distinguishes a template build from a sandbox. Both hold a
	// sandbox token — build pressure is published as provisioning
	// sandboxes, and the ranker counts provisioning against the same
	// limit, so a gate that ignored builds would enforce a different
	// limit than the one ranking believes in.
	build bool
	// gen is the generation this token was charged in. A rebuild replaces
	// only tokens that existed when its snapshot of the world was taken;
	// anything charged later is newer than the snapshot and survives, or
	// a create admitted mid-rebuild would silently lose its charge.
	gen uint64
	// owner identifies WHICH holder charged this token, for ids that can
	// be re-registered while a previous holder is still shutting down.
	// Releasing by id alone would let the outgoing holder drop the
	// incoming one's charge; a release must match the owner that took it.
	// Nil for sandboxes, whose id is held by one lifecycle at a time.
	owner any
}

// Gate enforces the operator's concurrent-sandbox limit locally.
//
// Counting is len(map): the ledger is keyed by sandbox id, so the count is
// O(1) and exact at once, with no counter to drift from the thing it
// counts. That is the property that makes this safe to hold a mutex for —
// admission is a map lookup, a compare, and an insert, and the lock is
// never held across Firecracker, filesystem, database, network, logging or
// metric work.
//
// The ledger is authoritative while the gate is open. Capacity pressure is
// an eventually consistent sample taken off the hot path and must never
// lower these counts; it audits them, and an audit that finds the ledger
// undercounting closes the gate for reconstruction rather than quietly
// correcting it.
type Gate struct {
	mu     sync.Mutex
	state  State
	tokens map[string]admissionToken
	// maxSandboxes is the operator's limit. Zero means unlimited, matching
	// how the pressure publisher already reads VMD_MAX_SANDBOXES.
	maxSandboxes int
	// gen increments on every charge. A rebuild reads it before consulting
	// its slower source of truth and passes it back, which is what lets
	// the rebuild tell "this token predates my snapshot, replace it" from
	// "this was charged while I was reading, keep it".
	gen uint64
}

// NewGate builds a gate. An enabled gate starts reconstructing and
// admits nothing until Opened; a disabled one is inert and stays that way.
func NewGate(enabled bool, maxSandboxes int) *Gate {
	state := StateDisabled
	if enabled {
		state = StateReconstructing
	}
	return &Gate{
		state:        state,
		tokens:       make(map[string]admissionToken),
		maxSandboxes: maxSandboxes,
	}
}

// Enabled reports whether this gate enforces anything.
func (g *Gate) Enabled() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state != StateDisabled
}

// State reports the current lifecycle state, for diagnostics and tests.
func (g *Gate) State() State {
	if g == nil {
		return StateDisabled
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// Charged reports how many tokens are held. This is the count admission
// decisions are made against.
func (g *Gate) Charged() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.tokens)
}

// Reconstruct seeds the ledger from what the host is already carrying and
// opens the gate.
//
// Deliberately replaces rather than merges: a partial rebuild that kept
// unknown ids would carry forward exactly the phantom charges reconstruction
// exists to clear. Safe only because callers run it while the gate is closed
// — Open is what publishes the result.
// BeginReconstruct marks the point a rebuild starts reading the world, and
// returns the generation to hand back to Reconstruct.
//
// Rebuilding is not instantaneous — it reads a persistent store — and the
// gate keeps admitting owned work while it runs. Without this marker a
// rebuild would replace the ledger wholesale and discard any token charged
// while it was reading, so a create admitted mid-rebuild would proceed
// uncharged and the host would over-admit by exactly that many.
func (g *Gate) BeginReconstruct() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen
}

// Reconstruct replaces the ledger with what the caller observed, keeping
// any token charged after its snapshot began.
//
// since must come from BeginReconstruct, taken BEFORE the caller read its
// source of truth. Tokens at or below it predate the snapshot and are
// authoritative from the snapshot; tokens above it were charged while the
// caller was reading, are absent from what it saw, and must survive — they
// are in-flight work, not stale residue.
func (g *Gate) Reconstruct(since uint64, sandboxIDs, buildIDs []string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateDisabled {
		return
	}
	tokens := make(map[string]admissionToken, len(sandboxIDs)+len(buildIDs))
	for _, id := range sandboxIDs {
		tokens[id] = admissionToken{gen: g.gen}
	}
	for _, id := range buildIDs {
		tokens[id] = admissionToken{build: true, gen: g.gen}
	}
	// Carry forward everything charged since the snapshot started. Also
	// keeps the newer token when both sides have the id: the live charge
	// knows its owner, the reconstructed one does not.
	for id, tok := range g.tokens {
		if tok.gen > since {
			tokens[id] = tok
		}
	}
	g.tokens = tokens
}

// Open moves a reconstructed gate into service. Separate from Reconstruct so
// the transition is a deliberate act by the readiness path rather than a
// side effect of seeding — and so a caller cannot open a gate it never
// seeded.
func (g *Gate) Open() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateReconstructing || g.state == StateDraining {
		g.state = StateOpen
	}
}

// Close returns an enabled gate to reconstructing. Used by drain and by an
// audit that finds the ledger undercounting: in both cases the safe move is
// to stop admitting until the count can be rebuilt, never to keep serving
// from a ledger known to be wrong.
func (g *Gate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateDisabled {
		g.state = StateReconstructing
	}
}

// Drain closes the gate to new sandboxes. Existing tokens stay charged, so
// the pending count a drain waits on is the daemon's own and not an
// estimate made elsewhere.
func (g *Gate) Drain() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateDisabled {
		g.state = StateDraining
	}
}

// Admit charges id and reports whether the boot may proceed.
//
// Idempotent by id: an id that already holds a token is re-admitted without
// a second charge, so a retried create — or a create racing its own
// retry — cannot consume two slots. Resume is never refused on the operator
// limit; it is bound to this host and has nowhere else to go, and refusing
// it would strand a paused sandbox. Physical ceilings are enforced
// elsewhere, by the resources that actually run out.
func (g *Gate) Admit(id string, intent Intent) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateDisabled {
		return nil
	}
	if intent == IntentUnspecified {
		return ErrIntentRequired
	}
	if _, held := g.tokens[id]; held {
		// Already ours. Re-admitting costs nothing and must not be
		// refused even while draining: the sandbox is already here, and
		// failing its retry would destroy work the drain is trying to
		// let finish.
		return nil
	}
	if g.state != StateOpen {
		if intent == IntentResume && g.state == StateDraining {
			// A drain stops new placement, not the return of sandboxes
			// this host already owns.
			g.gen++
			g.tokens[id] = admissionToken{gen: g.gen}
			return nil
		}
		return ErrNotReady
	}
	if intent == IntentCreate && g.maxSandboxes > 0 && len(g.tokens) >= g.maxSandboxes {
		return ErrHostAtCapacity
	}
	g.gen++
	g.tokens[id] = admissionToken{gen: g.gen}
	return nil
}

// AdmitBuild charges a template build. Builds are always new work, so there
// is no resume equivalent — but they are refused for the same reason
// creates are, because their pressure is published as provisioning
// sandboxes and counted against this same limit.
// owner identifies the holder taking the charge, and must be presented
// again to release it. A build id can be re-registered while the previous
// worker is still winding down, so a release that matched on id alone would
// let the outgoing worker drop the incoming one's charge.
func (g *Gate) AdmitBuild(id string, owner any) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateDisabled {
		return nil
	}
	if existing, held := g.tokens[id]; held {
		// Re-admitting the same id under a NEW owner is a replacement, not
		// a retry: take ownership so the outgoing holder's release cannot
		// match, while the count stays put because the id is unchanged.
		if existing.owner != owner {
			g.gen++
			g.tokens[id] = admissionToken{build: true, gen: g.gen, owner: owner}
		}
		return nil
	}
	if g.state != StateOpen {
		return ErrNotReady
	}
	if g.maxSandboxes > 0 && len(g.tokens) >= g.maxSandboxes {
		return ErrHostAtCapacity
	}
	g.gen++
	g.tokens[id] = admissionToken{build: true, gen: g.gen, owner: owner}
	return nil
}

// Release drops id's token. Idempotent, because the failure paths that call
// it are not mutually exclusive — a create can fail its launch and then be
// torn down again by a reconciler, and the second release must not
// decrement anything a later id has since claimed.
func (g *Gate) Release(id string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.tokens, id)
}

// ReleaseOwned drops id's token only if owner still holds it.
//
// The guard is the point: an id can be re-registered while its previous
// holder is still shutting down, and that outgoing holder will release on
// its way out. Releasing by id alone would free the INCOMING holder's
// charge and let the host over-admit by one for as long as the replacement
// runs. A mismatch means someone else owns the id now, so there is nothing
// here to give back.
func (g *Gate) ReleaseOwned(id string, owner any) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok, held := g.tokens[id]; held && tok.owner == owner {
		delete(g.tokens, id)
	}
}

// Holds reports whether id is charged, for reconciliation and tests.
func (g *Gate) Holds(id string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_, held := g.tokens[id]
	return held
}

// AuditUndercount reports whether an observed sandbox count exceeds what the
// ledger is charging, which means the ledger has lost track of live work.
//
// One-directional on purpose. The observation is an eventually consistent
// sample: it can be taken before a just-admitted sandbox materializes, so
// observing FEWER than the ledger holds is normal and must never lower the
// count. Observing MORE cannot be explained that way — something is running
// that the gate is not charging for — and that is a correctness bug the
// caller answers by closing the gate and reconstructing.
func (g *Gate) AuditUndercount(observedSandboxes int) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateOpen {
		return false
	}
	return observedSandboxes > len(g.tokens)
}
