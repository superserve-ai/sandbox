package secretsproxy

import (
	"sync"

	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

// sandboxState is the in-memory record for one live sandbox.
type sandboxState struct {
	SandboxID string
	TeamID    string
	SourceIP  string
	// secretsByID maps secret_id -> binding for fast lookup once a JWT is
	// validated. The provider field is preserved so the audit log can
	// record it without an extra lookup.
	secretsByID map[string]api.SecretBinding
	egress      api.EgressRules
}

// State is the proxy's authoritative in-memory view of which sandboxes
// exist on this host and what credentials they're allowed to swap.
// Populated by vmd over the control socket; never persisted.
type State struct {
	mu sync.RWMutex
	// Indexed both ways so the request hot path (source IP -> sandbox)
	// is O(1) and the control path (sandbox_id -> sandbox) is too.
	bySandbox map[string]*sandboxState
	bySource  map[string]*sandboxState
}

func NewState() *State {
	return &State{
		bySandbox: make(map[string]*sandboxState),
		bySource:  make(map[string]*sandboxState),
	}
}

// Register installs or replaces a sandbox's bindings + egress rules.
// Idempotent: re-registering the same sandbox overwrites the previous
// state, which is what we want when vmd is recovering from a proxy
// restart.
func (s *State) Register(req api.RegisterRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If this sandbox already exists with a different SourceIP, clear
	// the old entry from bySource before inserting the new one.
	if prev, ok := s.bySandbox[req.SandboxID]; ok && prev.SourceIP != req.SourceIP {
		delete(s.bySource, prev.SourceIP)
	}

	st := &sandboxState{
		SandboxID:   req.SandboxID,
		TeamID:      req.TeamID,
		SourceIP:    req.SourceIP,
		secretsByID: make(map[string]api.SecretBinding, len(req.Bindings)),
		egress:      req.Egress,
	}
	for _, b := range req.Bindings {
		st.secretsByID[b.SecretID] = b
	}
	s.bySandbox[req.SandboxID] = st
	s.bySource[req.SourceIP] = st
}

// Unregister drops both indexes for a sandbox. Idempotent.
func (s *State) Unregister(sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.bySandbox[sandboxID]
	if !ok {
		return
	}
	delete(s.bySandbox, sandboxID)
	delete(s.bySource, st.SourceIP)
}

// UpdateBindings replaces a sandbox's binding set. Returns false if the
// sandbox isn't registered (caller should re-register).
func (s *State) UpdateBindings(sandboxID string, bindings []api.SecretBinding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.bySandbox[sandboxID]
	if !ok {
		return false
	}
	st.secretsByID = make(map[string]api.SecretBinding, len(bindings))
	for _, b := range bindings {
		st.secretsByID[b.SecretID] = b
	}
	return true
}

// UpdateEgress replaces a sandbox's egress rules.
func (s *State) UpdateEgress(sandboxID string, egress api.EgressRules) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.bySandbox[sandboxID]
	if !ok {
		return false
	}
	st.egress = egress
	return true
}

// PropagateSecret updates the real value for every sandbox that holds a
// binding for secretID. realValue == "" removes the binding entirely
// (used on revocation).
func (s *State) PropagateSecret(secretID, realValue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.bySandbox {
		b, ok := st.secretsByID[secretID]
		if !ok {
			continue
		}
		if realValue == "" {
			delete(st.secretsByID, secretID)
			continue
		}
		b.RealValue = realValue
		st.secretsByID[secretID] = b
	}
}

// LookupBySourceIP is the request hot-path lookup. Returns a snapshot of
// the sandbox state suitable for read-only use; the caller does not need
// to hold any locks.
func (s *State) LookupBySourceIP(srcIP string) (Sandbox, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.bySource[srcIP]
	if !ok {
		return Sandbox{}, false
	}
	return Sandbox{
		SandboxID: st.SandboxID,
		TeamID:    st.TeamID,
		Bindings:  st.secretsByID,
		Egress:    st.egress,
	}, true
}

// Sandbox is the read-only snapshot returned by LookupBySourceIP. Maps
// are returned as references but the request handler treats them as
// read-only; State only ever swaps the whole map under the lock.
type Sandbox struct {
	SandboxID string
	TeamID    string
	Bindings  map[string]api.SecretBinding
	Egress    api.EgressRules
}
