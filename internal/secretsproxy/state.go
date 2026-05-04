package secretsproxy

import (
	"sync"

	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

type sandboxState struct {
	SandboxID   string
	TeamID      string
	SourceIP    string
	secretsByID map[string]api.SecretBinding
	egress      api.EgressRules
}

// State is the in-memory view of registered sandboxes. Indexed by both
// sandbox_id and source IP so register/update and request lookup are
// O(1). Never persisted.
type State struct {
	mu        sync.RWMutex
	bySandbox map[string]*sandboxState
	bySource  map[string]*sandboxState
}

func NewState() *State {
	return &State{
		bySandbox: make(map[string]*sandboxState),
		bySource:  make(map[string]*sandboxState),
	}
}

// Register installs or replaces a sandbox's state. Idempotent.
func (s *State) Register(req api.RegisterRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reusing a sandbox_id with a new SourceIP — drop the old reverse-map entry.
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
// binding for secretID. realValue == "" removes the binding (revoke).
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

// LookupBySourceIP returns a read-only snapshot for the request handler.
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

// Sandbox is the read-only snapshot returned by LookupBySourceIP. The
// caller must not mutate Bindings; State only ever replaces the whole
// map atomically under the lock.
type Sandbox struct {
	SandboxID string
	TeamID    string
	Bindings  map[string]api.SecretBinding
	Egress    api.EgressRules
}
