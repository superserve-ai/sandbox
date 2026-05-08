package secretsproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"

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
// O(1). Optionally persisted to a tmpfs file so a proxy restart
// recovers state without re-bootstrapping every sandbox.
type State struct {
	mu          sync.RWMutex
	bySandbox   map[string]*sandboxState
	bySource    map[string]*sandboxState
	persistPath string // empty = in-memory only
}

func NewState() *State {
	return &State{
		bySandbox: make(map[string]*sandboxState),
		bySource:  make(map[string]*sandboxState),
	}
}

// SetPersistPath enables persistence after construction.
func (s *State) SetPersistPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistPath = path
}

// NewStateWithFile creates a State that persists to path. Missing file
// → cold start. Corrupt file → returns the parse error.
func NewStateWithFile(path string) (*State, error) {
	s := NewState()
	s.persistPath = path
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// persistedSandbox is the JSON-encodable shape on disk.
type persistedSandbox struct {
	SandboxID string                       `json:"sandbox_id"`
	TeamID    string                       `json:"team_id"`
	SourceIP  string                       `json:"source_ip"`
	Bindings  map[string]api.SecretBinding `json:"bindings"`
	Egress    api.EgressRules              `json:"egress"`
}

type persistedFile struct {
	Version   int                `json:"version"`
	Sandboxes []persistedSandbox `json:"sandboxes"`
}

const stateFileVersion = 1

// load reads the state file into memory. Caller has not yet exposed the
// state to writers, so no lock is taken.
func (s *State) load() error {
	data, err := os.ReadFile(s.persistPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var pf persistedFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if pf.Version != stateFileVersion {
		return fmt.Errorf("state file version %d not supported", pf.Version)
	}
	for _, p := range pf.Sandboxes {
		st := &sandboxState{
			SandboxID:   p.SandboxID,
			TeamID:      p.TeamID,
			SourceIP:    p.SourceIP,
			secretsByID: p.Bindings,
			egress:      p.Egress,
		}
		if st.secretsByID == nil {
			st.secretsByID = map[string]api.SecretBinding{}
		}
		s.bySandbox[p.SandboxID] = st
		s.bySource[p.SourceIP] = st
	}
	log.Info().Int("count", len(pf.Sandboxes)).Str("path", s.persistPath).
		Msg("restored state from file")
	return nil
}

// persist writes the current bySandbox map to disk via temp-file +
// atomic rename. Caller must hold s.mu (write lock). Errors are logged
// but never fatal — the in-memory map remains the source of truth.
func (s *State) persist() {
	if s.persistPath == "" {
		return
	}
	pf := persistedFile{
		Version:   stateFileVersion,
		Sandboxes: make([]persistedSandbox, 0, len(s.bySandbox)),
	}
	for _, st := range s.bySandbox {
		pf.Sandboxes = append(pf.Sandboxes, persistedSandbox{
			SandboxID: st.SandboxID,
			TeamID:    st.TeamID,
			SourceIP:  st.SourceIP,
			Bindings:  st.secretsByID,
			Egress:    st.egress,
		})
	}
	data, err := json.Marshal(&pf)
	if err != nil {
		log.Error().Err(err).Msg("persist: marshal")
		return
	}
	dir := filepath.Dir(s.persistPath)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		log.Error().Err(err).Msg("persist: create temp")
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Error().Err(err).Msg("persist: write")
		return
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Error().Err(err).Msg("persist: chmod")
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		log.Error().Err(err).Msg("persist: close")
		return
	}
	if err := os.Rename(tmpName, s.persistPath); err != nil {
		os.Remove(tmpName)
		log.Error().Err(err).Msg("persist: rename")
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
	s.persist()
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
	s.persist()
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
	s.persist()
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
	s.persist()
	return true
}

// PropagateSecret updates the real value for every sandbox that holds a
// binding for secretID. realValue == "" removes the binding (revoke).
//
// Builds a new map per affected sandbox rather than mutating in place so
// readers holding a reference from LookupBySourceIP can finish without
// racing on the underlying map.
func (s *State) PropagateSecret(secretID, realValue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	touched := false
	for _, st := range s.bySandbox {
		if _, ok := st.secretsByID[secretID]; !ok {
			continue
		}
		next := make(map[string]api.SecretBinding, len(st.secretsByID))
		for k, v := range st.secretsByID {
			if k == secretID {
				if realValue == "" {
					continue // revoke: drop the binding
				}
				v.RealValue = realValue
			}
			next[k] = v
		}
		st.secretsByID = next
		touched = true
	}
	if touched {
		s.persist()
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
