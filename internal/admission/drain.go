package admission

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type DrainState struct {
	Revision int64 `json:"revision"`
	Closed   bool  `json:"closed"`
}

// ConfigureDrain starts a newly enrolled gate closed. The state lives beside
// the host state database, outside runtime tmpfs, and survives daemon restarts.
func (g *Gate) ConfigureDrain(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	data, err := os.ReadFile(path)
	state := DrainState{Closed: true}
	if err == nil {
		var encoded struct {
			Revision *int64 `json:"revision"`
			Closed   *bool  `json:"closed"`
		}
		if err = json.Unmarshal(data, &encoded); err != nil {
			return err
		}
		if encoded.Revision == nil || encoded.Closed == nil {
			return fmt.Errorf("incomplete drain state")
		}
		state = DrainState{Revision: *encoded.Revision, Closed: *encoded.Closed}
		if state.Revision < 0 || (state.Revision == 0 && !state.Closed) {
			return fmt.Errorf("invalid drain revision")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	g.drainPath = path
	g.drainState = state
	if g.state == StateDisabled {
		g.state = StateReconstructing
		g.maxSandboxes = 0
	}
	return nil
}

func (g *Gate) DrainStatus() (DrainState, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.drainState, g.drainPath != ""
}

// TransitionDrain shares the admission lock: no new charge can race past an
// acknowledged close. Revisions fence delayed commands from other API replicas.
func (g *Gate) TransitionDrain(revision int64, closed bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.drainPath == "" {
		return fmt.Errorf("durable host drain is not configured")
	}
	if revision <= 0 || revision < g.drainState.Revision {
		return fmt.Errorf("stale drain revision")
	}
	if revision == g.drainState.Revision && closed != g.drainState.Closed {
		return fmt.Errorf("conflicting drain revision")
	}
	next := DrainState{Revision: revision, Closed: closed}
	// A failed persistence attempt must never reopen admission.
	g.drainState = DrainState{Revision: revision, Closed: true}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(g.drainPath), ".drain-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), g.drainPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(g.drainPath))
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	g.drainState = next
	return nil
}
