package handoff

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockActions records the call sequence and can inject a failure at a named step
// or block StartStandby to exercise the single-deploy lock.
type mockActions struct {
	mu       sync.Mutex
	calls    []string
	failAt   string
	block    chan struct{} // if non-nil, StartStandby blocks on it
	rolledTo string
}

func (m *mockActions) record(s string) {
	m.mu.Lock()
	m.calls = append(m.calls, s)
	m.mu.Unlock()
}
func (m *mockActions) seq() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}
func (m *mockActions) err(step string) error {
	if m.failAt == step {
		return errors.New(step + " failed")
	}
	return nil
}

func (m *mockActions) StartStandby(ctx context.Context, n Generation) error {
	m.record("StartStandby")
	if m.block != nil {
		<-m.block
	}
	return m.err("StartStandby")
}
func (m *mockActions) AwaitReady(ctx context.Context, n Generation) error {
	m.record("AwaitReady")
	return m.err("AwaitReady")
}
func (m *mockActions) Quiesce(on bool) {
	if on {
		m.record("Quiesce(true)")
	} else {
		m.record("Quiesce(false)")
	}
}
func (m *mockActions) DrainAndStop(ctx context.Context, p Generation) error {
	m.record("DrainAndStop")
	return m.err("DrainAndStop")
}
func (m *mockActions) Activate(ctx context.Context, n Generation) error {
	m.record("Activate")
	return m.err("Activate")
}
func (m *mockActions) SetActive(g Generation) { m.record("SetActive:" + g.ID) }
func (m *mockActions) Stabilize(ctx context.Context, g Generation) error {
	m.record("Stabilize")
	return m.err("Stabilize")
}
func (m *mockActions) Rollback(ctx context.Context, p Generation) error {
	m.record("Rollback")
	m.rolledTo = p.ID
	return nil
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDeployHappyPath(t *testing.T) {
	m := &mockActions{}
	c := New(m, Generation{ID: "A", GRPCSocket: "/tmp/a.sock"})
	if err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B", GRPCSocket: "/tmp/b.sock"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	want := []string{"StartStandby", "AwaitReady", "Quiesce(true)", "DrainAndStop", "Activate", "SetActive:B", "Quiesce(false)", "Stabilize"}
	if !eq(m.seq(), want) {
		t.Fatalf("sequence = %v, want %v", m.seq(), want)
	}
	if c.Current().ID != "B" {
		t.Fatalf("current = %s, want B", c.Current().ID)
	}
}

func TestDeployIdempotentWhenAlreadyLive(t *testing.T) {
	m := &mockActions{}
	c := New(m, Generation{ID: "B"})
	if err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if len(m.seq()) != 0 {
		t.Fatalf("idempotent deploy should act nothing, got %v", m.seq())
	}
}

func TestDeployCASMismatch(t *testing.T) {
	m := &mockActions{}
	c := New(m, Generation{ID: "A"})
	if err := c.Deploy(context.Background(), Generation{ID: "X"}, Generation{ID: "B"}); err != ErrCASMismatch {
		t.Fatalf("Deploy = %v, want ErrCASMismatch", err)
	}
	if len(m.seq()) != 0 {
		t.Fatalf("CAS mismatch should act nothing, got %v", m.seq())
	}
}

func TestActivateFailureRollsBack(t *testing.T) {
	m := &mockActions{failAt: "Activate"}
	c := New(m, Generation{ID: "A"})
	err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B"})
	if err == nil {
		t.Fatal("expected activate failure")
	}
	if m.rolledTo != "A" {
		t.Fatalf("rolled back to %q, want A", m.rolledTo)
	}
	if c.Current().ID != "A" {
		t.Fatalf("current = %s, want A after rollback", c.Current().ID)
	}
	// Gateway must be resumed even on the failure path.
	got := m.seq()
	if got[len(got)-1] != "Quiesce(false)" && !contains(got, "Quiesce(false)") {
		t.Fatalf("gateway not resumed after rollback: %v", got)
	}
}

func TestSingleDeployLock(t *testing.T) {
	m := &mockActions{block: make(chan struct{})}
	c := New(m, Generation{ID: "A"})

	started := make(chan struct{})
	go func() {
		close(started)
		c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B"})
	}()
	<-started
	// Wait until the first deploy is inside run() (StartStandby recorded).
	for i := 0; i < 100; i++ {
		if contains(m.seq(), "StartStandby") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "C"}); err != ErrDeployInProgress {
		t.Fatalf("concurrent Deploy = %v, want ErrDeployInProgress", err)
	}
	close(m.block)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
