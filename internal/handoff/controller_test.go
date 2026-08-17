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
	mu           sync.Mutex
	calls        []string
	failAt       string
	failRollback bool
	drainBusy    bool          // if true, Drain reports not-drained (abort path)
	block        chan struct{} // if non-nil, StartStandby blocks on it
	rolledTo     string
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
func (m *mockActions) QuiesceGRPC(on bool) {
	m.record("QuiesceGRPC(" + map[bool]string{true: "true", false: "false"}[on] + ")")
}
func (m *mockActions) QuiesceResolver(on bool) {
	m.record("QuiesceResolver(" + map[bool]string{true: "true", false: "false"}[on] + ")")
}
func (m *mockActions) Drain(ctx context.Context, g Generation, budget time.Duration) (bool, error) {
	m.record("Drain")
	if m.drainBusy {
		return false, nil
	}
	return true, m.err("Drain")
}
func (m *mockActions) Undrain(ctx context.Context, g Generation) error {
	m.record("Undrain")
	return nil
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
	if m.failRollback {
		return errors.New("rollback failed")
	}
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
	want := []string{"StartStandby", "AwaitReady", "QuiesceGRPC(true)", "Drain", "DrainAndStop", "QuiesceResolver(true)", "Activate", "SetActive:B", "QuiesceResolver(false)", "QuiesceGRPC(false)", "Stabilize"}
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
	// Gateway must be resumed (both holds) after a successful rollback.
	got := m.seq()
	if !contains(got, "QuiesceGRPC(false)") || !contains(got, "QuiesceResolver(false)") {
		t.Fatalf("gateway not resumed after rollback: %v", got)
	}
}

func TestDrainBudgetExceededAbortsNotCuts(t *testing.T) {
	// Old generation can't drain in budget: the deploy must ABORT — resume the
	// old generation (Undrain), never stop it, drop the standby, and postpone.
	m := &mockActions{drainBusy: true}
	c := New(m, Generation{ID: "A", GRPCSocket: "/a-grpc", ResolverSocket: "/a-res"})
	err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B"})
	if !errors.Is(err, ErrDeployPostponed) {
		t.Fatalf("Deploy = %v, want ErrDeployPostponed", err)
	}
	seq := m.seq()
	// The old generation must be resumed (Undrain) and never stopped.
	if !contains(seq, "Undrain") {
		t.Fatalf("must Undrain the old generation on abort: %v", seq)
	}
	// Exactly the standby (next) is stopped — never the old writer. The mock
	// records "DrainAndStop" for either; assert the old generation stays current.
	if c.Current().ID != "A" {
		t.Fatalf("old generation must remain current after abort, got %s", c.Current().ID)
	}
	// Gateway must be resumed.
	if !contains(seq, "QuiesceGRPC(false)") {
		t.Fatalf("gateway not resumed after abort: %v", seq)
	}
	// Never activated the new generation.
	if contains(seq, "Activate") {
		t.Fatalf("must not activate on a drain abort: %v", seq)
	}
}

func TestRollbackFailureStaysFailClosed(t *testing.T) {
	// Activate fails AND restoring the previous generation fails: the controller
	// must NOT release traffic (no Quiesce(false)) — it holds fail-closed.
	m := &mockActions{failAt: "Activate", failRollback: true}
	c := New(m, Generation{ID: "A"})
	if err := c.Deploy(context.Background(), Generation{ID: "A"}, Generation{ID: "B"}); err == nil {
		t.Fatal("expected error when activate and rollback both fail")
	}
	if contains(m.seq(), "QuiesceGRPC(false)") || contains(m.seq(), "QuiesceResolver(false)") {
		t.Fatalf("must stay fail-closed (no resume) when rollback fails: %v", m.seq())
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
