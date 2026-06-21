package vmdwaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/actor"
)

type mockBooter struct {
	mu         sync.Mutex
	restoreIDs []string
	destroyIDs []string
	restoreErr error
}

func (m *mockBooter) RestoreSnapshot(_ context.Context, id, _, _, _, _, _, _ string, _ map[string]string) (string, uint32, uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoreErr != nil {
		return "", 0, 0, m.restoreErr
	}
	m.restoreIDs = append(m.restoreIDs, id)
	return "10.0.0.5", 1, 1024, nil
}

func (m *mockBooter) DestroyInstance(_ context.Context, id string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyIDs = append(m.destroyIDs, id)
	return nil
}

type mockDeliverer struct {
	mu     sync.Mutex
	events []string // "<sandboxID>:<eventID>"
}

func (m *mockDeliverer) Deliver(_ context.Context, sandboxID string, ev actor.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, sandboxID+":"+ev.ID)
	return nil
}

func target(actor.Actor) (Target, error) {
	return Target{SnapshotPath: "/snap/s", MemPath: "/snap/m", TeamID: "t"}, nil
}

func TestWakerRestoresAndDelivers(t *testing.T) {
	boot := &mockBooter{}
	del := &mockDeliverer{}
	w := New(boot, del, target)
	ctx := context.Background()

	a := actor.Actor{ID: "act-7", Name: "agent"}
	h, err := w.Wake(ctx, a, nil)
	if err != nil {
		t.Fatalf("wake: %v", err)
	}
	if len(boot.restoreIDs) != 1 || boot.restoreIDs[0] != "act-7" {
		t.Fatalf("should restore the actor's sandbox once: %v", boot.restoreIDs)
	}
	if w.SandboxID("act-7") != "act-7" {
		t.Errorf("sandbox should be live for the actor")
	}

	// The handler delivers each event into the in-guest harness.
	if err := h(ctx, actor.Event{ID: "e1"}); err != nil {
		t.Fatal(err)
	}
	if err := h(ctx, actor.Event{ID: "e2"}); err != nil {
		t.Fatal(err)
	}
	if len(del.events) != 2 || del.events[0] != "act-7:e1" || del.events[1] != "act-7:e2" {
		t.Fatalf("events should be delivered to the actor's sandbox in order: %v", del.events)
	}
}

func TestWakerRestoreErrorPropagates(t *testing.T) {
	boot := &mockBooter{restoreErr: errors.New("snapshot missing")}
	w := New(boot, &mockDeliverer{}, target)
	if _, err := w.Wake(context.Background(), actor.Actor{ID: "a", Name: "x"}, nil); err == nil {
		t.Fatal("restore failure should propagate from Wake")
	}
}

func TestWakerResolveErrorPropagates(t *testing.T) {
	w := New(&mockBooter{}, &mockDeliverer{}, func(actor.Actor) (Target, error) {
		return Target{}, errors.New("no template bound")
	})
	if _, err := w.Wake(context.Background(), actor.Actor{ID: "a", Name: "x"}, nil); err == nil {
		t.Fatal("resolve failure should propagate from Wake")
	}
}

func TestWakerDestroy(t *testing.T) {
	boot := &mockBooter{}
	w := New(boot, &mockDeliverer{}, target)
	ctx := context.Background()
	_, _ = w.Wake(ctx, actor.Actor{ID: "act-9", Name: "x"}, nil)

	if err := w.Destroy(ctx, "act-9"); err != nil {
		t.Fatal(err)
	}
	if len(boot.destroyIDs) != 1 || boot.destroyIDs[0] != "act-9" {
		t.Fatalf("destroy should tear down the actor's sandbox: %v", boot.destroyIDs)
	}
	if w.SandboxID("act-9") != "" {
		t.Error("sandbox should no longer be live after destroy")
	}
	// Idempotent: destroying again is a no-op.
	if err := w.Destroy(ctx, "act-9"); err != nil {
		t.Fatalf("second destroy should be a no-op: %v", err)
	}
}

// TestWakerDrivesRealRuntime: the production Waker plugs into the UNMODIFIED
// Router + Registry + Inbox and drives the wake→deliver path, just like the
// real control plane will (here with mock vmd + deliverer).
func TestWakerDrivesRealRuntime(t *testing.T) {
	boot := &mockBooter{}
	del := &mockDeliverer{}
	w := New(boot, del, target)

	reg := actor.NewRegistry(actor.NewMemStore(), nil)
	router := actor.NewRouter(reg, w, "host-A", 8)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := router.Route(ctx, "team", "support/ticket-1", actor.Actor{Template: "base"}, actor.Event{ID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	// Drain: the serial inbox processes all three through the real handler.
	waitUntil(t, func() bool { del.mu.Lock(); defer del.mu.Unlock(); return len(del.events) == 3 })

	boot.mu.Lock()
	restores := len(boot.restoreIDs)
	boot.mu.Unlock()
	if restores != 1 {
		t.Fatalf("one wake (restore) for 3 events to one actor, got %d", restores)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met")
}
