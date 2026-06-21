package actor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingWaker counts wakes and returns a handler that records processed
// events, so tests can assert "woken once, processed N".
type recordingWaker struct {
	wakes int64
	mu    sync.Mutex
	seen  map[string][]string // actorID -> event ids, in process order
	done  chan struct{}       // closed-style signal per event via counter
	count int64
}

func newRecordingWaker() *recordingWaker {
	return &recordingWaker{seen: map[string][]string{}}
}

func (w *recordingWaker) Wake(_ context.Context, a Actor, _ *Lease) (Handler, error) {
	atomic.AddInt64(&w.wakes, 1)
	id := a.ID
	return func(_ context.Context, ev Event) error {
		w.mu.Lock()
		w.seen[id] = append(w.seen[id], ev.ID)
		w.mu.Unlock()
		atomic.AddInt64(&w.count, 1)
		return nil
	}, nil
}

func (w *recordingWaker) processed() int64 { return atomic.LoadInt64(&w.count) }
func (w *recordingWaker) wakeCount() int64 { return atomic.LoadInt64(&w.wakes) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// TestRouterActivityHook: the activity callback fires once per routed event,
// carrying the resolved Actor id — this is what wires Route → TierController.Touch
// so a present user keeps the Actor promoted.
func TestRouterActivityHook(t *testing.T) {
	reg := NewRegistry(NewMemStore(), nil)
	w := newRecordingWaker()
	var mu sync.Mutex
	var got []string
	r := NewRouter(reg, w, "host-A", 8).OnActivity(func(id string) {
		mu.Lock()
		got = append(got, id)
		mu.Unlock()
	})
	ctx := context.Background()

	for _, id := range []string{"e0", "e1"} {
		if err := r.Route(ctx, "t", "agent-1", Actor{Template: "base"}, Event{ID: id}); err != nil {
			t.Fatal(err)
		}
	}

	// The hook fires synchronously inside Route, so it has recorded both by now.
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("activity hook should fire once per event, got %d: %v", len(got), got)
	}
	if got[0] == "" || got[0] != got[1] {
		t.Fatalf("activity should carry the (same) actor id for both events: %v", got)
	}
}

func TestRouterWakeOnReference(t *testing.T) {
	store := NewMemStore()
	reg := NewRegistry(store, nil)
	w := newRecordingWaker()
	r := NewRouter(reg, w, "host-A", 16)
	ctx := context.Background()

	// First event to a cold actor wakes it exactly once and is delivered.
	for i := 0; i < 3; i++ {
		if err := r.Route(ctx, "t", "agent-1", Actor{Template: "base"}, Event{ID: "e" + itoa(int64(i))}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return w.processed() == 3 })
	if w.wakeCount() != 1 {
		t.Fatalf("actor should be woken once for 3 events, woke %d", w.wakeCount())
	}

	// A different actor wakes separately.
	if err := r.Route(ctx, "t", "agent-2", Actor{}, Event{ID: "x"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w.processed() == 4 })
	if w.wakeCount() != 2 {
		t.Fatalf("second actor should wake separately, total wakes %d", w.wakeCount())
	}
}

func TestRouterHibernateAndRewake(t *testing.T) {
	reg := NewRegistry(NewMemStore(), nil)
	w := newRecordingWaker()
	r := NewRouter(reg, w, "host-A", 16)
	ctx := context.Background()

	a, _, _ := reg.GetActor(context.Background(), "t", "agent", Actor{})
	if err := r.Route(ctx, "t", "agent", Actor{}, Event{ID: "e1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w.processed() == 1 })
	if !r.IsLive(a.ID) {
		t.Fatal("actor should be live after routing")
	}

	r.Hibernate(a.ID, TierPaused1)
	if r.IsLive(a.ID) {
		t.Fatal("actor should not be live after hibernate")
	}
	// Lease must be released so another host could take over.
	got, _ := reg.store.Get(context.Background(), a.ID)
	if got.LeaseHolder != "" {
		t.Errorf("hibernate should release the lease, holder=%q", got.LeaseHolder)
	}
	if got.Tier != TierPaused1 {
		t.Errorf("tier should be recorded as tier1, got %s", got.Tier)
	}

	// Next event re-wakes.
	if err := r.Route(ctx, "t", "agent", Actor{}, Event{ID: "e2"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w.processed() == 2 })
	if w.wakeCount() != 2 {
		t.Fatalf("re-wake expected, total wakes %d", w.wakeCount())
	}
}

// TestRouterSingleWriterAcrossHosts: two routers (two hosts) over the same store
// — only one can hold a given Actor live at a time.
func TestRouterSingleWriterAcrossHosts(t *testing.T) {
	store := NewMemStore()
	regA := NewRegistry(store, nil)
	regB := NewRegistry(store, nil)
	wA, wB := newRecordingWaker(), newRecordingWaker()
	rA := NewRouter(regA, wA, "host-A", 4)
	rB := NewRouter(regB, wB, "host-B", 4)
	ctx := context.Background()

	a, _, _ := regA.GetActor(context.Background(), "t", "agent", Actor{})

	// host-A wakes and holds the Actor.
	if err := rA.Route(ctx, "t", "agent", Actor{}, Event{ID: "a1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return wA.processed() == 1 })

	// host-B cannot take it while host-A holds the lease.
	if err := rB.Route(ctx, "t", "agent", Actor{}, Event{ID: "b1"}); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("host-B should be refused with ErrLeaseHeld, got %v", err)
	}
	if wB.wakeCount() != 0 {
		t.Fatalf("host-B must not wake the Actor it can't lease, wakes=%d", wB.wakeCount())
	}

	// After host-A hibernates (releasing the lease), host-B can take over.
	rA.Hibernate(a.ID, TierCold)
	if err := rB.Route(ctx, "t", "agent", Actor{}, Event{ID: "b2"}); err != nil {
		t.Fatalf("host-B should acquire after host-A releases: %v", err)
	}
	waitFor(t, func() bool { return wB.processed() == 1 })
}
