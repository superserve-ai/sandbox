package actor

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// concurrencyWaker returns handlers that detect any single-writer violation
// (two handler bodies running at once for the same Actor) and count processed
// events. A fresh handler is returned per wake, but they all share the same
// counters so a re-wake racing a teardown would be caught.
type concurrencyWaker struct {
	inHandler int32
	maxConc   int32
	processed int64
	wakes     int64
}

func (w *concurrencyWaker) Wake(_ context.Context, a Actor, _ *Lease) (Handler, error) {
	atomic.AddInt64(&w.wakes, 1)
	return func(ctx context.Context, ev Event) error {
		n := atomic.AddInt32(&w.inHandler, 1)
		for {
			m := atomic.LoadInt32(&w.maxConc)
			if n <= m || atomic.CompareAndSwapInt32(&w.maxConc, m, n) {
				break
			}
		}
		// Widen the window so a concurrent delivery would be observed.
		time.Sleep(50 * time.Microsecond)
		atomic.AddInt64(&w.processed, 1)
		atomic.AddInt32(&w.inHandler, -1)
		return nil
	}, nil
}

// TestRouterDemoteRaceSingleWriter hammers one Actor with concurrent routes while
// a second goroutine continuously demotes it across all tiers. It asserts the two
// load-bearing invariants of the demotion lifecycle:
//   - single-writer: a handler body is NEVER running concurrently with another
//     (no two live instances), even as instances are torn down and re-woken;
//   - no loss: every event that Route returns nil for is eventually processed
//     exactly once (events racing a teardown are re-woken and re-delivered).
//
// Run with -race to also catch the inbox close / map / lease data races.
func TestRouterDemoteRaceSingleWriter(t *testing.T) {
	reg := NewRegistry(NewMemStore(), nil)
	w := &concurrencyWaker{}
	r := NewRouter(reg, w, "host-A", 4)
	a, _, _ := reg.GetActor(context.Background(), "t", "agent", Actor{})
	ctx := context.Background()

	var vmPauses int64
	vmDemote := func() error {
		atomic.AddInt64(&vmPauses, 1)
		time.Sleep(30 * time.Microsecond) // simulate the vmd op; must not race delivery
		return nil
	}

	const routers, perRouter = 6, 150
	var sent int64
	var wg sync.WaitGroup
	for g := 0; g < routers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perRouter; i++ {
				if err := r.Route(ctx, "t", "agent", Actor{}, Event{ID: fmt.Sprintf("%d-%d", g, i)}); err != nil {
					t.Errorf("route(%d-%d): %v", g, i, err)
					return
				}
				atomic.AddInt64(&sent, 1)
			}
		}(g)
	}

	// Demote across all tiers, interleaving with the routes. A FINITE storm (not
	// an infinite one): real demotion is idle-triggered, so a continuously-routed
	// Actor is Touch'd and never demoted — an unbounded unconditional demoter
	// would just starve routes, which is not the invariant under test. Across
	// these demotions we still exercise hundreds of teardown/re-wake interleavings.
	const demotes = 400
	stop := make(chan struct{})
	var dwg sync.WaitGroup
	dwg.Add(1)
	go func() {
		defer dwg.Done()
		tiers := []Tier{TierPaused1, TierPaused2, TierPaused3, TierCold}
		for i := 0; i < demotes; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = r.Demote(ctx, a.ID, tiers[i%len(tiers)], vmDemote)
			// Space demotions so a route reliably wakes+sends in the gap (real
			// demotion is idle-gated at ~1/s, never a tight storm). Still ~hundreds
			// of teardown/re-wake interleavings across the run.
			time.Sleep(200 * time.Microsecond)
		}
	}()

	wg.Wait()
	close(stop)
	dwg.Wait()

	// All routed events must drain (one final demote may have torn down the live
	// instance; a wake-up route ensures the last batch is consumed).
	waitFor(t, func() bool {
		return atomic.LoadInt64(&w.processed) == int64(routers*perRouter)
	})

	if mc := atomic.LoadInt32(&w.maxConc); mc > 1 {
		t.Fatalf("single-writer VIOLATED: %d concurrent handler invocations", mc)
	}
	if got, want := atomic.LoadInt64(&w.processed), int64(routers*perRouter); got != want {
		t.Fatalf("event loss: processed %d, sent %d", got, want)
	}
	if atomic.LoadInt64(&w.wakes) < 1 {
		t.Fatal("expected at least one wake")
	}
	t.Logf("processed=%d wakes=%d vmPauses=%d maxConc=%d",
		w.processed, w.wakes, vmPauses, w.maxConc)
}

// TestRouterDemoteKeepsLeaseForTier1 checks the stickiness rule at the Router
// level: a Tier-1 demote keeps this host's lease; a deeper demote releases it.
func TestRouterDemoteKeepsLeaseForTier1(t *testing.T) {
	reg := NewRegistry(NewMemStore(), nil)
	w := newRecordingWaker()
	r := NewRouter(reg, w, "host-A", 4)
	a, _, _ := reg.GetActor(context.Background(), "t", "agent", Actor{})
	ctx := context.Background()

	noop := func() error { return nil }

	mustRoute(t, r, ctx)
	if err := r.Demote(ctx, a.ID, TierPaused1, noop); err != nil {
		t.Fatal(err)
	}
	if got, _ := reg.store.Get(ctx, a.ID); got.LeaseHolder != "host-A" {
		t.Errorf("Tier-1 demote should keep the lease, holder=%q", got.LeaseHolder)
	}

	mustRoute(t, r, ctx) // re-wakes, re-acquiring our own lease
	if err := r.Demote(ctx, a.ID, TierPaused2, noop); err != nil {
		t.Fatal(err)
	}
	if got, _ := reg.store.Get(ctx, a.ID); got.LeaseHolder != "" {
		t.Errorf("Tier-2 demote should release the lease, holder=%q", got.LeaseHolder)
	}
}

func mustRoute(t *testing.T, r *Router, ctx context.Context) {
	t.Helper()
	if err := r.Route(ctx, "t", "agent", Actor{}, Event{ID: "e"}); err != nil {
		t.Fatal(err)
	}
}
