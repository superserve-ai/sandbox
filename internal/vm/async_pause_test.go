package vm

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestWaitForFlush covers the async-pause flush handshake: idle is a no-op, a
// waiter blocks until the flush ends and then sees its outcome, and once settled
// it's idle again.
func TestWaitForFlush(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}
	inst := &VMInstance{ID: "vm1"}

	// No flush in progress → returns nil immediately.
	if err := m.waitForFlush(inst); err != nil {
		t.Fatalf("waitForFlush(idle) = %v, want nil", err)
	}

	// Begin a flush; a waiter must block until endFlush, then get its error.
	m.beginFlush(inst)
	want := errors.New("flush boom")
	done := make(chan error, 1)
	go func() { done <- m.waitForFlush(inst) }()

	select {
	case <-done:
		t.Fatal("waitForFlush returned before endFlush")
	case <-time.After(20 * time.Millisecond):
	}

	m.endFlush(inst, want)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("waitForFlush = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForFlush did not unblock after endFlush")
	}

	// Settled → idle again.
	if err := m.waitForFlush(inst); err != nil {
		t.Fatalf("waitForFlush(after) = %v, want nil", err)
	}
}

// TestCountHeldBridgeMemfds covers the bridge-memfd cap accounting: the default cap,
// an override, and counting only instances currently holding a memfd.
func TestCountHeldBridgeMemfds(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}}

	if got := m.maxBridgeMemfds(); got != 4 {
		t.Fatalf("default cap = %d, want 4", got)
	}
	m.cfg.MaxBridgeMemfds = 2
	if got := m.maxBridgeMemfds(); got != 2 {
		t.Fatalf("configured cap = %d, want 2", got)
	}

	if n := m.countHeldBridgeMemfds(); n != 0 {
		t.Fatalf("count(empty) = %d, want 0", n)
	}
	m.vms["a"] = &VMInstance{ID: "a", holdingBridgeMemfd: true}
	m.vms["b"] = &VMInstance{ID: "b"}
	m.vms["c"] = &VMInstance{ID: "c", holdingBridgeMemfd: true}
	if n := m.countHeldBridgeMemfds(); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
}

func TestHoldingBridgeMemfdPersists(t *testing.T) {
	// The bridge-memfd hold must survive a vmd restart (toRecord → toInstance): a reattached
	// fast-resumed FC still keeps the prior memfd mapped, so it must keep counting against the cap.
	if got := toInstance(toRecord(&VMInstance{ID: "v", holdingBridgeMemfd: true})); !got.holdingBridgeMemfd {
		t.Fatal("holdingBridgeMemfd did not survive the record round-trip")
	}
	if got := toInstance(toRecord(&VMInstance{ID: "w"})); got.holdingBridgeMemfd {
		t.Fatal("holdingBridgeMemfd wrongly true after round-trip of a non-holder")
	}
}

// TestTryClaimBridgeMemfd covers the atomic reserve: a slot goes only to an eligible
// (mid-flush, in-flight files set) instance, the cap is enforced, and the count-and-claim is
// atomic so a burst of concurrent claims can never exceed the cap.
func TestTryClaimBridgeMemfd(t *testing.T) {
	mkInst := func(id string) *VMInstance {
		return &VMInstance{
			ID:                   id,
			flushing:             true,
			bridgeMemFdPath:      "/proc/1/fd/7",
			bridgePendingVmstate: "/snap/" + id + "/vmstate.0.snap",
			bridgePendingLayer:   "/snap/" + id + "/mem.0.diff",
		}
	}

	// Ineligible instances are never granted, even with the cap wide open.
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, cfg: ManagerConfig{MaxBridgeMemfds: 4}}
	notFlushing := &VMInstance{ID: "x", bridgeMemFdPath: "/proc/1/fd/7", bridgePendingVmstate: "/v"}
	m.vms["x"] = notFlushing
	if _, _, _, ok := m.tryClaimBridgeMemfd(notFlushing); ok {
		t.Fatal("granted a slot to a non-flushing instance")
	}
	noPaths := &VMInstance{ID: "y", flushing: true}
	m.vms["y"] = noPaths
	if _, _, _, ok := m.tryClaimBridgeMemfd(noPaths); ok {
		t.Fatal("granted a slot with no in-flight files")
	}

	// A grant returns the in-flight files and marks the hold; the cap is then enforced.
	m = &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, cfg: ManagerConfig{MaxBridgeMemfds: 2}}
	a, b, c := mkInst("a"), mkInst("b"), mkInst("c")
	m.vms["a"], m.vms["b"], m.vms["c"] = a, b, c
	if mp, vp, lp, ok := m.tryClaimBridgeMemfd(a); !ok || mp != a.bridgeMemFdPath || vp != a.bridgePendingVmstate || lp != a.bridgePendingLayer {
		t.Fatalf("claim a = (%q,%q,%q,%v), want its files + true", mp, vp, lp, ok)
	}
	if !a.holdingBridgeMemfd {
		t.Fatal("claim a did not mark the hold")
	}
	if _, _, _, ok := m.tryClaimBridgeMemfd(b); !ok {
		t.Fatal("claim b under cap denied")
	}
	if _, _, _, ok := m.tryClaimBridgeMemfd(c); ok {
		t.Fatal("claim c granted past the cap of 2")
	}

	// Atomic under a burst: cap 3 over many eligible instances → exactly 3 grants.
	m = &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{}, cfg: ManagerConfig{MaxBridgeMemfds: 3}}
	const n = 24
	insts := make([]*VMInstance, n)
	for i := range insts {
		id := fmt.Sprintf("vm%d", i)
		insts[i] = mkInst(id)
		m.vms[id] = insts[i]
	}
	var granted int64
	var wg sync.WaitGroup
	for _, in := range insts {
		wg.Add(1)
		go func(in *VMInstance) {
			defer wg.Done()
			if _, _, _, ok := m.tryClaimBridgeMemfd(in); ok {
				atomic.AddInt64(&granted, 1)
			}
		}(in)
	}
	wg.Wait()
	if granted != 3 {
		t.Fatalf("concurrent grants = %d, want exactly 3 (the cap)", granted)
	}
}
