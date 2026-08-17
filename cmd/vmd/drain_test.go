package main

import (
	"testing"
	"time"
)

func TestDrainGateBusyThenDrains(t *testing.T) {
	g := newDrainGate()

	if !g.admit() {
		t.Fatal("should admit an RPC when not draining")
	}
	// One in-flight RPC + a short budget → reports busy, and leaves draining set.
	if g.drainToZero(30 * time.Millisecond) {
		t.Fatal("drainToZero should report busy while an RPC is in flight")
	}
	// While draining, new RPCs are refused.
	if g.admit() {
		t.Fatal("admit must be refused while draining")
	}

	g.done() // the in-flight RPC finishes → inflight hits zero
	if !g.drainToZero(50 * time.Millisecond) {
		t.Fatal("drainToZero should succeed once no RPC is in flight")
	}

	// Aborting the drain resumes admission.
	g.undrain()
	if !g.admit() {
		t.Fatal("admit should resume after undrain")
	}
	g.done()
}
