package gateway

import (
	"testing"
	"time"
)

func TestRouterGRPCHoldIsIndependent(t *testing.T) {
	r := NewRouter()
	r.SetActive(Upstream{Generation: "A", GRPCSocket: "/tmp/a.sock", ResolverSocket: "/tmp/a-res.sock"})

	// Holding gRPC must NOT hold the resolver — the resolver keeps serving while
	// the old generation drains.
	r.QuiesceGRPC(true)
	if _, held := r.Active(); !held {
		t.Fatal("gRPC should be held")
	}
	if _, resHeld, _ := r.resolverState(); resHeld {
		t.Fatal("resolver must not be held by QuiesceGRPC")
	}
}

func TestRouterResolverResumeSignalsWaiters(t *testing.T) {
	r := NewRouter()

	// Un-held: the resume channel is already closed (no wait).
	_, held, ch := r.resolverState()
	if held {
		t.Fatal("fresh router should not hold the resolver")
	}
	select {
	case <-ch:
	default:
		t.Fatal("fresh resolver resume channel should be closed")
	}

	r.QuiesceResolver(true)
	_, held, ch = r.resolverState()
	if !held {
		t.Fatal("resolver should be held")
	}
	select {
	case <-ch:
		t.Fatal("resume channel closed while still held")
	default:
	}

	done := make(chan struct{})
	go func() { <-ch; close(done) }()
	r.QuiesceResolver(false)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiter not released after QuiesceResolver(false)")
	}
}
