package gateway

import (
	"testing"
	"time"
)

func TestRouterQuiesceResumeSignalsWaiters(t *testing.T) {
	r := NewRouter()

	// Un-quiesced: the resume channel is already closed (no wait).
	select {
	case <-r.resumedChan():
	default:
		t.Fatal("fresh router should not be quiescing")
	}

	r.SetActive(Upstream{Generation: "A", Socket: "/tmp/a.sock"})
	r.Quiesce(true)
	if up, q := r.Active(); !q || up.Generation != "A" {
		t.Fatalf("after Quiesce(true): up=%v quiescing=%v", up, q)
	}

	// A waiter blocks until resume.
	ch := r.resumedChan()
	select {
	case <-ch:
		t.Fatal("resume channel closed while still quiescing")
	default:
	}

	done := make(chan struct{})
	go func() { <-ch; close(done) }()
	r.Quiesce(false)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiter not released after Quiesce(false)")
	}
	if _, q := r.Active(); q {
		t.Fatal("still quiescing after resume")
	}
}
