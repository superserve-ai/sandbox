package network

import (
	"sync"
	"testing"
)

func TestConnectionAcquisitionSurvivesAddressReuse(t *testing.T) {
	l := NewConnectionLimiter()
	old, ok := l.TryAcquire("192.0.2.1", 1)
	if !ok {
		t.Fatal("old acquisition rejected")
	}
	l.Remove("192.0.2.1")
	current, ok := l.TryAcquire("192.0.2.1", 1)
	if !ok {
		t.Fatal("new acquisition rejected")
	}
	old()
	old()
	if l.Count("192.0.2.1") != 1 {
		t.Fatal("old cleanup decremented new registration")
	}
	if _, ok := l.TryAcquire("192.0.2.1", 1); ok {
		t.Fatal("limit bypassed")
	}
	current()
	current()
	if len(l.connections) != 0 {
		t.Fatal("idle counter leaked")
	}
}

func TestConnectionLimiterConcurrentBound(t *testing.T) {
	l := NewConnectionLimiter()
	const limit = 7
	var wg sync.WaitGroup
	releases := make(chan func(), 200)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if done, ok := l.TryAcquire("192.0.2.2", limit); ok {
				releases <- done
			}
		}()
	}
	wg.Wait()
	close(releases)
	if l.Count("192.0.2.2") != limit {
		t.Fatalf("count=%d", l.Count("192.0.2.2"))
	}
	for done := range releases {
		done()
	}
	if len(l.connections) != 0 {
		t.Fatal("counter leaked")
	}
}
