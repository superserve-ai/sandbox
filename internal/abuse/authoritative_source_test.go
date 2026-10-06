package abuse

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthoritativeCacheFailureExpiryAndTrust(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	trusted, restricted := uuid.New(), uuid.New()
	expires := now.Add(time.Minute)
	fail := false
	source := NewAuthoritativeSource(nil, AuthoritativeOptions{TTL: time.Hour, Loader: func(_ context.Context, emit func(PolicyRecord)) (ComputeMode, int64, error) {
		if fail {
			return ModeOff, 0, errors.New("offline")
		}
		emit(PolicyRecord{TeamID: trusted, Trusted: true, Restricted: true})
		emit(PolicyRecord{TeamID: restricted, Restricted: true, ExpiresAt: &expires})
		return ModeEnforce, 1, nil
	}})
	source.now = func() time.Time { return now }
	evaluator := &ComputeEvaluator{Source: source}
	if source.TeamPolicy(trusted).Known || evaluator.Evaluate(restricted, ActionCreate).Outcome != "allowed" {
		t.Fatal("unpopulated policy did not fail open")
	}
	source.Refresh(ctx)
	if evaluator.Evaluate(trusted, ActionCreate).Outcome != "allowed" || evaluator.Evaluate(restricted, ActionResume).Outcome != "blocked" {
		t.Fatal("trust/restriction projection incorrect")
	}
	fail = true
	source.Refresh(ctx)
	if evaluator.Evaluate(restricted, ActionCreate).Outcome != "blocked" {
		t.Fatal("transient refresh failure lost valid state")
	}
	now = expires
	source.Refresh(ctx)
	if evaluator.Evaluate(restricted, ActionCreate).Outcome != "allowed" {
		t.Fatal("expired deny survived background maintenance")
	}
	now = now.Add(2 * time.Hour)
	source.Refresh(ctx)
	if source.TeamPolicy(restricted).Known || !source.TeamPolicy(trusted).Known {
		t.Fatal("stale negative trust remains authoritative or sticky positive trust lost")
	}
	if !source.TeamPolicy(trusted).Trusted {
		t.Fatal("trust was evicted during outage")
	}
}

func TestAuthoritativeCacheAdmissionKeepsExistingDenies(t *testing.T) {
	one, two, trusted := uuid.New(), uuid.New(), uuid.New()
	rows := []PolicyRecord{{TeamID: one, Restricted: true}}
	var rejected int
	source := NewAuthoritativeSource(nil, AuthoritativeOptions{Capacity: 1, Loader: func(_ context.Context, emit func(PolicyRecord)) (ComputeMode, int64, error) {
		for _, row := range rows {
			emit(row)
		}
		return ModeEnforce, 1, nil
	}, Report: func(_ string, stats CacheStats) { rejected = stats.CapacityRejected }})
	source.Refresh(context.Background())
	rows = []PolicyRecord{{TeamID: two, Restricted: true}, {TeamID: trusted, Trusted: true}, {TeamID: one, Restricted: true}}
	source.Refresh(context.Background())
	if !source.TeamPolicy(one).Restricted || source.TeamPolicy(two).Restricted || !source.TeamPolicy(trusted).Trusted || rejected != 1 {
		t.Fatalf("capacity churn displaced known deny/trust: %+v", source.Stats())
	}
	rows = []PolicyRecord{{TeamID: two, Restricted: true}}
	source.Refresh(context.Background())
	if source.TeamPolicy(one).Restricted || !source.TeamPolicy(two).Restricted || source.TeamPolicy(trusted).Trusted {
		t.Fatal("complete replacement did not release/revoke prior state")
	}
}

func TestAuthoritativeCacheRejectsPartialRefresh(t *testing.T) {
	one, two := uuid.New(), uuid.New()
	fail := false
	source := NewAuthoritativeSource(nil, AuthoritativeOptions{Loader: func(_ context.Context, emit func(PolicyRecord)) (ComputeMode, int64, error) {
		if fail {
			emit(PolicyRecord{TeamID: two, Restricted: true})
			return ModeEnforce, 2, errors.New("scan failed")
		}
		emit(PolicyRecord{TeamID: one, Trusted: true})
		return ModeEnforce, 1, nil
	}})
	source.Refresh(context.Background())
	fail = true
	source.Refresh(context.Background())
	if !source.TeamPolicy(one).Trusted || source.TeamPolicy(two).Restricted {
		t.Fatal("partial snapshot was published")
	}
}

func TestAuthoritativeCacheConcurrentReadsAndCoalescedChanges(t *testing.T) {
	id := uuid.New()
	generation := int64(0)
	source := NewAuthoritativeSource(nil, AuthoritativeOptions{Loader: func(_ context.Context, emit func(PolicyRecord)) (ComputeMode, int64, error) {
		generation++
		emit(PolicyRecord{TeamID: id, Trusted: true, Restricted: true})
		return ModeEnforce, generation, nil
	}})
	source.Refresh(context.Background())
	<-source.Changes()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if (&ComputeEvaluator{Source: source}).Evaluate(id, ActionResume).Outcome != "allowed" {
					t.Error("trusted team denied")
				}
			}
		}()
	}
	for range 20 {
		source.Refresh(context.Background())
	}
	wg.Wait()
	select {
	case <-source.Changes():
		t.Fatal("unchanged effective policy caused repeated containment wakeups")
	default:
	}
}
