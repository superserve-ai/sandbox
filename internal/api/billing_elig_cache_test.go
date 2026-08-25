package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

// eligMockHandlers returns a Handlers whose DB answers every eligibility read
// with the current value of *answer, counting reads in *reads. block, when
// non-nil, holds each read until it is closed.
func eligMockHandlers(reads *atomic.Int64, answer *atomic.Bool, block chan struct{}) *Handlers {
	mock := &mockDBTX{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			reads.Add(1)
			if block != nil {
				<-block
			}
			return &mockRow{scanFn: func(dest ...any) error {
				*(dest[0].(*bool)) = answer.Load()
				return nil
			}}
		},
	}
	return &Handlers{DB: db.New(mock)}
}

// Within the TTL every verdict — eligible and ineligible alike — is served
// from cache: the create path pays the DB read once per team per window.
func TestBillingEligCacheServesBothVerdicts(t *testing.T) {
	for _, eligible := range []bool{true, false} {
		var reads atomic.Int64
		var answer atomic.Bool
		answer.Store(eligible)
		h := eligMockHandlers(&reads, &answer, nil)
		teamID := uuid.New()

		for i := 0; i < 5; i++ {
			got, err := h.teamBillingEligibleCached(context.Background(), teamID)
			if err != nil || got != eligible {
				t.Fatalf("eligible=%v call %d: got=%v err=%v", eligible, i, got, err)
			}
		}
		if got := reads.Load(); got != 1 {
			t.Fatalf("eligible=%v: DB reads = %d, want 1", eligible, got)
		}
	}
}

// A burst of concurrent cold-cache checks for one team shares a single
// flight — the pattern the 100-way create benchmark exercises.
func TestBillingEligCacheCoalescesBurst(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	block := make(chan struct{})
	h := eligMockHandlers(&reads, &answer, block)
	teamID := uuid.New()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := h.teamBillingEligibleCached(context.Background(), teamID); err != nil || !got {
				t.Errorf("got=%v err=%v", got, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond) // let every goroutine reach the flight
	close(block)
	wg.Wait()
	if got := reads.Load(); got != 1 {
		t.Fatalf("DB reads = %d, want 1 (concurrent misses must share one flight)", got)
	}
}

// The post-activation recheck is coalesced per team the same way: a create
// burst's worth of concurrent rechecks costs one DB read, not one per create.
func TestReconcileActivatedSandboxCoalesces(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true) // eligible: the pause sweep must not run (it would add reads)
	block := make(chan struct{})
	h := eligMockHandlers(&reads, &answer, block)
	teamID := uuid.New()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.reconcileActivatedSandbox(context.Background(), teamID)
		}()
	}
	time.Sleep(50 * time.Millisecond) // let every goroutine join the flight
	close(block)
	wg.Wait()
	if got := reads.Load(); got != 1 {
		t.Fatalf("DB reads = %d, want 1 (burst rechecks must share one flight)", got)
	}
}

// The map may never exceed its hard cap: memory stays bounded no matter how
// many unique teams churn through faster than expiry-based eviction reclaims.
func TestBillingEligCacheHardCap(t *testing.T) {
	var reads atomic.Int64
	var answer atomic.Bool
	answer.Store(true)
	h := eligMockHandlers(&reads, &answer, nil)

	for i := 0; i < billingEligCacheMaxEntries+100; i++ {
		if _, err := h.teamBillingEligibleCached(context.Background(), uuid.New()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	h.billingElig.mu.Lock()
	n := len(h.billingElig.m)
	h.billingElig.mu.Unlock()
	if n > billingEligCacheMaxEntries {
		t.Fatalf("cache holds %d entries, cap is %d", n, billingEligCacheMaxEntries)
	}
}
