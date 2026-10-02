package api

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLegacyStorageHandoffBoundsRetriesPerHost(t *testing.T) {
	h := &Handlers{}
	key := legacyStorageAckKey{hostID: "example-host"}
	reportID := uuid.New()
	initialStarted := make(chan struct{})
	retryStarted := make(chan struct{})
	releaseInitial := make(chan struct{})
	releaseRetry := make(chan struct{})
	initialDone := make(chan struct{})
	var initialOnce, retryOnce sync.Once
	var initialAccepted bool
	var initialCalls, retryCalls, unexpectedCalls atomic.Int64
	outage := errors.New("storage unavailable")
	unexpected := func(context.Context) error {
		unexpectedCalls.Add(1)
		return outage
	}
	t.Cleanup(func() {
		initialOnce.Do(func() { close(releaseInitial) })
		retryOnce.Do(func() { close(releaseRetry) })
		<-initialDone
		h.WaitAsyncBookkeeping()
	})
	go func() {
		defer close(initialDone)
		initialAccepted = h.handoffLegacyStorageReport(key, reportID, func(context.Context) error {
			initialCalls.Add(1)
			close(initialStarted)
			<-releaseInitial
			return outage
		}, func(context.Context) error {
			retryCalls.Add(1)
			close(retryStarted)
			<-releaseRetry
			return nil
		})
	}()
	<-initialStarted

	assertArrivalsAreDeferred := func() {
		t.Helper()
		var wg sync.WaitGroup
		var accepted atomic.Int64
		for i := range 64 {
			id := reportID
			if i%2 == 0 {
				// ID-less legacy arrivals each receive a newly generated ID.
				id = uuid.New()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if h.handoffLegacyStorageReport(key, id, unexpected, unexpected) {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 0 {
			t.Fatal("in-flight storage was acknowledged before durable acceptance")
		}
		if unexpectedCalls.Load() != 0 {
			t.Fatalf("recurring arrivals started %d extra storage attempts", unexpectedCalls.Load())
		}
	}
	assertArrivalsAreDeferred()
	initialOnce.Do(func() { close(releaseInitial) })
	<-initialDone
	if initialAccepted {
		t.Fatal("failed inline handoff was acknowledged")
	}
	<-retryStarted
	assertArrivalsAreDeferred()
	if _, ok := h.legacyStorageAccepted.Load(key); ok {
		t.Fatal("retry was cached as accepted before it committed")
	}
	for _, independentKey := range []legacyStorageAckKey{
		{hostID: "another-host"},
		{hostID: key.hostID, incarnationID: uuid.NewString()},
	} {
		if !h.handoffLegacyStorageReport(independentKey, uuid.New(), func(context.Context) error { return nil }, unexpected) {
			t.Fatal("in-flight report blocked an independent host or incarnation")
		}
	}
	retryOnce.Do(func() { close(releaseRetry) })
	h.WaitAsyncBookkeeping()
	if initialCalls.Load() != 1 || retryCalls.Load() != 1 {
		t.Fatalf("handoff calls = %d inline, %d retry; want one each", initialCalls.Load(), retryCalls.Load())
	}
	if !h.handoffLegacyStorageReport(key, reportID, unexpected, unexpected) {
		t.Fatal("durably accepted report was not acknowledged from the cache")
	}
	if unexpectedCalls.Load() != 0 {
		t.Fatal("accepted report performed more storage work")
	}
	newReportID := uuid.New()
	newReportEnqueued := false
	if !h.handoffLegacyStorageReport(key, newReportID, func(context.Context) error {
		newReportEnqueued = true
		return nil
	}, unexpected) || !newReportEnqueued {
		t.Fatal("a new report reused an older report's acceptance or remained blocked")
	}
	if _, active := h.legacyStorageInFlight.Load(key); active {
		t.Fatal("successful handoff retained the host's in-flight claim")
	}
}

func TestLegacyStorageHandoffFailureReleasesHost(t *testing.T) {
	h := &Handlers{}
	key := legacyStorageAckKey{hostID: "example-host", incarnationID: uuid.NewString()}
	reportID := uuid.New()
	outage := errors.New("storage unavailable")
	var inlineBudget, retryBudget time.Duration
	if h.handoffLegacyStorageReport(key, reportID, func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if ok {
			inlineBudget = time.Until(deadline)
		}
		return outage
	}, func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if ok {
			retryBudget = time.Until(deadline)
		}
		return outage
	}) {
		t.Fatal("failed handoff was acknowledged")
	}
	h.WaitAsyncBookkeeping()
	if inlineBudget <= 0 || inlineBudget > 2*time.Second || retryBudget <= 0 || retryBudget > 2*time.Minute {
		t.Fatalf("unexpected handoff budgets: inline %s, retry %s", inlineBudget, retryBudget)
	}
	if _, accepted := h.legacyStorageAccepted.Load(key); accepted {
		t.Fatal("failed retry was cached as durably accepted")
	}
	if _, active := h.legacyStorageInFlight.Load(key); active {
		t.Fatal("failed retry retained the host's in-flight claim")
	}
	enqueued := false
	if !h.handoffLegacyStorageReport(key, reportID, func(context.Context) error {
		enqueued = true
		return nil
	}, func(context.Context) error { return outage }) || !enqueued {
		t.Fatal("later heartbeat could not retry after storage recovered")
	}
}
