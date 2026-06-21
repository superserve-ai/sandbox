package actor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAlarmSchedulerFiresDueOnly(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	store := NewMemAlarmStore()
	ctx := context.Background()

	var woke []string
	var mu sync.Mutex
	sched := NewAlarmScheduler(store, func(_ context.Context, a Alarm) error {
		mu.Lock()
		woke = append(woke, a.ActorID)
		mu.Unlock()
		return nil
	}, clk.now, 0)

	soon, _ := store.SetAlarm(ctx, "a", clk.now().Add(5*time.Second))
	_ = soon
	_, _ = store.SetAlarm(ctx, "b", clk.now().Add(30*time.Second))

	// Nothing due yet.
	if n, err := sched.Tick(ctx); n != 0 || err != nil {
		t.Fatalf("no alarms due yet: fired=%d err=%v", n, err)
	}

	// Advance past the first alarm only.
	clk.advance(10 * time.Second)
	n, err := sched.Tick(ctx)
	if err != nil || n != 1 {
		t.Fatalf("one alarm should fire: fired=%d err=%v", n, err)
	}
	mu.Lock()
	if len(woke) != 1 || woke[0] != "a" {
		t.Fatalf("alarm a should have woken its actor, got %v", woke)
	}
	mu.Unlock()
	// Fired alarm is deleted; the future one remains.
	if store.Len() != 1 {
		t.Fatalf("fired alarm should be deleted, %d remain", store.Len())
	}

	// Advance past the second.
	clk.advance(30 * time.Second)
	n, _ = sched.Tick(ctx)
	if n != 1 || store.Len() != 0 {
		t.Fatalf("second alarm should fire and clear: fired=%d remaining=%d", n, store.Len())
	}
}

// TestAlarmRetryOnWakeFailure: a wake failure leaves the alarm so the next Tick
// retries — at-least-once delivery, no silent drop.
func TestAlarmRetryOnWakeFailure(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	store := NewMemAlarmStore()
	ctx := context.Background()
	_, _ = store.SetAlarm(ctx, "a", clk.now())

	attempts := 0
	sched := NewAlarmScheduler(store, func(_ context.Context, _ Alarm) error {
		attempts++
		if attempts == 1 {
			return errors.New("wake failed (host busy)")
		}
		return nil
	}, clk.now, 0)

	if n, err := sched.Tick(ctx); n != 0 || err == nil {
		t.Fatalf("failed wake should fire 0 and surface error: fired=%d err=%v", n, err)
	}
	if store.Len() != 1 {
		t.Fatal("alarm must remain after a failed wake (retry)")
	}
	if n, err := sched.Tick(ctx); n != 1 || err != nil {
		t.Fatalf("retry should succeed: fired=%d err=%v", n, err)
	}
	if store.Len() != 0 {
		t.Fatal("alarm should be cleared after a successful retry")
	}
}

func TestAlarmBatchLimit(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	store := NewMemAlarmStore()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, _ = store.SetAlarm(ctx, "a"+itoa(int64(i)), clk.now())
	}
	sched := NewAlarmScheduler(store, func(_ context.Context, _ Alarm) error { return nil }, clk.now, 3)
	n, _ := sched.Tick(ctx)
	if n != 3 {
		t.Fatalf("batch should cap firing at 3, got %d", n)
	}
	if store.Len() != 7 {
		t.Fatalf("7 alarms should remain for the next tick, got %d", store.Len())
	}
}
