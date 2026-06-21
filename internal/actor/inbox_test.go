package actor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestInboxSerializes is the core invariant: under many concurrent senders, the
// handler is NEVER invoked concurrently — the Actor's single-writer state sees
// one event at a time.
func TestInboxSerializes(t *testing.T) {
	ib := NewInbox(0) // unbuffered → maximal contention
	var inHandler int32
	var maxConcurrent int32
	var processed int64

	ctx, cancel := context.WithCancel(context.Background())
	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		ib.Run(ctx, func(_ context.Context, _ Event) error {
			n := atomic.AddInt32(&inHandler, 1)
			if n > atomic.LoadInt32(&maxConcurrent) {
				atomic.StoreInt32(&maxConcurrent, n)
			}
			if n != 1 {
				t.Errorf("handler ran concurrently: %d in flight", n)
			}
			time.Sleep(time.Millisecond) // widen the window for a race to show
			atomic.AddInt64(&processed, 1)
			atomic.AddInt32(&inHandler, -1)
			return nil
		}, nil)
	}()

	const senders = 32
	var sendWG sync.WaitGroup
	for s := 0; s < senders; s++ {
		sendWG.Add(1)
		go func(id int) {
			defer sendWG.Done()
			_ = ib.Send(ctx, Event{ID: "e", Type: "msg"})
		}(s)
	}
	sendWG.Wait()

	// Drain, then stop the consumer.
	for ib.Depth() > 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	cancel()
	consumerWG.Wait()

	if got := atomic.LoadInt32(&maxConcurrent); got != 1 {
		t.Fatalf("max concurrent handler invocations = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&processed); got != senders {
		t.Fatalf("processed %d events, want %d", got, senders)
	}
}

// TestInboxFIFO: a single sender's events are processed in arrival order.
func TestInboxFIFO(t *testing.T) {
	ib := NewInbox(100)
	const n = 50
	var order []int
	var mu sync.Mutex
	done := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ib.Run(ctx, func(_ context.Context, ev Event) error {
		mu.Lock()
		order = append(order, int(ev.Payload[0]))
		if len(order) == n {
			close(done)
		}
		mu.Unlock()
		return nil
	}, nil)

	for i := 0; i < n; i++ {
		if err := ib.Send(ctx, Event{Payload: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for events")
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < n; i++ {
		if order[i] != i {
			t.Fatalf("event %d processed out of order: got %d", i, order[i])
		}
	}
}

func TestInboxCloseRejectsSend(t *testing.T) {
	ib := NewInbox(1)
	ib.Close()
	if err := ib.Send(context.Background(), Event{}); !errors.Is(err, ErrInboxClosed) {
		t.Fatalf("send after close should be ErrInboxClosed, got %v", err)
	}
	ib.Close() // idempotent
}

func TestInboxSendRespectsContext(t *testing.T) {
	ib := NewInbox(0) // unbuffered, no consumer → Send blocks
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := ib.Send(ctx, Event{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked send should honor ctx deadline, got %v", err)
	}
}

// TestInboxDrainsOnClose: a Run consumer processes already-queued events after
// Close before exiting (no silent message loss on graceful shutdown).
func TestInboxDrainsOnClose(t *testing.T) {
	ib := NewInbox(10)
	for i := 0; i < 5; i++ {
		_ = ib.Send(context.Background(), Event{Payload: []byte{byte(i)}})
	}
	ib.Close()

	var count int64
	ib.Run(context.Background(), func(_ context.Context, _ Event) error {
		atomic.AddInt64(&count, 1)
		return nil
	}, nil)
	if count != 5 {
		t.Fatalf("drained %d queued events on close, want 5", count)
	}
}
