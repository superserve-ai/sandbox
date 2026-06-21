package actor

import (
	"context"
	"errors"
	"sync"
)

// Event is one message delivered to an Actor. The runtime routes HTTP requests,
// webhooks, alarms, and agent→agent messages into Events; the Actor processes
// them one at a time so its single-writer state never sees concurrent mutation.
type Event struct {
	ID      string // unique id (for dedup / tracing)
	Type    string // e.g. "msg", "webhook", "alarm"
	Payload []byte

	// Out, when non-nil, is the per-turn output sink: the harness's output for
	// THIS event is streamed into it and it is Closed when the turn completes,
	// so a request/response caller can stream the reply. Nil for fire-and-forget
	// events (webhooks, alarms, agent→agent) that produce no streamed reply.
	Out *Relay
}

// Handler processes a single Event to completion. The Inbox guarantees it is
// never called concurrently for the same Actor.
type Handler func(ctx context.Context, ev Event) error

// ErrInboxClosed is returned by Send after the Inbox is closed.
var ErrInboxClosed = errors.New("actor: inbox closed")

// Inbox is a per-Actor mailbox. Concurrent Send calls enqueue; a single Run
// consumer drains them strictly one-at-a-time in arrival order. This is the
// "serialize concurrent input through an inbox" half of the Actor model — the
// complement to the single-writer lease: the lease guarantees one live instance,
// the inbox guarantees that instance processes events serially, so an Actor's
// /state is mutated by exactly one event at a time.
//
// Close is safe against concurrent Sends (the hibernation/demotion path closes
// an inbox while routes may still be arriving): the data channel is never closed
// under a sender, and no enqueued event is dropped. See Close.
type Inbox struct {
	ch chan Event

	mu       sync.Mutex
	cond     *sync.Cond // signaled when inflight reaches 0 after close
	closed   bool
	inflight int           // in-flight Send calls (counted under mu)
	done     chan struct{} // closed by Close: stop accepting new events
	drained  chan struct{} // closed after all in-flight sends settle: Run may drain+exit
}

// NewInbox creates an inbox with the given queue depth. Send blocks when the
// queue is full (backpressure) until the consumer drains or ctx is cancelled.
func NewInbox(depth int) *Inbox {
	if depth < 0 {
		depth = 0
	}
	i := &Inbox{
		ch:      make(chan Event, depth),
		done:    make(chan struct{}),
		drained: make(chan struct{}),
	}
	i.cond = sync.NewCond(&i.mu)
	return i
}

// Send enqueues ev. It blocks if the queue is full until space frees, the inbox
// closes (ErrInboxClosed), or ctx is cancelled (ctx.Err()). Safe to call
// concurrently with Close: an event is either enqueued (and guaranteed drained
// by Run) or rejected with ErrInboxClosed — never lost, never a panic.
func (i *Inbox) Send(ctx context.Context, ev Event) error {
	// Register as in-flight under the lock (atomic with the closed check) so
	// Close's drain wait cannot complete while this Send might still enqueue.
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return ErrInboxClosed
	}
	i.inflight++
	i.mu.Unlock()
	defer func() {
		i.mu.Lock()
		i.inflight--
		if i.closed && i.inflight == 0 {
			i.cond.Broadcast() // let a waiting Close proceed to drain
		}
		i.mu.Unlock()
	}()

	// The data channel is never closed, so the send case can't panic. On close,
	// the done case wins and we reject; any event that does land in the buffer is
	// drained by Run (Close waits for all in-flight Sends before letting Run exit).
	select {
	case i.ch <- ev:
		return nil
	case <-i.done:
		return ErrInboxClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run is the single consumer. It calls h for each event, strictly serially, in
// arrival order, until ctx is cancelled or Close is called and the queue is
// drained. A handler error is returned to onErr (if non-nil) and does not stop
// the loop — one bad event must not wedge the Actor.
//
// Run must be called by exactly one goroutine — that single-consumer discipline
// IS the serialization guarantee.
func (i *Inbox) Run(ctx context.Context, h Handler, onErr func(Event, error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-i.drained:
			// Close has settled: no more sends can enqueue. Drain whatever is
			// buffered (in arrival order) and exit — no event is dropped.
			for {
				select {
				case ev := <-i.ch:
					if err := h(ctx, ev); err != nil && onErr != nil {
						onErr(ev, err)
					}
				default:
					return
				}
			}
		case ev := <-i.ch:
			if err := h(ctx, ev); err != nil && onErr != nil {
				onErr(ev, err)
			}
		}
	}
}

// Close stops accepting new events and lets a Run consumer drain the remaining
// queue then exit. Idempotent. It closes `done` (so in-flight Sends bail with
// ErrInboxClosed instead of blocking), waits for every in-flight Send to return,
// and only then closes `drained` — guaranteeing that when Run drains, no further
// event can still be racing into the buffer. The data channel itself is never
// closed, so a concurrent Send can never panic.
func (i *Inbox) Close() {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}
	i.closed = true
	close(i.done) // in-flight Sends blocked on a full buffer now bail
	for i.inflight > 0 {
		i.cond.Wait() // released i.mu; reacquired on wake
	}
	i.mu.Unlock()
	close(i.drained) // no Send can enqueue past here; safe for Run to drain+exit
}

// Depth returns the number of events currently queued (for idle detection: an
// empty inbox is a precondition for hibernating the Actor).
func (i *Inbox) Depth() int { return len(i.ch) }
