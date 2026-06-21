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
type Inbox struct {
	ch      chan Event
	closeMu sync.Mutex
	closed  bool
	done    chan struct{}
}

// NewInbox creates an inbox with the given queue depth. Send blocks when the
// queue is full (backpressure) until the consumer drains or ctx is cancelled.
func NewInbox(depth int) *Inbox {
	if depth < 0 {
		depth = 0
	}
	return &Inbox{ch: make(chan Event, depth), done: make(chan struct{})}
}

// Send enqueues ev. It blocks if the queue is full until space frees, the inbox
// closes (ErrInboxClosed), or ctx is cancelled (ctx.Err()).
func (i *Inbox) Send(ctx context.Context, ev Event) error {
	// Fast path: reject if already closed so we don't block on a dead inbox.
	i.closeMu.Lock()
	closed := i.closed
	i.closeMu.Unlock()
	if closed {
		return ErrInboxClosed
	}
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
		case ev, ok := <-i.ch:
			if !ok {
				return
			}
			if err := h(ctx, ev); err != nil && onErr != nil {
				onErr(ev, err)
			}
		}
	}
}

// Close stops accepting new events. In-flight Send calls unblock with
// ErrInboxClosed; a Run consumer drains remaining queued events then exits when
// the channel is closed. Idempotent.
func (i *Inbox) Close() {
	i.closeMu.Lock()
	defer i.closeMu.Unlock()
	if i.closed {
		return
	}
	i.closed = true
	close(i.done)
	close(i.ch)
}

// Depth returns the number of events currently queued (for idle detection: an
// empty inbox is a precondition for hibernating the Actor).
func (i *Inbox) Depth() int { return len(i.ch) }
