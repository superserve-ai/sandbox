package vm

import (
	"sync"
	"time"
)

// LogStream identifies which kind of data a BuildLogEvent carries.
type LogStream string

const (
	// LogStreamStdout/Stderr are forwarded verbatim from the build VM's
	// boxd process (run steps, start_cmd, ready_cmd probes).
	LogStreamStdout LogStream = "stdout"
	LogStreamStderr LogStream = "stderr"

	// LogStreamSystem is supervisor/manager-generated text: step
	// boundaries ("step 2/3: pip install"), phase transitions
	// ("snapshotting"), terminal status ("ready" / "failed").
	LogStreamSystem LogStream = "system"
)

// BuildLogEvent is one chunk published to subscribers of a build's log
// stream. Text is typically one line but may be mid-line for large outputs.
type BuildLogEvent struct {
	Timestamp time.Time
	Stream    LogStream
	Text      string
	// Finished is true on the final event emitted when the build reaches
	// a terminal status. After this, the channel is closed by the buffer.
	Finished bool
	Status   BuildStatus // set only on the Finished event
}

// buildLogBufferSize is the ring capacity in events. 10k is enough to hold
// the full output of a typical 3-5 minute build (rough budget: 30-60
// events/sec during `apt-get install`, so up to ~15k events for 5 min of
// non-stop chatter — we accept dropping the earliest if it overflows).
const buildLogBufferSize = 10_000

// subscriberChanBuffer is how many events a slow subscriber can queue
// before we start dropping their feed. Bigger than typical network-buffer
// stall duration; a client that can't keep up that long is probably gone.
const subscriberChanBuffer = 256

// buildLogBuffer holds a bounded ring of events for one build plus any
// active subscribers. Thread-safe. One of these per in-flight build,
// stored on the buildRecord and cleaned up when the record is deleted.
type buildLogBuffer struct {
	mu          sync.Mutex
	events      []BuildLogEvent // ring buffer; len capped at buildLogBufferSize
	dropped     int             // counter of events dropped due to overflow
	closed      bool            // true once Close has been called
	subscribers map[chan BuildLogEvent]struct{}
}

func newBuildLogBuffer() *buildLogBuffer {
	return &buildLogBuffer{
		events:      make([]BuildLogEvent, 0, 256),
		subscribers: make(map[chan BuildLogEvent]struct{}),
	}
}

// Append adds one event to the ring and fans it out to all subscribers.
// Overflow past buildLogBufferSize drops the oldest event to make room;
// the dropped counter lets observers detect buffer pressure after the fact.
//
// Subscribers with full channels get the event silently dropped for them
// — we don't block the producer. A slow reader degrades only their own
// view, not the build or the other readers.
func (b *buildLogBuffer) Append(ev BuildLogEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	if len(b.events) >= buildLogBufferSize {
		// Ring eviction: drop the oldest by shifting. A proper circular
		// buffer would avoid the shift cost, but at 10k entries and build
		// durations measured in minutes the shift is negligible compared
		// to the RPC chatter it accompanies. Keep the code simple.
		b.events = b.events[1:]
		b.dropped++
	}
	b.events = append(b.events, ev)

	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// Subscriber behind — skip them for this event. They'll
			// catch up on their next successful send or unsubscribe.
		}
	}
}

// Subscribe returns a channel that receives all events appended AFTER the
// subscribe call, plus a snapshot of the buffered history pre-pended in
// order. The caller MUST drain the channel or call Unsubscribe — leaking
// would keep the channel in the fan-out set indefinitely. Close the
// subscription by calling the returned unsubscribe function.
func (b *buildLogBuffer) Subscribe() (<-chan BuildLogEvent, func()) {
	ch := make(chan BuildLogEvent, subscriberChanBuffer)

	b.mu.Lock()
	// Replay buffered history into the subscriber's channel first so they
	// see a coherent tail-from-start view. Gated by the subscriber channel
	// buffer — if history is bigger than the channel can hold, the fast
	// prefix goes in and the slow suffix is dropped.
	for _, ev := range b.events {
		select {
		case ch <- ev:
		default:
			break
		}
	}

	if b.closed {
		// Buffer already closed: there will be no further appends, so
		// close the subscriber channel too. Caller still reads history.
		close(ch)
		b.mu.Unlock()
		return ch, func() {}
	}

	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		if _, ok := b.subscribers[ch]; ok {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
	return ch, unsubscribe
}

// Close emits one final Finished event (or coerces the last event) and
// closes every subscriber channel. After Close, Append is a no-op and new
// Subscribe calls receive the buffered history + an immediately-closed
// channel. Called when the build reaches a terminal status.
func (b *buildLogBuffer) Close(finalStatus BuildStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true

	finalEvent := BuildLogEvent{
		Timestamp: time.Now(),
		Stream:    LogStreamSystem,
		Text:      string(finalStatus),
		Finished:  true,
		Status:    finalStatus,
	}
	// Add to the history so a late subscriber also sees the terminal event.
	if len(b.events) >= buildLogBufferSize {
		b.events = b.events[1:]
		b.dropped++
	}
	b.events = append(b.events, finalEvent)

	for ch := range b.subscribers {
		select {
		case ch <- finalEvent:
		default:
		}
		close(ch)
	}
	b.subscribers = nil
}

// Snapshot returns a copy of the buffered history. Used by tests and
// diagnostic endpoints; live streaming goes through Subscribe.
func (b *buildLogBuffer) Snapshot() []BuildLogEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BuildLogEvent, len(b.events))
	copy(out, b.events)
	return out
}

// appendBuildLog is the Manager-level entry point used by the step executor.
// Safe to call with an unknown buildVMID — a no-op rather than an error so
// callers don't need to know whether the build is registered.
func (m *Manager) appendBuildLog(buildVMID string, ev BuildLogEvent) {
	m.buildsMu.RLock()
	rec, ok := m.builds[buildVMID]
	m.buildsMu.RUnlock()
	if !ok || rec.logs == nil {
		return
	}
	rec.logs.Append(ev)
}

// subscribeBuildLogs opens a subscription on a build's log stream. Returns
// (channel, unsubscribe, ok) where ok=false when the build is unknown.
func (m *Manager) subscribeBuildLogs(buildVMID string) (<-chan BuildLogEvent, func(), bool) {
	m.buildsMu.RLock()
	rec, ok := m.builds[buildVMID]
	m.buildsMu.RUnlock()
	if !ok || rec.logs == nil {
		return nil, nil, false
	}
	ch, unsub := rec.logs.Subscribe()
	return ch, unsub, true
}
