package actor

import (
	"context"
	"sync"
)

// Chunk is one ordered piece of an Actor's output stream. Seq is a monotonic
// sequence the Actor stamps so a relay can dedup replays across a wake.
type Chunk struct {
	Seq  int64
	Data []byte
}

// Relay holds an Actor's output stream for a client and SURVIVES the Actor
// pausing/resuming mid-stream (Epic 5.4). The Actor's outbox Appends chunks; the
// client reads them in order via a cursor. When the Actor hibernates the
// upstream simply goes quiet — the client's read blocks but the stream stays
// open (no error, no close). On re-wake the Actor resumes Appending; chunks it
// replays (Seq already seen) are deduped, so the client never sees a gap or a
// duplicate. This is what makes "streaming that survives hibernation" true: the
// break is invisible to the caller.
//
// The edge proxy holds one Relay per in-flight client stream and copies the
// Actor's outbox into Append and the Relay's chunks out to the client socket;
// this type is that relay's core, independent of the proxy wiring.
type Relay struct {
	mu     sync.Mutex
	cond   *sync.Cond
	chunks []Chunk
	last   int64
	closed bool
}

// NewRelay creates an open relay.
func NewRelay() *Relay {
	r := &Relay{}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// Append adds a chunk from the Actor's outbox. Chunks with Seq <= the highest
// already accepted are ignored — so when a resumed Actor replays its outbox from
// a checkpoint, already-delivered output is not duplicated. No-op after Close.
func (r *Relay) Append(seq int64, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || seq <= r.last {
		return
	}
	r.chunks = append(r.chunks, Chunk{Seq: seq, Data: append([]byte(nil), data...)})
	r.last = seq
	r.cond.Broadcast()
}

// Close ends the stream (the turn is done). Pending ReadFrom calls return ok=false.
func (r *Relay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.cond.Broadcast()
}

// ReadFrom returns the first chunk with Seq > afterSeq, blocking until one is
// available. It returns ok=false (no error) when the stream is closed and fully
// drained — a clean end of stream. It returns ctx.Err() if ctx is cancelled
// (e.g. the client disconnected). Crucially, an Actor pausing mid-stream does
// NOT close the relay, so this blocks (stream stays open) rather than ending.
//
// A client streams by looping with a cursor:
//
//	cur := int64(0)
//	for {
//	    c, ok, err := relay.ReadFrom(ctx, cur)
//	    if err != nil || !ok { break }
//	    send(c.Data); cur = c.Seq
//	}
func (r *Relay) ReadFrom(ctx context.Context, afterSeq int64) (Chunk, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Wake a blocked Wait when ctx is cancelled.
	stop := context.AfterFunc(ctx, func() {
		r.mu.Lock()
		r.cond.Broadcast()
		r.mu.Unlock()
	})
	defer stop()

	for {
		for _, c := range r.chunks {
			if c.Seq > afterSeq {
				return c, true, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return Chunk{}, false, err
		}
		if r.closed {
			return Chunk{}, false, nil // clean end of stream
		}
		r.cond.Wait()
	}
}

// LastSeq returns the highest sequence accepted (for the Actor to resume its
// outbox replay just past it on wake).
func (r *Relay) LastSeq() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}
