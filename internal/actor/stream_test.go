package actor

import (
	"context"
	"sync"
	"testing"
	"time"
)

// drain reads the relay to EOF from a fresh cursor and returns the data in order.
func drain(t *testing.T, r *Relay) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out []string
	cur := int64(0)
	for {
		c, ok, err := r.ReadFrom(ctx, cur)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if !ok {
			return out
		}
		out = append(out, string(c.Data))
		cur = c.Seq
	}
}

func TestRelayInOrderThenClose(t *testing.T) {
	r := NewRelay()
	r.Append(1, []byte("a"))
	r.Append(2, []byte("b"))
	r.Append(3, []byte("c"))
	r.Close()
	got := drain(t, r)
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("expected [a b c], got %v", got)
	}
}

// TestRelaySurvivesHibernation: the client is mid-read when the Actor pauses (no
// appends), then resumes. The read must block across the gap (stream stays open)
// and then deliver the post-resume chunk — no error, no premature close.
func TestRelaySurvivesHibernation(t *testing.T) {
	r := NewRelay()
	r.Append(1, []byte("before"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Read the first chunk.
	c1, ok, err := r.ReadFrom(ctx, 0)
	if !ok || err != nil || string(c1.Data) != "before" {
		t.Fatalf("first read: %q ok=%v err=%v", c1.Data, ok, err)
	}

	// Client blocks waiting for the next chunk while the Actor is hibernated.
	type res struct {
		c   Chunk
		ok  bool
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, ok, err := r.ReadFrom(ctx, c1.Seq)
		ch <- res{c, ok, err}
	}()

	// Simulate hibernation: nothing happens for a bit. The reader must NOT
	// return (stream stays open across the pause).
	select {
	case got := <-ch:
		t.Fatalf("reader returned during hibernation (stream broke): %+v", got)
	case <-time.After(150 * time.Millisecond):
	}

	// Actor re-wakes and emits more output.
	r.Append(2, []byte("after"))

	got := <-ch
	if !got.ok || got.err != nil || string(got.c.Data) != "after" {
		t.Fatalf("post-resume read: %q ok=%v err=%v", got.c.Data, got.ok, got.err)
	}
}

// TestRelayDedupsReplay: a resumed Actor replays its outbox from a checkpoint
// (re-emitting earlier seqs). The relay must dedup so the client at cursor=3
// sees only the genuinely-new chunk 4, never a duplicate.
func TestRelayDedupsReplay(t *testing.T) {
	r := NewRelay()
	r.Append(1, []byte("x"))
	r.Append(2, []byte("y"))
	r.Append(3, []byte("z"))

	// Replay from the start (Actor recovered and re-ran steps) — all <= last(3).
	r.Append(1, []byte("x"))
	r.Append(2, []byte("y"))
	r.Append(3, []byte("z"))
	// One genuinely new chunk.
	r.Append(4, []byte("w"))
	r.Close()

	got := drain(t, r)
	if len(got) != 4 {
		t.Fatalf("replay must be deduped to 4 chunks, got %d: %v", len(got), got)
	}
	if got[3] != "w" {
		t.Fatalf("last chunk should be the new one (w), got %q", got[3])
	}
}

func TestRelayCtxCancelUnblocks(t *testing.T) {
	r := NewRelay()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := r.ReadFrom(ctx, 0)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel() // client disconnected
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled read should return ctx error")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock the reader")
	}
}

// TestRelayConcurrent: upstream appends while a client reads (race-detected).
func TestRelayConcurrent(t *testing.T) {
	r := NewRelay()
	const n = 200
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= n; i++ {
			r.Append(int64(i), []byte{byte(i)})
		}
		r.Close()
	}()
	got := drain(t, r)
	wg.Wait()
	if len(got) != n {
		t.Fatalf("client should receive all %d chunks, got %d", n, len(got))
	}
}
