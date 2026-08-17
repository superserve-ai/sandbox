package hostreg

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// hostDB serves GetHost with a switchable vmd_addr, optional read failure,
// and an optional gate that holds reads open while a test interleaves.
type hostDB struct {
	mu       sync.Mutex
	addr     string
	failRead bool
	gate     chan struct{} // non-nil: QueryRow waits until closed
	reads    atomic.Int64
}

func (h *hostDB) setAddr(a string) { h.mu.Lock(); h.addr = a; h.mu.Unlock() }
func (h *hostDB) setFailRead(v bool) {
	h.mu.Lock()
	h.failRead = v
	h.mu.Unlock()
}
func (h *hostDB) setGate(c chan struct{}) { h.mu.Lock(); h.gate = c; h.mu.Unlock() }

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

func (h *hostDB) readCount() int64 { return h.reads.Load() }

func (h *hostDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}
func (h *hostDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, fmt.Errorf("unexpected Query")
}
func (h *hostDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	h.reads.Add(1)
	h.mu.Lock()
	addr, fail, gate := h.addr, h.failRead, h.gate
	h.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if fail {
		return errRow{err: fmt.Errorf("connection reset")}
	}
	id := args[0].(string)
	return hostScanRow(func(dest ...any) error {
		*dest[0].(*string) = id
		*dest[1].(*string) = addr
		*dest[2].(*string) = "proxy:5007"
		*dest[3].(*string) = "region-a"
		*dest[4].(*string) = "active"
		*dest[5].(*int32) = 1024
		*dest[6].(*int32) = 8
		*dest[7].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: time.Now(), Valid: true}
		*dest[8].(*time.Time) = time.Now()
		*dest[9].(*time.Time) = time.Now()
		return nil
	})
}

type hostScanRow func(...any) error

func (r hostScanRow) Scan(dest ...any) error { return r(dest...) }

// A client whose host row changed address must be re-dialed BEFORE the next
// dispatch once its recheck is due — never returned pointing at the old
// machine. The address change lands on whichever control-plane replica
// served the heartbeat; every other replica converges through this check.
func TestClientForRedialsBeforeDispatchWhenAddressChanges(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	var lastAddr atomic.Value
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		lastAddr.Store(addr)
		return nil, nil // client value is irrelevant to the registry's bookkeeping
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("first ClientFor: %v", err)
	}
	if dials.Load() != 1 || lastAddr.Load().(string) != "10.0.0.1:50051" {
		t.Fatalf("first dial = %d/%v", dials.Load(), lastAddr.Load())
	}

	store.setAddr("10.0.0.2:50051")
	time.Sleep(5 * time.Millisecond) // entry is now due for verification

	// Blocking semantics: this single call must verify and re-dial.
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("ClientFor after address change: %v", err)
	}
	if dials.Load() != 2 || lastAddr.Load().(string) != "10.0.0.2:50051" {
		t.Fatalf("after change: dials = %d addr = %v, want 2 dials at the new address",
			dials.Load(), lastAddr.Load())
	}
}

// An unchanged address must refresh the recheck clock without re-dialing:
// steady state stays at one dial no matter how many verifications run.
func TestClientForKeepsClientWhenAddressUnchanged(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	for i := 0; i < 20; i++ {
		if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
			t.Fatalf("ClientFor %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1 (verification must not re-dial an unchanged address)", dials.Load())
	}
}

// A COLD dial (no cached entry) raced by an invalidation must also discard
// its result: the row was read before the reclaim committed, so the dialed
// client points at the old machine. The resolution re-reads and returns a
// client for the newest address — the caller never receives the old one.
func TestClientForColdDialRacedByInvalidateReturnsNewestAddress(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var mu sync.Mutex
	var dialed []string
	dialStarted := make(chan struct{})
	dialRelease := make(chan struct{})
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if addr == "10.0.0.1:50051" {
			close(dialStarted)
			<-dialRelease // hold the cold dial open while the reclaim lands
		}
		return nil, nil
	}
	r := New(db.New(store), dial)

	done := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(context.Background(), "host-a")
		done <- err
	}()

	<-dialStarted // resolution read .1 and is dialing it
	store.setAddr("10.0.0.2:50051")
	r.Invalidate("host-a") // the reclaim to .2 commits mid-dial
	close(dialRelease)

	if err := <-done; err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), dialed...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "10.0.0.1:50051" || got[1] != "10.0.0.2:50051" {
		t.Fatalf("dial sequence = %v, want [.1 discarded, .2 returned]", got)
	}
	// The settled entry serves the newest address without another dial.
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("post-race ClientFor: %v", err)
	}
	mu.Lock()
	n := len(dialed)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("dials after settle = %d, want 2", n)
	}
}

// A transient read failure with NO invalidation keeps the availability
// softness: the still-cached client is returned rather than failing the op.
func TestClientForServesCachedOnReadBlipWithoutInvalidation(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	store.setFailRead(true)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("read blip must serve the cached client, got error: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

// Sustained read failure must not become a read (and a warning) per call:
// the failed verification backs off, serving the cached client without
// touching the DB until the backoff lapses.
func TestClientForBacksOffFailedVerification(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)
	r.recheck = 100 * time.Millisecond // backoff = min(5s, ttl) = 100ms

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Expire the entry and break the DB.
	r.mu.Lock()
	e := r.clients["host-a"]
	e.checkedAt = time.Now().Add(-time.Second)
	r.clients["host-a"] = e
	r.mu.Unlock()
	store.setFailRead(true)

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("degraded ClientFor: %v", err)
	}
	after := store.readCount() // seed read + 1 failed verification

	// Immediate repeat calls stay inside the backoff: zero further reads.
	for i := 0; i < 10; i++ {
		if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
			t.Fatalf("backoff ClientFor %d: %v", i, err)
		}
	}
	if got := store.readCount(); got != after {
		t.Fatalf("reads during backoff = %d, want %d (no per-call reads)", got, after)
	}

	// Past the backoff, verification is retried again.
	time.Sleep(120 * time.Millisecond)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("post-backoff ClientFor: %v", err)
	}
	if got := store.readCount(); got != after+1 {
		t.Fatalf("reads after backoff = %d, want %d (one paced retry)", got, after+1)
	}
}

// A read failure AFTER the entry was invalidated must fail closed: the
// invalidation had a reason (an address reclaim), and dispatching the
// pre-invalidation client past it risks the machine that lost the identity.
func TestClientForFailsClosedWhenInvalidatedAndRowUnreadable(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	gate := make(chan struct{})
	store.setGate(gate)
	store.setFailRead(true)

	done := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(context.Background(), "host-a")
		done <- err
	}()
	// The verification read is in flight (or about to be); land the
	// invalidation, then let the read fail.
	time.Sleep(2 * time.Millisecond)
	r.Invalidate("host-a")
	close(gate)

	if err := <-done; err == nil {
		t.Fatal("invalidated entry with unreadable row must fail closed, got a client")
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1 (nothing new may be dialed through a failed verification)", dials.Load())
	}
}

// An Invalidate landing while a verification dial is in flight must not be
// undone by that verification's store: the result is discarded and the row
// re-read, so the entry lands on the newest address, never the one that was
// current when the verification began.
func TestClientForDiscardsVerificationRacedByInvalidate(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var mu sync.Mutex
	var dialed []string
	dialStarted := make(chan struct{})
	dialRelease := make(chan struct{})
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if addr == "10.0.0.2:50051" {
			close(dialStarted)
			<-dialRelease // hold the dial open while the invalidation lands
		}
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed ClientFor: %v", err)
	}
	store.setAddr("10.0.0.2:50051")
	time.Sleep(5 * time.Millisecond) // entry due for verification

	done := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(context.Background(), "host-a")
		done <- err
	}()

	<-dialStarted // verification has read .2 and is dialing it
	store.setAddr("10.0.0.3:50051")
	r.Invalidate("host-a") // the reclaim to .3 lands mid-dial
	close(dialRelease)

	if err := <-done; err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), dialed...)
	mu.Unlock()
	want := []string{"10.0.0.1:50051", "10.0.0.2:50051", "10.0.0.3:50051"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("dial sequence = %v, want %v (raced dial discarded, row re-read)", got, want)
	}

	// The cache must hold the newest address as verified — an immediate call
	// dials nothing new.
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("post-race ClientFor: %v", err)
	}
	mu.Lock()
	n := len(dialed)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("dials after settle = %d, want 3 (entry must be cached at the newest address)", n)
	}
}

// When the address changed but the new machine cannot be dialed, ClientFor
// must fail loudly — never quietly hand back the old-address client, which
// would execute the operation on the machine that lost this identity.
func TestClientForFailsClosedWhenNewAddressUndialable(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	var failDial atomic.Bool
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		if failDial.Load() {
			return nil, fmt.Errorf("connection refused")
		}
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("first ClientFor: %v", err)
	}

	store.setAddr("10.0.0.2:50051")
	failDial.Store(true)
	time.Sleep(5 * time.Millisecond)

	if _, err := r.ClientFor(context.Background(), "host-a"); err == nil {
		t.Fatal("ClientFor returned a client while the new address is undialable")
	}

	// Recovery: once the new machine is reachable, the next call succeeds.
	failDial.Store(false)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("ClientFor after recovery: %v", err)
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("dials = %d, want 3 (initial, failed re-dial, recovery)", got)
	}
}
