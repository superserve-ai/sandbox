package hostreg

import (
	"context"
	"fmt"
	"runtime"
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
		*dest[10].(*bool) = false
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
// softness while the last successful verification is within the lease: the
// still-cached client is returned rather than failing the op.
func TestClientForServesCachedOnReadBlipWithinLease(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = 100 * time.Millisecond // lease = 200ms

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Verification due now, but the last successful verification is
	// recent: within the lease.
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now()
	r.clients["host-a"] = e
	r.mu.Unlock()
	store.setFailRead(true)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("read blip within lease must serve the cached client, got error: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

// Past the unverified lease, a failing row read fails CLOSED: "we could not
// check" must not keep dispatching forever to a machine that may have lost
// the identity. Recovery is immediate once reads succeed again.
func TestClientForFailsClosedPastUnverifiedLease(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = 100 * time.Millisecond // lease = 200ms

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now()
	e.verifiedAt = time.Now().Add(-300 * time.Millisecond)
	r.clients["host-a"] = e
	r.mu.Unlock()
	store.setFailRead(true)
	if _, err := r.ClientFor(context.Background(), "host-a"); err == nil {
		t.Fatal("read failure past the lease must fail closed, got a client")
	}
	store.setFailRead(false)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("recovery after reads resume: %v", err)
	}
}

// Inside the last fifth of the verification window, a fresh call triggers a
// background refresh so the blocking due-verification read almost never
// lands on a request.
func TestClientForRefreshesAheadOfExpiry(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = 300 * time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	reads := store.readCount()
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now().Add(50 * time.Millisecond) // inside the last fifth, still fresh
	r.clients["host-a"] = e
	r.mu.Unlock()

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("fresh call in refresh-ahead window: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for store.readCount() < reads+1 {
		if time.Now().After(deadline) {
			t.Fatal("background refresh never read the row")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// The refresh renewed the entry: an immediate call neither reads nor dials.
	after := store.readCount()
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("post-refresh call: %v", err)
	}
	if store.readCount() != after || dials.Load() != 1 {
		t.Fatalf("post-refresh reads/dials = %d/%d, want %d/1", store.readCount(), dials.Load(), after)
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
	e.nextCheckAt = time.Now().Add(-time.Second)
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

// A caller whose request is canceled must stop waiting for a slow
// resolution immediately; the shared resolution finishes on its detached
// context and still fills the cache for the callers that follow.
func TestClientForCanceledCallerStopsWaiting(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	gate := make(chan struct{})
	store.setGate(gate) // hold the row read open: resolution is slow
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(ctx, "host-a")
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled caller got a client, want context error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled caller still waiting on the shared resolution")
	}

	// The abandoned resolution completes and caches; the next caller is
	// served without a new resolution.
	store.setGate(nil)
	close(gate)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := r.ClientFor(context.Background(), "host-a"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resolution never completed after the caller abandoned it")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// With the production ratio (backoff ≪ TTL), a failed verification must NOT
// re-fire through refresh-ahead: after a failure, the entry sits inside what
// would be the refresh-ahead window, and only the backoff may schedule the
// next read. Repeated calls during the backoff do zero reads.
func TestClientForFailureSuppressesRefreshAhead(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)
	r.recheck = 300 * time.Millisecond
	r.failBackoff = 50 * time.Millisecond // production shape: backoff ≪ TTL

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now()
	r.clients["host-a"] = e
	r.mu.Unlock()
	store.setFailRead(true)

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("degraded ClientFor: %v", err)
	}
	after := store.readCount()
	// nextCheckAt = now+50ms, which is deep inside the 60ms refresh-ahead
	// margin — the old clock arithmetic would fire a read per call here.
	for i := 0; i < 10; i++ {
		if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
			t.Fatalf("backoff ClientFor %d: %v", i, err)
		}
	}
	// Give any (wrong) async refresh a moment to land before asserting.
	time.Sleep(20 * time.Millisecond)
	if got := store.readCount(); got != after {
		t.Fatalf("reads during backoff = %d, want %d (refresh-ahead must stay suppressed while degraded)", got, after)
	}
}

// The fast path itself enforces the lease: a failure backoff that outlives
// the lease must not keep serving — the next call goes to resolution and
// fails closed while reads are still failing.
func TestClientForFastPathHonorsLeaseDuringBackoff(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)
	r.recheck = 100 * time.Millisecond // lease = 200ms
	r.failBackoff = 80 * time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Verification due; lease nearly exhausted (30ms left of 200ms).
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now()
	e.verifiedAt = time.Now().Add(-170 * time.Millisecond)
	r.clients["host-a"] = e
	r.mu.Unlock()
	store.setFailRead(true)

	// Within lease: served, and an 80ms backoff window opens.
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("within-lease ClientFor: %v", err)
	}
	// 40ms later the backoff is still open but the lease has expired: the
	// fast path must refuse and resolution must fail closed.
	time.Sleep(40 * time.Millisecond)
	if _, err := r.ClientFor(context.Background(), "host-a"); err == nil {
		t.Fatal("lease expired mid-backoff: dispatch must fail closed, got a client")
	}
}

// Refresh-ahead launches ONE background goroutine per host, no matter how
// many warm calls land in the refresh window while the read is slow —
// singleflight dedupes the read, but only this guard bounds the goroutines
// parked behind it.
func TestClientForRefreshAheadLaunchesOneGoroutine(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)
	r.recheck = 300 * time.Millisecond

	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r.mu.Lock()
	e := r.clients["host-a"]
	e.nextCheckAt = time.Now().Add(30 * time.Millisecond) // inside the refresh window, still fresh
	r.clients["host-a"] = e
	r.mu.Unlock()

	gate := make(chan struct{})
	store.setGate(gate) // the background read parks until released
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
			t.Fatalf("warm ClientFor %d: %v", i, err)
		}
	}
	after := runtime.NumGoroutine()
	if after-before > 5 {
		t.Fatalf("goroutines grew by %d during a slow refresh, want ≤ 5 (one refresh per host)", after-before)
	}
	store.setGate(nil)
	close(gate)
	// Let the refresh finish so it doesn't leak into other tests.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, loaded := r.refreshing.Load("host-a"); !loaded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh goroutine never finished")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Observe fires once per EXECUTED resolution — never per waiter. A burst of
// callers sharing one gated flight contributes exactly one sample, and a
// caller that cancels its wait records nothing: the sample belongs to the
// resolution (which succeeds behind the canceled waiter), not the waiters.
func TestObserveRecordsPerResolutionNotPerWaiter(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	gate := make(chan struct{})
	store.setGate(gate) // hold the flight's row read open
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)

	var mu sync.Mutex
	type sample struct {
		kind string
		err  error
	}
	var samples []sample
	r.Observe = func(kind string, _ time.Duration, err error) {
		mu.Lock()
		samples = append(samples, sample{kind, err})
		mu.Unlock()
	}

	// Ten cold waiters share one flight; one of them cancels mid-wait.
	cancelCtx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		ctx := context.Background()
		if i == 0 {
			ctx = cancelCtx
		}
		wg.Add(1)
		go func(ctx context.Context) {
			defer wg.Done()
			_, _ = r.ClientFor(ctx, "host-a")
		}(ctx)
	}
	time.Sleep(20 * time.Millisecond) // let the waiters pile onto the flight
	cancel()
	close(gate)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(samples) != 1 {
		t.Fatalf("samples = %d (%v), want exactly 1 per executed resolution", len(samples), samples)
	}
	if samples[0].kind != "cold" || samples[0].err != nil {
		t.Fatalf("sample = %+v, want cold/success (the canceled waiter must not record an error)", samples[0])
	}
}

// A caller that has just read the host row hands the address to the
// registry: a cached client at that address has its lease renewed without a
// row read of its own, so the dispatch that follows never blocks on one.
func TestMarkVerifiedRenewsLeaseWithoutRead(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)
	r.recheck = time.Millisecond
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil { // cold: read + dial
		t.Fatalf("prime: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // lease due; ClientFor alone would read again

	r.MarkVerified(context.Background(), "host-a", "10.0.0.1:50051")
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("ClientFor after MarkVerified: %v", err)
	}
	if n := store.readCount(); n != 1 {
		t.Fatalf("reads = %d, want 1 (MarkVerified must renew the lease without a read)", n)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

// With no client yet, MarkVerified resolves up front (one read, one dial) so
// the first dispatch on a fresh process finds a verified client waiting.
func TestMarkVerifiedColdResolvesOnce(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dials atomic.Int64
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) {
		dials.Add(1)
		return nil, nil
	}
	r := New(db.New(store), dial)

	r.MarkVerified(context.Background(), "host-a", "10.0.0.1:50051")
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	if n := store.readCount(); n != 1 {
		t.Fatalf("reads = %d, want 1", n)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1", dials.Load())
	}
}

// The row just reported a new address: the client at the old one must not
// survive as a within-lease fallback when the re-resolution's read fails.
func TestMarkVerifiedMovedAddressFailsClosedWhenReadFails(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	dial := func(_, _ string, _ func()) (vmdclient.Client, error) { return nil, nil }
	r := New(db.New(store), dial)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	store.setFailRead(true)
	r.MarkVerified(context.Background(), "host-a", "10.0.0.2:50051")
	if _, err := r.ClientFor(context.Background(), "host-a"); err == nil {
		t.Fatal("ClientFor served the client at the old address after the row reported a move")
	}
}

// A moved address re-resolves: one read, one fresh dial, and the next
// dispatch goes to the new machine without a further read.
func TestMarkVerifiedMovedAddressRedials(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var dialed []string
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		dialed = append(dialed, addr)
		return nil, nil
	}
	r := New(db.New(store), dial)
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	store.setAddr("10.0.0.2:50051")
	r.MarkVerified(context.Background(), "host-a", "10.0.0.2:50051")
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("ClientFor after move: %v", err)
	}
	if want := []string{"10.0.0.1:50051", "10.0.0.2:50051"}; fmt.Sprint(dialed) != fmt.Sprint(want) {
		t.Fatalf("dialed = %v, want %v", dialed, want)
	}
	if n := store.readCount(); n != 2 {
		t.Fatalf("reads = %d, want 2 (prime + the move's re-resolution)", n)
	}
}

// A cold lookup that read the row before the host moved must not publish
// that older address over a verification that observed the move while the
// lookup was still dialing: MarkVerified supersedes it even with no client
// cached, so the lookup re-reads and the newest address is what settles.
func TestMarkVerifiedSupersedesColdLookupThatReadTheOldAddress(t *testing.T) {
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
			<-dialRelease // hold the cold dial open while the move is observed
		}
		return nil, nil
	}
	r := New(db.New(store), dial)

	lookup := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(context.Background(), "host-a")
		lookup <- err
	}()
	<-dialStarted // the lookup read .1 and is dialing it
	store.setAddr("10.0.0.2:50051")

	verified := make(chan struct{})
	go func() {
		r.MarkVerified(context.Background(), "host-a", "10.0.0.2:50051") // joins the lookup in flight
		close(verified)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for { // MarkVerified bumps the generation before it joins; wait for that
		r.mu.RLock()
		gen := r.gens["host-a"]
		r.mu.RUnlock()
		if gen > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("MarkVerified never superseded the in-flight lookup")
		}
		time.Sleep(time.Millisecond)
	}
	close(dialRelease)

	if err := <-lookup; err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	<-verified
	mu.Lock()
	got := append([]string(nil), dialed...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "10.0.0.1:50051" || got[1] != "10.0.0.2:50051" {
		t.Fatalf("dial sequence = %v, want [.1 discarded, .2 published]", got)
	}
	r.mu.RLock()
	settled := r.clients["host-a"].addr
	r.mu.RUnlock()
	if settled != "10.0.0.2:50051" {
		t.Fatalf("settled address = %q, want the newer .2", settled)
	}
}

// Concurrent verifications that all report the same, unchanged address must
// coalesce: a cold lookup has two attempts, and if every report superseded
// it the lookup would fail with a spurious address flap on a healthy host.
func TestConcurrentSameAddressVerificationsDoNotStarveColdLookup(t *testing.T) {
	store := &hostDB{addr: "10.0.0.1:50051"}
	var mu sync.Mutex
	var dialed []string
	dialStarted := make(chan struct{})
	dialRelease := make(chan struct{})
	var once sync.Once
	dial := func(_, addr string, _ func()) (vmdclient.Client, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		once.Do(func() {
			close(dialStarted)
			<-dialRelease // hold the first dial open while the reports land
		})
		return nil, nil
	}
	r := New(db.New(store), dial)

	lookup := make(chan error, 1)
	go func() {
		_, err := r.ClientFor(context.Background(), "host-a")
		lookup <- err
	}()
	<-dialStarted

	var verified sync.WaitGroup
	for i := 0; i < 3; i++ {
		verified.Add(1)
		go func() {
			defer verified.Done()
			r.MarkVerified(context.Background(), "host-a", "10.0.0.1:50051")
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for { // the first report supersedes the lookup; the others must not
		r.mu.RLock()
		gen := r.gens["host-a"]
		r.mu.RUnlock()
		if gen > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no report superseded the in-flight lookup")
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 100; i++ {
		runtime.Gosched() // let the remaining reports reach their (no-op) check
	}
	close(dialRelease)

	if err := <-lookup; err != nil {
		t.Fatalf("ClientFor: %v (equivalent reports must not exhaust the lookup)", err)
	}
	verified.Wait()
	r.mu.RLock()
	gen, settled := r.gens["host-a"], r.clients["host-a"].addr
	r.mu.RUnlock()
	if gen != 1 {
		t.Fatalf("generation bumps = %d, want exactly 1 for three reports of one address", gen)
	}
	if settled != "10.0.0.1:50051" {
		t.Fatalf("settled address = %q", settled)
	}
	if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
		t.Fatalf("post-settle ClientFor: %v", err)
	}
}
