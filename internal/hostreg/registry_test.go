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

// hostDB serves GetHost with a switchable vmd_addr.
type hostDB struct {
	mu   sync.Mutex
	addr string
}

func (h *hostDB) setAddr(a string) { h.mu.Lock(); h.addr = a; h.mu.Unlock() }

func (h *hostDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec")
}
func (h *hostDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, fmt.Errorf("unexpected Query")
}
func (h *hostDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	h.mu.Lock()
	addr := h.addr
	h.mu.Unlock()
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
