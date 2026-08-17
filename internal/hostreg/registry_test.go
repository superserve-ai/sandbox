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

// A cached client whose host row changed address must be evicted within one
// recheck interval — the address change happens on whichever control-plane
// replica served the heartbeat, and every other replica converges through
// this recheck rather than dialing the old machine forever.
func TestClientForEvictsWhenRowAddressChanges(t *testing.T) {
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

	// Row address changes (identity reclaimed elsewhere). Stale-serve means
	// the very next call may still return the old client, but the recheck it
	// triggers must evict, and a following call re-dials the new address.
	store.setAddr("10.0.0.2:50051")
	deadline := time.Now().Add(2 * time.Second)
	for {
		time.Sleep(2 * time.Millisecond)
		if _, err := r.ClientFor(context.Background(), "host-a"); err != nil {
			t.Fatalf("ClientFor: %v", err)
		}
		if dials.Load() >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cached client never evicted after address change; dials = %d", dials.Load())
		}
	}
	if got := lastAddr.Load().(string); got != "10.0.0.2:50051" {
		t.Fatalf("re-dial went to %q, want the new address", got)
	}
}

// An unchanged address must refresh the recheck clock without evicting:
// steady state stays at one dial no matter how many calls arrive.
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
		t.Fatalf("dials = %d, want 1 (rechecks must not re-dial an unchanged address)", dials.Load())
	}
}
