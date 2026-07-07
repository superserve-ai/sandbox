package vm

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestReattachByID_ConcurrentCallersDedupe pins the guarantee that the eager
// startup pass and lazy request loads, routed through the same singleflight
// group, never run reattachRecord more than once for a given vmID — even when
// they race with different cleanupStale values. Run under -race, it also guards
// the shared m.vms / m.reattachSF access.
func TestReattachByID_ConcurrentCallersDedupe(t *testing.T) {
	s, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer s.Close()

	// Paused record with no namespace/IP: reattachRecord skips the liveness
	// checks and all network work, so no netMgr is needed.
	if err := s.Put(VMRecord{ID: "vm-x", Status: StatusPaused}); err != nil {
		t.Fatalf("put: %v", err)
	}

	mgr := &Manager{
		state: s,
		vms:   make(map[string]*VMInstance),
		log:   zerolog.Nop(),
	}

	var execCount atomic.Int32
	reattachHook = func(string) {
		execCount.Add(1)
		// Hold the in-flight singleflight call open long enough that every
		// concurrent caller joins it instead of starting a fresh flight.
		time.Sleep(100 * time.Millisecond)
	}
	defer func() { reattachHook = nil }()

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*VMInstance, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Mix cleanupStale to mirror eager (true) vs lazy (false) callers.
			results[i] = mgr.reattachByID("vm-x", i%2 == 0)
		}(i)
	}
	close(start)
	wg.Wait()

	if got := execCount.Load(); got != 1 {
		t.Fatalf("reattachRecord ran %d times, want 1 (singleflight must dedupe concurrent callers)", got)
	}
	if len(mgr.vms) != 1 {
		t.Fatalf("m.vms has %d entries, want exactly 1", len(mgr.vms))
	}
	for i, r := range results {
		if r == nil || r != results[0] {
			t.Fatalf("caller %d returned %p, want the single shared instance %p", i, r, results[0])
		}
	}
}
