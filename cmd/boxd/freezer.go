package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Correcting the wall clock on wake (clock.go) closes most of the problem with
// a frozen restore, but not all of it: between the vCPUs resuming and boxd's
// first health check, the customer's processes are already running on the
// stale clock. The freezer cgroup closes that gap. Every process boxd spawns
// is placed in one cgroup; the supervisor asks boxd to freeze it just before a
// snapshot, so the image is taken with the workload stopped and only boxd
// runnable. On wake nothing but boxd runs until the clock is right, and the
// health check that reports ready is what thaws it.
//
// The guest kernel predates the cgroup v2 freezer, so this is the v1 one,
// mounted by the init script at cgroupFreezerDir.

// cgroupFreezerDir is the workload cgroup the init script creates.
const cgroupFreezerDir = "/sys/fs/cgroup/freezer/workload"

// defaultFreezeBudget bounds how long a freeze may wait for every task to stop.
// A task in uninterruptible I/O cannot be frozen until it returns, and the
// supervisor is holding a pause open while it waits — so on timeout the freeze
// is undone and reported as failed, and the supervisor takes the slower path.
const defaultFreezeBudget = 2 * time.Second

// freezerFS is the cgroup as a handful of files, so the sequencing can be
// tested against a fake that stalls in FREEZING for a while.
type freezerFS interface {
	readState() (string, error)
	writeState(string) error
	addProc(pid int) error
}

type cgroupFS struct{ dir string }

func (c cgroupFS) readState() (string, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, "freezer.state"))
	return strings.TrimSpace(string(b)), err
}

func (c cgroupFS) writeState(s string) error {
	return os.WriteFile(filepath.Join(c.dir, "freezer.state"), []byte(s), 0)
}

func (c cgroupFS) addProc(pid int) error {
	return os.WriteFile(filepath.Join(c.dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
}

type freezer struct {
	fs freezerFS
	// mu serialises a freeze against in-flight spawns: a child exists from
	// Start() until place() puts it in the cgroup, and a freeze that ran in
	// that gap would miss it. Spawns hold it shared, a freeze exclusively.
	mu sync.RWMutex
	// unplaced holds the pid of every live process that could not be put in
	// the cgroup. While any exists a freeze would leave it running on the
	// stale clock, so the freeze refuses and the supervisor takes the slower
	// path. Entries leave when the process exits.
	unplaced sync.Map
	warned   sync.Once
}

func newFreezer(fs freezerFS) *freezer { return &freezer{fs: fs} }

// A nil *freezer means no freezer is configured: every operation is a no-op
// and a freeze is refused, exactly as when the cgroup is absent. Spawning and
// readiness must keep working in that state, so the methods below accept nil.

// spawnLock brackets Start()-then-place() so a freeze cannot run between them.
func (f *freezer) spawnLock() {
	if f != nil {
		f.mu.RLock()
	}
}

func (f *freezer) spawnUnlock() {
	if f != nil {
		f.mu.RUnlock()
	}
}

// available reports whether the cgroup exists at all. An image whose init did
// not mount the freezer has nothing to freeze; every operation degrades to the
// slower path rather than failing the guest.
func (f *freezer) available() bool {
	if f == nil {
		return false
	}
	_, err := f.fs.readState()
	return err == nil
}

// place puts a just-started process in the workload cgroup. Called with the
// spawn lock held shared so a freeze cannot run between Start() and here.
func (f *freezer) place(pid int) {
	if f == nil {
		return
	}
	if err := f.fs.addProc(pid); err != nil {
		f.unplaced.Store(pid, struct{}{})
		f.warned.Do(func() {
			log.Printf("freezer: could not place pid %d in %s; freezes will be refused while it runs: %v", pid, cgroupFreezerDir, err)
		})
	}
}

// exited forgets a process that place() could not put in the cgroup.
func (f *freezer) exited(pid int) {
	if f != nil {
		f.unplaced.Delete(pid)
	}
}

// freeze stops every process in the cgroup and waits until the kernel reports
// them all stopped, or the context expires — in which case it thaws what it
// started and reports failure, so the caller never snapshots a half-frozen
// workload believing it is safe.
func (f *freezer) freeze(ctx context.Context) error {
	if f == nil {
		return errors.New("no freezer configured")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.available() {
		return errors.New("freezer cgroup unavailable")
	}
	var stragglers []string
	f.unplaced.Range(func(k, _ any) bool {
		stragglers = append(stragglers, strconv.Itoa(k.(int)))
		return true
	})
	if len(stragglers) > 0 {
		return fmt.Errorf("%d process(es) outside the freezer cgroup: %s", len(stragglers), strings.Join(stragglers, ","))
	}

	if err := f.fs.writeState("FROZEN"); err != nil {
		return fmt.Errorf("request freeze: %w", err)
	}
	// The state file reads FREEZING until every task has stopped; poll densely
	// at first so a workload that stops in a millisecond is not charged the
	// poll interval, then back off.
	interval := time.Millisecond
	for {
		st, err := f.fs.readState()
		if err != nil {
			_ = f.fs.writeState("THAWED")
			return fmt.Errorf("read freezer state: %w", err)
		}
		if st == "FROZEN" {
			return nil
		}
		select {
		case <-ctx.Done():
			_ = f.fs.writeState("THAWED")
			return fmt.Errorf("workload did not freeze within budget (state %q): %w", st, ctx.Err())
		case <-time.After(interval):
		}
		interval = min(interval*2, 10*time.Millisecond)
	}
}

// thaw lets the workload run. Idempotent and best-effort by design: the only
// callers are the ready path, which must not fail readiness over it, and the
// supervisor undoing a freeze after a snapshot that did not happen.
func (f *freezer) thaw() error {
	if !f.available() {
		return nil
	}
	st, err := f.fs.readState()
	if err != nil {
		return err
	}
	if st == "THAWED" {
		return nil
	}
	return f.fs.writeState("THAWED")
}

// POST /freeze — stop the workload ahead of a snapshot.
//
//	{"budget_ms": 2000}   // optional
//
// 200 when every task is stopped; 503 when this guest cannot freeze (no
// cgroup, or a process outside it); 504 when the budget ran out, in which case
// the workload has already been thawed again.
func (f *freezer) handleFreeze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	budget := defaultFreezeBudget
	var body struct {
		BudgetMs int64 `json:"budget_ms"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.BudgetMs > 0 {
		budget = time.Duration(body.BudgetMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()

	if err := f.freeze(ctx); err != nil {
		code := http.StatusServiceUnavailable
		if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		log.Printf("freezer: freeze refused: %v", err)
		http.Error(w, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// POST /thaw — undo a freeze whose snapshot did not happen.
func (f *freezer) handleThaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := f.thaw(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
