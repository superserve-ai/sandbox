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

// Between the vCPUs resuming and the first health check, the workload would
// run on the stale clock. So every process boxd spawns lives in one freezer
// cgroup, the supervisor freezes it just before a snapshot, and the health
// check that reports ready thaws it. cgroup v1: the guest kernel predates v2.

// cgroupFreezerDir is the workload cgroup the init script creates.
const cgroupFreezerDir = "/sys/fs/cgroup/freezer/workload"

// defaultFreezeBudget bounds the wait for every task to stop; a task in
// uninterruptible I/O cannot be frozen until it returns.
const defaultFreezeBudget = 2 * time.Second

// freezerFS is the cgroup as files, so sequencing is testable against a fake.
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
	// mu: spawns hold it shared from Start() until placement; a freeze holds
	// it exclusively, so it cannot run in that gap and miss a child.
	mu sync.RWMutex
	// unplaced: live pids that could not be put in the cgroup. A freeze is
	// refused while any exist, since they would keep running.
	unplaced sync.Map
	warned   sync.Once
}

func newFreezer(fs freezerFS) *freezer { return &freezer{fs: fs} }

// A nil *freezer means none is configured: no-ops, and a freeze is refused.

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

func (f *freezer) available() bool {
	if f == nil {
		return false
	}
	_, err := f.fs.readState()
	return err == nil
}

// place puts a just-started process in the workload cgroup.
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

func (f *freezer) exited(pid int) {
	if f != nil {
		f.unplaced.Delete(pid)
	}
}

// freeze stops the cgroup and waits until the kernel reports every task
// stopped. On timeout it thaws what it started and fails, so a caller never
// snapshots a half-frozen workload.
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
	// FREEZING until every task has stopped; poll densely, then back off.
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

// thaw lets the workload run. Idempotent; a no-op without a cgroup.
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

// POST /freeze {"budget_ms": N}: 200 frozen; 503 cannot freeze; 504 budget
// exhausted (already thawed again).
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

// POST /thaw: undo a freeze whose snapshot did not happen.
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
