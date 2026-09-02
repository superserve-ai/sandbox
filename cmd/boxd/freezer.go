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

// placementWait bounds the wait for a spawned process to appear in the cgroup.
var placementWait = 50 * time.Millisecond

// errThawUnconfirmed: a thaw was attempted and could not be confirmed.
var errThawUnconfirmed = errors.New("thaw not confirmed")

// freezerFS is the cgroup as files, so sequencing is testable against a fake.
type freezerFS interface {
	readState() (string, error)
	writeState(string) error
	// procCgroup returns the freezer cgroup path of a live process, e.g. "/workload".
	procCgroup(pid int) (string, error)
}

type cgroupFS struct{ dir string }

func (c cgroupFS) readState() (string, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, "freezer.state"))
	return strings.TrimSpace(string(b)), err
}

func (c cgroupFS) writeState(s string) error {
	return os.WriteFile(filepath.Join(c.dir, "freezer.state"), []byte(s), 0)
}

func (c cgroupFS) procCgroup(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		// hierarchy-ID:controllers:path
		if i := strings.Index(line, ":freezer:"); i >= 0 {
			return line[i+len(":freezer:"):], nil
		}
	}
	return "", errors.New("no freezer hierarchy")
}

type freezer struct {
	fs  freezerFS
	dir string
	// mu: spawns hold it shared from Start() until placement is confirmed; a
	// freeze holds it exclusively, so it cannot run in that gap.
	mu sync.RWMutex
	// unplaced: live pids not confirmed in the cgroup. A freeze is refused
	// while any exist, since they would keep running.
	unplaced sync.Map
	warned   sync.Once
}

func newFreezer(fs freezerFS, dir string) *freezer { return &freezer{fs: fs, dir: dir} }

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

// mounted: absent (degrade) versus present but unreadable (error).
func (f *freezer) mounted() (bool, error) {
	if f == nil {
		return false, nil
	}
	_, err := f.fs.readState()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

func (f *freezer) available() bool {
	ok, _ := f.mounted()
	return ok
}

// wrap makes the command join the cgroup before exec, so descendants inherit
// it. Passthrough without a cgroup.
func (f *freezer) wrap(name string, args []string) (string, []string) {
	if !f.available() {
		return name, args
	}
	// $0 is the command, "$@" its arguments; the shell's pid becomes the
	// command's pid on exec. A failed write is left to confirmPlaced to catch.
	script := "echo $$ > " + filepath.Join(f.dir, "cgroup.procs") + " 2>/dev/null; exec \"$0\" \"$@\""
	return "/bin/sh", append([]string{"-c", script, name}, args...)
}

// confirmPlaced waits for a just-started process to appear in the cgroup.
// Called with the spawn lock held shared.
func (f *freezer) confirmPlaced(pid int) {
	if f == nil || !f.available() {
		return
	}
	want := "/" + filepath.Base(f.dir)
	deadline := time.Now().Add(placementWait)
	var last string
	var lastErr error
	for {
		last, lastErr = f.fs.procCgroup(pid)
		if lastErr == nil && last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	f.unplaced.Store(pid, struct{}{})
	f.warned.Do(func() {
		log.Printf("freezer: pid %d not in %s (in %q, err %v); freezes refused while it runs", pid, want, last, lastErr)
	})
}

// isFrozen: a frozen workload on wake means a frozen-clock restore, so the
// clock must be corrected before anything runs.
func (f *freezer) isFrozen() bool {
	if f == nil {
		return false
	}
	st, err := f.fs.readState()
	return err == nil && st != "THAWED"
}

// wakeLoop corrects the clock and thaws a frozen workload without depending
// on /health being polled.
func (f *freezer) wakeLoop(ctx context.Context, clock *wallClock, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !f.isFrozen() {
			continue
		}
		if _, ready := clock.sync(true); ready {
			if err := f.thaw(); err != nil {
				log.Printf("freezer: thaw after clock correction failed: %v", err)
			}
		}
	}
}

func (f *freezer) exited(pid int) {
	if f != nil {
		f.unplaced.Delete(pid)
	}
}

// freeze stops the cgroup and waits for every task to stop. On timeout it
// thaws; an unconfirmed thaw wraps errThawUnconfirmed.
func (f *freezer) freeze(ctx context.Context) error {
	if f == nil {
		return errors.New("no freezer configured")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if ok, err := f.mounted(); err != nil {
		return fmt.Errorf("freezer cgroup: %w", err)
	} else if !ok {
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
			return f.undo(fmt.Errorf("read freezer state: %w", err))
		}
		if st == "FROZEN" {
			return nil
		}
		select {
		case <-ctx.Done():
			return f.undo(fmt.Errorf("workload did not freeze within budget (state %q): %w", st, ctx.Err()))
		case <-time.After(interval):
		}
		interval = min(interval*2, 10*time.Millisecond)
	}
}

// undo thaws after a failed freeze and folds an unconfirmed thaw into the error.
func (f *freezer) undo(cause error) error {
	if terr := f.thawLocked(); terr != nil {
		return fmt.Errorf("%w; %w: %v", cause, errThawUnconfirmed, terr)
	}
	return cause
}

// thaw lets the workload run and confirms it did. A no-op without a cgroup.
func (f *freezer) thaw() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.thawLocked()
}

func (f *freezer) thawLocked() error {
	ok, err := f.mounted()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if st, err := f.fs.readState(); err != nil {
		return err
	} else if st == "THAWED" {
		return nil
	}
	if err := f.fs.writeState("THAWED"); err != nil {
		return err
	}
	st, err := f.fs.readState()
	if err != nil {
		return err
	}
	if st != "THAWED" {
		return fmt.Errorf("state %q after thaw", st)
	}
	return nil
}

// POST /freeze {"budget_ms": N}: 200 frozen; 503 cannot freeze; 504 budget
// exhausted and thawed again; 500 budget exhausted and thaw unconfirmed.
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
		switch {
		case errors.Is(err, errThawUnconfirmed):
			code = http.StatusInternalServerError
		case errors.Is(err, context.DeadlineExceeded):
			code = http.StatusGatewayTimeout
		}
		log.Printf("freezer: freeze refused: %v", err)
		http.Error(w, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// POST /thaw: 200 only once the workload is confirmed running.
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
