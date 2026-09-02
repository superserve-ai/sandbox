package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Between the vCPUs resuming and the clock being corrected, the workload would
// run on the stale clock. So every process boxd spawns lives in one freezer
// cgroup, and the supervisor drives an explicit protocol around a snapshot:
//
//	/freeze  stop the workload; it stays stopped until told otherwise
//	/thaw    the snapshot did not happen; release it
//	/wake    restored; correct the clock per the supervisor's policy, then release
//
// Nothing in the guest releases the workload on its own: from inside, "about
// to be snapshotted" and "just restored" look identical. cgroup v1: the guest
// kernel predates v2.

// cgroupFreezerDir is the workload cgroup the init script creates.
const cgroupFreezerDir = "/sys/fs/cgroup/freezer/workload"

// defaultFreezeBudget bounds the wait for every task to stop; a task in
// uninterruptible I/O cannot be frozen until it returns.
const defaultFreezeBudget = 2 * time.Second

// errThawUnconfirmed: a thaw was attempted and could not be confirmed.
var errThawUnconfirmed = errors.New("thaw not confirmed")

// freezerFS is the cgroup as files, so sequencing is testable against a fake.
type freezerFS interface {
	readState() (string, error)
	writeState(string) error
}

type cgroupFS struct{ dir string }

func (c cgroupFS) readState() (string, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, "freezer.state"))
	return strings.TrimSpace(string(b)), err
}

func (c cgroupFS) writeState(s string) error {
	return os.WriteFile(filepath.Join(c.dir, "freezer.state"), []byte(s), 0)
}

type freezer struct {
	fs  freezerFS
	dir string
	// mounted is fixed at startup: init mounts the cgroup before boxd runs.
	mounted bool
	// mu: spawns hold it shared across Start(); a freeze holds it exclusively.
	mu sync.RWMutex
}

func newFreezer(fs freezerFS, dir string) *freezer {
	f := &freezer{fs: fs, dir: dir}
	if fs != nil {
		_, err := fs.readState()
		f.mounted = err == nil
	}
	return f
}

// A nil *freezer means none is configured: passthrough, and a freeze is refused.

func (f *freezer) available() bool { return f != nil && f.mounted }

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

// wrap makes the command join the cgroup before exec, and refuse to run if it
// cannot: a process outside the cgroup would survive a freeze. The shell's pid
// becomes the command's on exec, so every descendant inherits the placement.
// Passthrough without a cgroup.
func (f *freezer) wrap(name string, args []string) (string, []string) {
	if !f.available() {
		return name, args
	}
	script := "echo $$ > " + filepath.Join(f.dir, "cgroup.procs") + " && exec \"$0\" \"$@\""
	return "/bin/sh", append([]string{"-c", script, name}, args...)
}

func (f *freezer) isFrozen() bool {
	if !f.available() {
		return false
	}
	st, err := f.fs.readState()
	return err == nil && st != "THAWED"
}

// freeze stops the cgroup and waits for every task to stop. On timeout it
// thaws; an unconfirmed thaw wraps errThawUnconfirmed.
func (f *freezer) freeze(ctx context.Context) error {
	if !f.available() {
		return errors.New("freezer cgroup unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

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

func (f *freezer) undo(cause error) error {
	if terr := f.thawLocked(); terr != nil {
		return fmt.Errorf("%w; %w: %v", cause, errThawUnconfirmed, terr)
	}
	return cause
}

// thaw lets the workload run and confirms it did. A no-op without a cgroup.
func (f *freezer) thaw() error {
	if !f.available() {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.thawLocked()
}

func (f *freezer) thawLocked() error {
	st, err := f.fs.readState()
	if err != nil {
		return err
	}
	if st == "THAWED" {
		return nil
	}
	if err := f.fs.writeState("THAWED"); err != nil {
		return err
	}
	if st, err = f.fs.readState(); err != nil {
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

// POST /thaw: the snapshot did not happen. 200 only once confirmed running.
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

// POST /wake {"clock_frozen": bool}: the supervisor restored this guest.
// Correct the clock — required if it was restored frozen — then release the
// workload. 200 ready; 503 with status "clock" or "thaw" otherwise, workload
// left stopped. Idempotent: a woken guest answers 200 again.
func handleWake(clock *wallClock, fz *freezer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ClockFrozen *bool `json:"clock_frozen"`
		}
		if r.Body == nil || json.NewDecoder(r.Body).Decode(&body) != nil || body.ClockFrozen == nil {
			// A wake that does not say whether the clock was frozen releases
			// nothing.
			http.Error(w, "clock_frozen required", http.StatusBadRequest)
			return
		}
		wc, ready := clock.sync(*body.ClockFrozen)
		status := "ok"
		if ready {
			if err := fz.thaw(); err != nil {
				log.Printf("freezer: thaw on wake failed: %v", err)
				ready, status = false, "thaw"
				wc.Error = "thaw: " + err.Error()
			}
		} else {
			status = "clock"
		}
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(struct {
			Status    string          `json:"status"`
			WallClock wallClockStatus `json:"wall_clock"`
		}{Status: status, WallClock: wc})
	}
}

// The lifecycle routes are the supervisor's, on a listener every process in
// the sandbox can reach. A connection from one of the guest's own addresses is
// refused. A root process can still bind another address, so this guards
// against accident, not a boundary.
var localAddrs = net.InterfaceAddrs

func fromGuest(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, err := localAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func hostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fromGuest(r.RemoteAddr) {
			http.Error(w, "supervisor only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
