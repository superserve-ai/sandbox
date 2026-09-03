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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	// frozen mirrors the state this freezer last confirmed, so health can
	// answer without a file read or waiting on a freeze in progress.
	frozen atomic.Bool
	// token is the supervisor's proof that a thaw or wake belongs to the
	// freeze it is releasing; it lives here, so it is in the snapshot. last
	// is the token of the freeze most recently released, so a repeated
	// request after success is answered the same way.
	token, last string
}

var (
	errTokenMismatch = errors.New("freeze token mismatch")
	errTokenConflict = errors.New("another freeze is active")
)

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

// placement is the pipe over which the wrapper reports that it joined the
// cgroup. The spawn lock is held until that report arrives: Start returning
// only proves the shell exists, not that it has placed itself, and a freeze in
// that gap would snapshot a workload running outside the cgroup.
type placement struct {
	r, w *os.File
}

// attach hands the wrapper its end of the pipe as fd 3.
func (p *placement) attach(cmd *exec.Cmd) {
	if p != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, p.w)
	}
}

var errNotPlaced = errors.New("workload process did not join the freezer cgroup")

// wrap makes the command join the cgroup before exec, report it, and refuse to
// run if it cannot: a process outside the cgroup would survive a freeze. The
// shell's pid becomes the command's on exec, so every descendant inherits the
// placement. Passthrough without a cgroup.
func (f *freezer) wrap(name string, args []string) (string, []string, *placement) {
	if !f.available() {
		return name, args, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		// Without a pipe the placement cannot be confirmed; the wrapper still
		// refuses to run unplaced, and confirmPlacement refuses the spawn.
		return "/bin/sh", []string{"-c", "exit 1"}, nil
	}
	script := "echo $$ > " + filepath.Join(f.dir, "cgroup.procs") + " && printf 1 >&3 && exec 3>&- && exec \"$0\" \"$@\""
	return "/bin/sh", append([]string{"-c", script, name}, args...), &placement{r: r, w: w}
}

// confirmPlacement waits, under the spawn lock, for the wrapper's report. A
// process that never reports is killed: it may be running outside the cgroup.
func (f *freezer) confirmPlacement(cmd *exec.Cmd, p *placement) error {
	if !f.available() {
		return nil
	}
	if p == nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return errNotPlaced
	}
	p.w.Close()
	defer p.r.Close()
	_ = p.r.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if n, err := p.r.Read(b[:]); n == 1 && b[0] == '1' && err == nil {
		return nil
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	return errNotPlaced
}

func (f *freezer) isFrozen() bool {
	return f.available() && f.frozen.Load()
}

// freeze stops the cgroup and waits for every task to stop. On timeout it
// thaws; an unconfirmed thaw wraps errThawUnconfirmed. Repeating a freeze
// with its own token succeeds; a different token while one is active conflicts.
func (f *freezer) freeze(ctx context.Context, token string) error {
	if !f.available() {
		return errors.New("freezer cgroup unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.frozen.Load() {
		if token == f.token {
			return nil
		}
		return errTokenConflict
	}

	if err := f.fs.writeState("FROZEN"); err != nil {
		return fmt.Errorf("request freeze: %w", err)
	}
	// FREEZING until every task has stopped; poll densely, then back off.
	interval := time.Millisecond
	for {
		st, err := f.fs.readState()
		if err != nil {
			return f.undo(token, fmt.Errorf("read freezer state: %w", err))
		}
		if st == "FROZEN" {
			f.frozen.Store(true)
			f.token = token
			return nil
		}
		select {
		case <-ctx.Done():
			return f.undo(token, fmt.Errorf("workload did not freeze within budget (state %q): %w", st, ctx.Err()))
		case <-time.After(interval):
		}
		interval = min(interval*2, 10*time.Millisecond)
	}
}

// undo rolls back a freeze that did not complete. The token is remembered as
// released, so the supervisor's own follow-up thaw with it is answered as
// already done rather than refused.
func (f *freezer) undo(token string, cause error) error {
	if terr := f.thawLocked(); terr != nil {
		return fmt.Errorf("%w; %w: %v", cause, errThawUnconfirmed, terr)
	}
	f.last, f.token = token, ""
	return cause
}

// thaw lets the workload run and confirms it did, for the freeze the token
// names. Repeating it after success succeeds; any other token is refused
// without changing state. A no-op without a cgroup.
func (f *freezer) thaw(token string) error {
	if !f.available() {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.frozen.Load() {
		if token == f.last && token != "" {
			return nil
		}
		return errTokenMismatch
	}
	if token != f.token {
		return errTokenMismatch
	}
	if err := f.thawLocked(); err != nil {
		return err
	}
	f.last, f.token = f.token, ""
	return nil
}

// holds reports whether token names the active freeze, or the last released one.
func (f *freezer) holds(token string) bool {
	if !f.available() {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.frozen.Load() {
		return token == f.token
	}
	return token != "" && token == f.last
}

func (f *freezer) thawLocked() error {
	st, err := f.fs.readState()
	if err != nil {
		return err
	}
	if st == "THAWED" {
		f.frozen.Store(false)
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
	f.frozen.Store(false)
	return nil
}

// POST /freeze {"budget_ms": N, "token": T}: 200 frozen, with the protocol
// version, capability and token echoed; 400 no token; 409 another freeze is
// active; 503 cannot freeze; 504 budget exhausted and thawed again; 500 budget
// exhausted and thaw unconfirmed.
func (f *freezer) handleFreeze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	budget := defaultFreezeBudget
	var body struct {
		BudgetMs int64  `json:"budget_ms"`
		Token    string `json:"token"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if body.BudgetMs > 0 {
		budget = time.Duration(body.BudgetMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()

	if err := f.freeze(ctx, body.Token); err != nil {
		code := http.StatusServiceUnavailable
		switch {
		case errors.Is(err, errTokenConflict):
			code = http.StatusConflict
		case errors.Is(err, errThawUnconfirmed):
			code = http.StatusInternalServerError
		case errors.Is(err, context.DeadlineExceeded):
			code = http.StatusGatewayTimeout
		}
		log.Printf("freezer: freeze refused: %v", err)
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(freezeReply{Version: protocolVersion, Capability: protocolCapability, Token: body.Token})
}

// protocolVersion is the wake protocol this boxd speaks; the supervisor
// refuses an image whose manifest names one it does not understand.
const (
	protocolVersion    = 1
	protocolCapability = "wake"
)

type freezeReply struct {
	Version    int    `json:"version"`
	Capability string `json:"capability"`
	Token      string `json:"token"`
}

// POST /thaw {"token": T}: the snapshot did not happen. 200 only once
// confirmed running; 409 the token names no freeze this guest holds.
func (f *freezer) handleThaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if err := f.thaw(body.Token); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errTokenMismatch) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// POST /wake {"clock_frozen": bool, "token": T}: the supervisor restored this
// guest. Correct the clock — required if it was restored frozen — then release
// the workload. 200 ready; 409 with status "token" when the token names no
// freeze this guest holds, nothing changed; 503 with status "clock" or "thaw"
// otherwise, workload left stopped. Idempotent: a woken guest answers 200 again
// to the same token.
func handleWake(clock *wallClock, fz *freezer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ClockFrozen *bool  `json:"clock_frozen"`
			Token       string `json:"token"`
		}
		if r.Body == nil || json.NewDecoder(r.Body).Decode(&body) != nil || body.ClockFrozen == nil || body.Token == "" {
			// A wake that does not say whether the clock was frozen, or whose
			// freeze it belongs to, releases nothing.
			http.Error(w, "clock_frozen and token required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !fz.holds(body.Token) {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(struct {
				Status string `json:"status"`
			}{"token"})
			return
		}
		wc, ready := clock.sync(*body.ClockFrozen)
		status := "ok"
		if ready {
			if err := fz.thaw(body.Token); err != nil {
				log.Printf("freezer: thaw on wake failed: %v", err)
				ready, status = false, "thaw"
				wc.Error = "thaw: " + err.Error()
			}
		} else {
			status = "clock"
		}
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
