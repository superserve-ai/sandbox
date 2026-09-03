package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	mu spawnGuard
	// frozen mirrors the state this freezer last confirmed, so health can
	// answer without a file read or waiting on a freeze in progress.
	frozen atomic.Bool
	// token is the supervisor's proof that a thaw or wake belongs to the
	// freeze it is releasing; it lives here, so it is in the snapshot. last
	// is the token of the freeze most recently released, so a repeated
	// request after success is answered the same way.
	token string
	last  atomic.Value // string: the token most recently released
}

var (
	errTokenMismatch = errors.New("freeze token mismatch")
	errTokenConflict = errors.New("another freeze is active")
)

// newFreezer wraps a cgroup the init script mounted. It is only asked for
// when the image says one exists (see freezerFromEnv); the read confirms the
// mount, so an image that claims a freezer it does not have fails closed —
// freezing is refused, and the builder never marks it.
func newFreezer(fs freezerFS, dir string) *freezer {
	f := &freezer{fs: fs, dir: dir}
	if fs != nil {
		_, err := fs.readState()
		f.mounted = err == nil
	}
	return f
}

// freezerEnv is set by the guest init script when it mounts the workload
// freezer, so boxd never probes the filesystem to find out: an image without
// the freezer starts exactly as it always did.
const freezerEnv = "BOXD_WORKLOAD_FREEZER"

func freezerFromEnv() *freezer {
	dir := os.Getenv(freezerEnv)
	if dir == "" {
		return newFreezer(nil, "")
	}
	return newFreezer(cgroupFS{dir: dir}, dir)
}

// A nil *freezer means none is configured: passthrough, and a freeze is refused.

func (f *freezer) available() bool { return f != nil && f.mounted }

var errWorkloadFrozen = errors.New("workload is frozen for a snapshot; no new process can start until it is released")

// beginSpawn admits a spawn: it holds the spawn lock shared until endSpawn,
// and refuses while the workload is frozen. A process started after the
// freeze returned would spend its first moments outside the cgroup, and a
// snapshot taken then would capture it running — to run on the stale clock
// after restore. Without a cgroup there is nothing a freeze could miss, so a
// spawn takes no lock at all and the exec path is what it was before the
// freezer existed.
func (f *freezer) beginSpawn() error {
	if !f.available() {
		return nil
	}
	f.mu.RLock()
	if f.frozen.Load() {
		f.mu.RUnlock()
		return errWorkloadFrozen
	}
	return nil
}

func (f *freezer) endSpawn() {
	if f.available() {
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

// close releases both ends; safe on nil and after a partial close.
func (p *placement) close() {
	if p == nil {
		return
	}
	if p.w != nil {
		p.w.Close()
		p.w = nil
	}
	if p.r != nil {
		p.r.Close()
		p.r = nil
	}
}

// confirmPlacement waits, under the spawn lock, for the wrapper's report, and
// releases the pipe whatever happened — called after every Start, failed or
// not. A process that never reports is killed: it may be running outside the
// cgroup. Without a freezer there is nothing to confirm and nothing to hold.
func (f *freezer) confirmPlacement(cmd *exec.Cmd, p *placement) error {
	if !f.available() {
		p.close()
		return nil
	}
	defer p.close()
	if cmd.Process == nil {
		// Start failed: nothing runs, nothing to place.
		return nil
	}
	if p == nil {
		_ = cmd.Process.Kill()
		return errNotPlaced
	}
	p.w.Close()
	p.w = nil
	_ = p.r.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if n, err := p.r.Read(b[:]); n == 1 && b[0] == '1' && err == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	return errNotPlaced
}

func (f *freezer) isFrozen() bool {
	return f.available() && f.frozen.Load()
}

// freeze stops the cgroup and waits for every task to stop. On timeout it
// thaws; if that cannot be confirmed it stays frozen under the token and wraps
// errThawUnconfirmed. Repeating a freeze with its own token succeeds; a
// different token while one is active conflicts.
func (f *freezer) freeze(ctx context.Context, token string) error {
	if !f.available() {
		return errors.New("freezer cgroup unavailable")
	}
	if err := f.lockWithin(ctx, token); err != nil {
		return err
	}
	defer f.mu.Unlock()
	if f.frozen.Load() {
		if token != f.token {
			return errTokenConflict
		}
		// Only a cgroup that reads FROZEN is a repeat; one left unconfirmed
		// by an earlier rollback is tried again.
		if st, err := f.fs.readState(); err == nil && st == "FROZEN" {
			return nil
		}
	}
	// The budget covers the wait for the guard too: a caller that has given
	// up must not find its workload stopped after all.
	if err := ctx.Err(); err != nil {
		if !f.frozen.Load() {
			f.last.Store(token)
		}
		return fmt.Errorf("budget spent before the freeze began: %w", err)
	}

	// Unready from the first request: tasks stop while the cgroup still
	// reads FREEZING, and health reads this flag alone.
	f.frozen.Store(true)
	if err := f.fs.writeState("FROZEN"); err != nil {
		return f.undo(token, fmt.Errorf("request freeze: %w", err))
	}
	// FREEZING until every task has stopped; poll densely, then back off.
	interval := time.Millisecond
	for {
		st, err := f.fs.readState()
		if err != nil {
			return f.undo(token, fmt.Errorf("read freezer state: %w", err))
		}
		if st == "FROZEN" {
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

// lockWithin takes the write side of the spawn guard, giving up when ctx
// ends first. A spawn in flight holds the guard for as long as its placement
// takes. An abandoned attempt withdraws at once, holding no spawn off, and
// records its token as released so the caller's follow-up thaw with it is
// answered as done.
func (f *freezer) lockWithin(ctx context.Context, token string) error {
	if err := f.mu.LockContext(ctx); err != nil {
		f.last.Store(token)
		return fmt.Errorf("spawn in flight past the freeze budget: %w", err)
	}
	return nil
}

// undo rolls back a freeze that did not complete. The token is remembered as
// released, so the supervisor's own follow-up thaw with it is answered as
// already done rather than refused. A rollback that cannot be confirmed leaves
// boxd frozen under the token: nothing spawns, health says so, and the
// supervisor's thaw retries the cgroup until it answers.
func (f *freezer) undo(token string, cause error) error {
	if terr := f.thawLocked(); terr != nil {
		f.frozen.Store(true)
		f.token = token
		return fmt.Errorf("%w; %w: %v", cause, errThawUnconfirmed, terr)
	}
	f.last.Store(token)
	f.token = ""
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
		if f.released(token) {
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
	f.last.Store(f.token)
	f.token = ""
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
	return f.released(token)
}

// released reports whether token names the most recently released freeze.
func (f *freezer) released(token string) bool {
	last, _ := f.last.Load().(string)
	return token != "" && token == last
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

// decodeBody reads one JSON object and nothing else: a body with trailing
// data, or one that does not decode whole, is an error.
func decodeBody(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("body required")
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing data after the body")
	}
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
	// A body that does not decode whole is refused before anything moves,
	// whatever fields it did fill.
	if decodeBody(r, &body) != nil || body.Token == "" {
		http.Error(w, "well-formed body with token required", http.StatusBadRequest)
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
		diagf("freezer: freeze refused: %v", err)
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
	// A body that does not decode whole is refused before anything moves,
	// whatever fields it did fill.
	if decodeBody(r, &body) != nil || body.Token == "" {
		http.Error(w, "well-formed body with token required", http.StatusBadRequest)
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
		if decodeBody(r, &body) != nil || body.ClockFrozen == nil || body.Token == "" {
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
				diagf("freezer: thaw on wake failed: %v", err)
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
		// The diagnostic never delays the answer: the response is only
		// flushed when this handler returns.
		if wc.CorrectedMs != 0 {
			diagf("wall clock: corrected by %dms from host time", wc.CorrectedMs)
		}
	}
}

// The lifecycle routes are the supervisor's, on a listener every process in
// the sandbox can reach. A connection from one of the guest's own addresses is
// refused. A root process can still bind another address, so this guards
// against accident, not a boundary.
//
// The guest's addresses are fixed at boot, so they are read once, on the first
// lifecycle request, and the wake path never enumerates interfaces.
type hostGate struct {
	addrs func() ([]net.Addr, error)
	mu    sync.Mutex
	ips   []net.IP
	known bool
}

func newHostGate() *hostGate { return &hostGate{addrs: net.InterfaceAddrs} }

func (g *hostGate) guestIPs() ([]net.IP, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.known {
		addrs, err := g.addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				g.ips = append(g.ips, n.IP)
			}
		}
		g.known = true
	}
	return g.ips, nil
}

func (g *hostGate) fromGuest(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	ips, err := g.guestIPs()
	if err != nil {
		return true
	}
	for _, own := range ips {
		if own.Equal(ip) {
			return true
		}
	}
	return false
}

func (g *hostGate) only(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.fromGuest(r.RemoteAddr) {
			http.Error(w, "supervisor only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
