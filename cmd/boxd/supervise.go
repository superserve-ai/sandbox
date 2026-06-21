package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/superserve-ai/sandbox/internal/start"
)

// logPrintf, lookupUser, lookupGroup are package-level seams so unit tests can
// stub them: logPrintf to silence/capture child output, the lookups to fake
// /etc/passwd resolution without depending on the test host's user database.
var (
	logPrintf   = log.Printf
	lookupUser  = user.Lookup
	lookupGroup = user.LookupGroup
)

// The supervisor runs the image's start command as a CHILD of boxd (boxd
// itself stays the control agent / PID-1 child via tini — it is NOT replaced).
// It owns a small state machine driven by one goroutine:
//
//	idle ──Start()──▶ running ──child exits──▶ (restart? backoff ▶ running) | stopped
//	                     │
//	                   Stop()/ctx cancel ──▶ stopped (SIGTERM, then SIGKILL)
//
// Only one supervised child exists at a time. A second /start while a child is
// live is refused (the handler returns 409) — the simplest correct idempotency
// rule. The same supervisor instance drives both the cold-boot path (reading
// the baked spec at start.StartSpecPath) and the live POST /start path, so bake
// and runtime-start share one code path.

// Backoff bounds for the restart policy. The schedule is exponential starting
// at backoffBase, doubling each consecutive restart, capped at backoffMax. A
// run that stays up longer than backoffResetAfter is treated as healthy and
// resets the backoff to base, so a process that crashes once an hour doesn't
// inherit a multi-minute delay.
const (
	backoffBase       = 500 * time.Millisecond
	backoffMax        = 30 * time.Second
	backoffResetAfter = 60 * time.Second
)

// childStopGrace is how long a child gets to exit after SIGTERM before boxd
// escalates to SIGKILL on the whole process group.
const childStopGrace = 5 * time.Second

// nextBackoff returns the delay before restart attempt n (0-indexed: attempt 0
// is the first restart after the initial exit). It is monotonic non-decreasing
// in n and capped at backoffMax. Kept pure so it is unit-testable without
// spawning processes.
func nextBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := backoffBase
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= backoffMax {
			return backoffMax
		}
	}
	if d > backoffMax {
		return backoffMax
	}
	return d
}

// shouldRestart decides whether a child that just exited with exitCode should
// be relaunched under the given policy. Pure function — the heart of the
// restart-policy contract, unit-tested exhaustively.
//
//	RestartNo        → never restart.
//	RestartOnFailure → restart only on non-zero exit.
//	RestartAlways    → restart on any exit.
//
// An empty/unknown policy normalizes to start.DefaultRestartPolicy.
func shouldRestart(policy start.RestartPolicy, exitCode int) bool {
	switch policy.Normalize() {
	case start.RestartAlways:
		return true
	case start.RestartOnFailure:
		return exitCode != 0
	case start.RestartNo:
		return false
	default:
		return false
	}
}

// parseUserCredential resolves Spec.User into a syscall.Credential. The User
// field may be "", "root", a numeric "uid", a numeric "uid:gid", a name, or
// "name:group". It returns (nil, nil) when the process should inherit boxd's
// own uid (root) — i.e. empty or "root".
//
// Best-effort, with documented limitations:
//   - Numeric uid/gid are used verbatim; they are NOT validated against
//     /etc/passwd, so a uid with no passwd entry still runs (matching Docker's
//     `--user 1234` behaviour on an image lacking that user).
//   - For a name, we look it up in the guest's /etc/passwd via os/user; an
//     unknown name is an error (we cannot invent a uid for it).
//   - Supplementary groups are NOT applied — only the primary gid. A process
//     needing extra groups must be launched with a numeric/named user whose
//     primary gid suffices.
func parseUserCredential(spec string) (*syscall.Credential, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "root" || spec == "0" || spec == "0:0" {
		return nil, nil
	}

	userPart, groupPart, hasGroup := strings.Cut(spec, ":")

	uid, gid, err := resolveUIDGID(userPart)
	if err != nil {
		return nil, err
	}

	if hasGroup {
		g, gerr := resolveGID(groupPart)
		if gerr != nil {
			return nil, gerr
		}
		gid = g
	}

	return &syscall.Credential{Uid: uid, Gid: gid}, nil
}

// resolveUIDGID resolves the user part of a User spec to a (uid, primary gid).
// A pure-numeric value is taken verbatim (gid defaults to the same number only
// if no group is given; callers override gid when a group part is present). A
// name is looked up in /etc/passwd.
func resolveUIDGID(userPart string) (uint32, uint32, error) {
	if n, err := strconv.ParseUint(userPart, 10, 32); err == nil {
		// Numeric uid with no passwd entry: default primary gid to the uid,
		// mirroring the common container convention. A ":gid" suffix overrides.
		return uint32(n), uint32(n), nil
	}
	u, err := lookupUser(userPart)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve user %q: %w", userPart, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %q: %w", userPart, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %q: %w", userPart, err)
	}
	return uint32(uid), uint32(gid), nil
}

// resolveGID resolves the group part of a User spec to a gid. Numeric verbatim,
// otherwise looked up by group name.
func resolveGID(groupPart string) (uint32, error) {
	if n, err := strconv.ParseUint(groupPart, 10, 32); err == nil {
		return uint32(n), nil
	}
	g, err := lookupGroup(groupPart)
	if err != nil {
		return 0, fmt.Errorf("resolve group %q: %w", groupPart, err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse gid for group %q: %w", groupPart, err)
	}
	return uint32(gid), nil
}

// supervisorEnv builds the child's environment: boxd's base env, then the
// spec's resolved env layered on top (later wins). Pure, so the env-layering
// contract is unit-testable. HOME/USER are NOT synthesized here — the resolved
// Spec.Env already carries whatever the resolver decided; we only guarantee a
// PATH default so a bare argv[0] resolves.
func supervisorEnv(base []string, specEnv map[string]string) []string {
	env := make([]string, 0, len(base)+len(specEnv)+1)
	env = append(env, base...)
	hasPath := false
	for _, kv := range base {
		if strings.HasPrefix(kv, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	for k, v := range specEnv {
		env = append(env, k+"="+v)
	}
	return env
}

// readStartSpec reads and decodes a baked start.Spec from path. Returns
// (nil, nil) when the file is absent — "nothing baked, idle" is not an error.
// The path is a parameter (not start.StartSpecPath hardcoded) so tests can
// point it at a temp dir.
func readStartSpec(path string) (*start.Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read start spec %s: %w", path, err)
	}
	var spec start.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("decode start spec %s: %w", path, err)
	}
	return &spec, nil
}

// writeStartSpec atomically bakes a start.Spec to path (creating parent dirs).
// Used by the /init bake path and reused by tests. Atomic via temp-file rename
// so a crash mid-write never leaves a half-spec that boxd would fail to decode
// on next boot.
func writeStartSpec(path string, spec *start.Spec) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for start spec %s: %w", path, err)
	}
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode start spec: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".start-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp start spec: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp start spec: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp start spec: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename start spec into place: %w", err)
	}
	return nil
}

// supervisorState is the supervisor's lifecycle state.
type supervisorState int

const (
	stateIdle    supervisorState = iota // no spec started yet
	stateRunning                        // a child is live (or backing off between restarts)
	stateStopped                        // the supervise loop has terminated
)

func (s supervisorState) String() string {
	switch s {
	case stateRunning:
		return "running"
	case stateStopped:
		return "stopped"
	default:
		return "idle"
	}
}

// supervisor owns the supervised child's lifecycle. There is exactly one per
// boxd process. All field access is guarded by mu; the long-running loop runs
// in its own goroutine and only touches shared state under mu.
type supervisor struct {
	// baseEnv is boxd's base environment for the child (os.Environ() in prod).
	// Held as a field so tests can inject a deterministic base.
	baseEnv []string

	// now is an injectable clock so the backoff-reset window is testable
	// without wall-clock dependence. newSupervisor wires it to time.Now.
	now func() time.Time

	mu       sync.Mutex
	state    supervisorState
	cancel   context.CancelFunc
	loopDone chan struct{}
}

// newSupervisor builds an idle supervisor. baseEnv is the environment layered
// under each child's resolved Spec.Env.
func newSupervisor(baseEnv []string) *supervisor {
	return &supervisor{
		baseEnv: baseEnv,
		now:     time.Now,
		state:   stateIdle,
	}
}

// IsSupervising reports whether a child is currently being supervised. This is
// the in-memory "already supervising" guard that prevents double-start on
// snapshot restore (the child is already live in the restored memory) and backs
// the 409 on a second /start.
func (s *supervisor) IsSupervising() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == stateRunning
}

// Start begins supervising spec's command. It returns errAlreadySupervising if
// a child is already live (the /start handler maps that to 409). A spec with no
// argv (IsRunnable()==false) is a no-op success: boxd idles, matching a base
// template with no runnable entrypoint.
func (s *supervisor) Start(spec *start.Spec) error {
	if spec == nil || !spec.IsRunnable() {
		return nil
	}

	s.mu.Lock()
	if s.state == stateRunning {
		s.mu.Unlock()
		return errAlreadySupervising
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.state = stateRunning
	s.cancel = cancel
	s.loopDone = done
	s.mu.Unlock()

	go s.loop(ctx, spec, done)
	return nil
}

// errAlreadySupervising is returned by Start when a child is already live.
var errAlreadySupervising = fmt.Errorf("a start command is already being supervised")

// Stop signals the supervised child to stop gracefully and waits for the
// supervise loop to exit. Safe to call when idle (no-op). Used on SIGTERM to
// boxd so the child gets a graceful stop before boxd exits.
func (s *supervisor) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.loopDone
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// loop is the supervise goroutine: it runs the child, applies the restart
// policy with capped exponential backoff, and exits when the policy says stop
// or ctx is cancelled (Stop / SIGTERM). Backoff resets after a healthy run.
func (s *supervisor) loop(ctx context.Context, spec *start.Spec, done chan struct{}) {
	defer close(done)
	defer func() {
		s.mu.Lock()
		s.state = stateStopped
		s.cancel = nil
		s.mu.Unlock()
	}()

	policy := spec.Restart.Normalize()
	attempt := 0

	for {
		runStart := s.now()
		exitCode, runErr := s.runOnce(ctx, spec)
		if runErr != nil {
			supervisorLogf("start command failed to launch: %v", runErr)
			// A launch failure (bad argv, chdir, perms) is treated like a
			// non-zero exit for restart purposes — on-failure/always retry,
			// no restarts exhaust on a permanently-broken spec via backoff cap.
			exitCode = 1
		} else {
			supervisorLogf("start command exited code=%d", exitCode)
		}

		if ctx.Err() != nil {
			// Asked to stop; don't restart regardless of policy.
			return
		}

		if !shouldRestart(policy, exitCode) {
			supervisorLogf("restart policy %q: not restarting (exit=%d)", policy, exitCode)
			return
		}

		// A run that stayed up long enough resets the backoff so a process
		// that crashes rarely doesn't accumulate a long delay.
		if s.now().Sub(runStart) >= backoffResetAfter {
			attempt = 0
		}
		delay := nextBackoff(attempt)
		attempt++
		supervisorLogf("restart policy %q: restarting in %s (attempt %d)", policy, delay, attempt)

		if !s.wait(ctx, delay) {
			return // ctx cancelled during backoff
		}
	}
}

// wait sleeps for d or returns early (false) if ctx is cancelled first.
func (s *supervisor) wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// runOnce launches the child once and blocks until it exits (or is killed via
// ctx cancellation). It returns the child's exit code. stdout/stderr are
// captured line-by-line into boxd's existing log stream (supervisorLogf →
// log.Printf), the same plumbing vmd already scrapes from boxd's output.
func (s *supervisor) runOnce(ctx context.Context, spec *start.Spec) (int, error) {
	cred, err := parseUserCredential(spec.User)
	if err != nil {
		return 1, fmt.Errorf("resolve user %q: %w", spec.User, err)
	}

	argv := spec.Argv
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = spec.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Env = supervisorEnv(s.baseEnv, spec.Env)

	// Own process group so we can signal the whole tree (a shell entrypoint's
	// children must die with it). Credential drops to the requested user.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if cred != nil {
		cmd.SysProcAttr.Credential = cred
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 1, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start %q: %w", argv[0], err)
	}
	supervisorLogf("start command launched pid=%d argv=%v user=%q dir=%q",
		cmd.Process.Pid, argv, spec.User, cmd.Dir)

	var pumpWG sync.WaitGroup
	pumpWG.Add(2)
	go pumpLines(&pumpWG, "stdout", stdout)
	go pumpLines(&pumpWG, "stderr", stderr)

	// Stop path: on ctx cancel, SIGTERM the group, then SIGKILL after a grace
	// period. waitDone lets us race the child's natural exit against the stop.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	pgid := cmd.Process.Pid // Setpgid makes pgid == pid of the leader

	select {
	case werr := <-waitDone:
		pumpWG.Wait()
		return supervisorExitCode(cmd, werr), nil
	case <-ctx.Done():
		// Graceful stop: SIGTERM the group, escalate to SIGKILL on grace.
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		select {
		case werr := <-waitDone:
			pumpWG.Wait()
			return supervisorExitCode(cmd, werr), nil
		case <-time.After(childStopGrace):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			werr := <-waitDone
			pumpWG.Wait()
			return supervisorExitCode(cmd, werr), nil
		}
	}
}

// supervisorExitCode derives the exit code from a finished cmd. A signalled
// child reports 128+signal, matching shell conventions; a clean exit reports
// its status. The cmd is always Wait()ed (waitDone), so no zombies are left.
func supervisorExitCode(cmd *exec.Cmd, werr error) int {
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code != -1 {
			return code
		}
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
	}
	if werr != nil {
		return 1
	}
	return 0
}

// pumpLines forwards a child stream to boxd's log output line by line, so the
// supervised process's stdout/stderr land in the same place vmd already
// scrapes (boxd's own stdout via the standard logger). Reuses the existing log
// transport rather than inventing a new one.
func pumpLines(wg *sync.WaitGroup, stream string, r io.Reader) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		supervisorLogf("[%s] %s", stream, sc.Text())
	}
}

// supervisorLogf routes supervisor + child output through boxd's existing
// logger. Kept as a single seam so a future change can redirect it (e.g. to a
// structured sink) without touching call sites.
var supervisorLogf = func(format string, args ...any) {
	logPrintf("supervise: "+format, args...)
}
