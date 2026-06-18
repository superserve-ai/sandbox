package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/creack/pty"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

const (
	httpPort     = 49983
	defaultShell = "/bin/bash"
	defaultHome  = "/home/user"
)

// dangerousPaths are paths that must never be modified via the filesystem API.
var dangerousPaths = []string{"/proc", "/sys", "/dev", "/sbin/init", "/usr/local/bin/boxd"}

// safePath validates and cleans a filesystem path. It rejects paths that could
// damage the VM's ability to function (init, boxd, /proc, /sys, /dev) and
// prevents path traversal to root.
func safePath(raw string) (string, error) {
	p := filepath.Clean(raw)
	if p == "/" || p == "." {
		return "", fmt.Errorf("cannot operate on root directory")
	}
	for _, d := range dangerousPaths {
		if p == d || strings.HasPrefix(p, d+"/") {
			return "", fmt.Errorf("access denied: %s", d)
		}
	}
	return p, nil
}

func main() {
	log.SetPrefix("[boxd] ")
	log.SetFlags(log.Ltime)

	// Ensure defaultHome exists before we accept any RPCs. Start()
	// defaults cmd.Dir to defaultHome when the caller omits Cwd; if the
	// directory is missing, exec fails with "chdir: no such file or
	// directory" — a cryptic failure mode for template builds whose base
	// images don't create /home/user (python:3.11, ubuntu:24.04, etc.).
	//
	// Fatal on failure — boxd can't reliably serve Start() requests
	// without a working defaultHome, and silently degrading would push
	// the failure to the first user exec.
	if err := os.MkdirAll(defaultHome, 0o755); err != nil {
		log.Fatalf("ensure defaultHome %s: %v", defaultHome, err)
	}
	// Chmod separately — MkdirAll respects umask and may strip group /
	// other bits. We want exactly 0755 so non-root processes can cd in.
	if err := os.Chmod(defaultHome, 0o755); err != nil {
		log.Fatalf("chmod defaultHome %s: %v", defaultHome, err)
	}

	mux := http.NewServeMux()

	ctx := &sandboxContext{}

	// Connect RPC services.
	procService := &processService{
		processes: &sync.Map{},
		ctx:       ctx,
	}
	mux.Handle(boxdpbconnect.NewProcessServiceHandler(procService))
	mux.Handle(boxdpbconnect.NewFilesystemServiceHandler(&filesystemService{}))

	// Raw HTTP endpoints (file content transfer + health + init + exec).
	mux.HandleFunc("/files", handleFiles)
	mux.HandleFunc("/init", handleInit(ctx))
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/exec", procService.handleExec)
	mux.HandleFunc("/exec/stream", procService.handleExecStream)

	addr := fmt.Sprintf("0.0.0.0:%d", httpPort)
	log.Printf("boxd listening on %s (Connect RPC + HTTP)", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      h2c.NewHandler(mux, &http2.Server{}),
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

// handleInit updates boxd's in-memory sandbox context. Called at least
// once by vmd after the VM is healthy, and also by template-builder
// before it snapshots the template so the context travels in the
// snapshot. Fields are additive — env_vars merge (new keys overwrite),
// default_user / default_workdir replace only when non-empty.
//
// POST /init
//
//	{
//	  "env_vars":        {"KEY":"VALUE", ...}, // optional
//	  "default_user":    "appuser",             // optional
//	  "default_workdir": "/srv/app",            // optional
//	  "hostname":        "sandbox-abc12345"     // optional
//	}
func handleInit(ctx *sandboxContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			EnvVars        map[string]string `json:"env_vars"`
			DefaultUser    string            `json:"default_user"`
			DefaultWorkdir string            `json:"default_workdir"`
			Hostname       string            `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		ctx.merge(body.EnvVars, body.DefaultUser, body.DefaultWorkdir)
		log.Printf("init: merged %d env var(s) user=%q workdir=%q",
			len(body.EnvVars), body.DefaultUser, body.DefaultWorkdir)

		if body.Hostname != "" {
			if err := setHostname(body.Hostname); err != nil {
				log.Printf("init: set hostname %q failed: %v", body.Hostname, err)
			} else {
				log.Printf("init: hostname set to %q", body.Hostname)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// setHostname is defined per-platform — see hostname_linux.go (the real
// syscall.Sethostname implementation) and hostname_other.go (a stub so the
// package stays buildable and unit-testable on non-Linux dev machines). boxd
// only runs inside a Linux microVM in production.

// ---------------------------------------------------------------------------
// Process service (Connect RPC)
// ---------------------------------------------------------------------------

type runningProcess struct {
	cmd   *exec.Cmd
	tty   *os.File       // nil for non-PTY processes.
	stdin io.WriteCloser // stdin pipe for non-PTY processes; nil in PTY mode.
}

// sandboxContext holds the sandbox-level state that persists across exec
// calls: env vars, the default user commands run as, and the default cwd.
// Populated by POST /init. Template-builder posts the template's defaults
// before snapshotting so the context travels in the Firecracker snapshot;
// vmd posts caller-provided values on restore, which merge on top.
type sandboxContext struct {
	mu             sync.RWMutex
	envVars        map[string]string
	defaultUser    string
	defaultWorkdir string
}

// merge applies an /init payload to the context. envVars are merged key by
// key (later keys overwrite). user/workdir replace only when non-empty so
// a later restore-time init without those fields preserves template values
// baked into the snapshot.
func (c *sandboxContext) merge(envVars map[string]string, user, workdir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.envVars == nil {
		c.envVars = map[string]string{}
	}
	for k, v := range envVars {
		c.envVars[k] = v
	}
	if user != "" {
		c.defaultUser = user
	}
	if workdir != "" {
		c.defaultWorkdir = workdir
	}
}

func (c *sandboxContext) snapshot() (map[string]string, string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.envVars))
	for k, v := range c.envVars {
		out[k] = v
	}
	return out, c.defaultUser, c.defaultWorkdir
}

type processService struct {
	boxdpbconnect.UnimplementedProcessServiceHandler
	processes *sync.Map // pid → *runningProcess
	ctx       *sandboxContext
}

// buildEnv assembles the environment for a child process. Layers (last wins):
// 1. OS base env  2. system defaults (PATH, HOME, USER — HOME/USER keyed to
// the effective user)  3. sandbox-level env vars from /init  4. per-request
// env vars from StartRequest.envs.
func (s *processService) buildEnv(requestEnvs map[string]string, effective *user.User) []string {
	envVars, _, _ := s.ctx.snapshot()

	home := defaultHome
	userName := "user"
	if effective != nil {
		home = effective.HomeDir
		if home == "" {
			home = "/home/" + effective.Username
		}
		userName = effective.Username
	}

	env := append(os.Environ(),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME="+home,
		"USER="+userName,
	)
	for k, v := range envVars {
		env = append(env, k+"="+v)
	}
	for k, v := range requestEnvs {
		env = append(env, k+"="+v)
	}
	return env
}

// pathFromEnv returns the PATH value from a KEY=VALUE slice. The last
// PATH entry wins, mirroring exec's last-wins env semantics.
func pathFromEnv(env []string) string {
	var path string
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = strings.TrimPrefix(kv, "PATH=")
		}
	}
	return path
}

// lookPathIn resolves `file` against the given PATH value. Mirrors
// os/exec.LookPath but uses a passed-in PATH instead of boxd's own.
// Used so bare command names (e.g. "python") resolve against the child
// process's effective PATH, which may include per-request overrides.
func lookPathIn(file, pathEnv string) (string, error) {
	if pathEnv == "" {
		return "", fmt.Errorf("PATH is empty")
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, file)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		// Executable by any of user/group/other.
		if fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("executable file not found in PATH")
}

// resolveUser looks up a user by name and returns its uid/gid for use with
// SysProcAttr.Credential. Returns (nil, nil) when the user is empty or is
// "root" — the caller should run without a Credential in that case so the
// child inherits boxd's uid (root).
func resolveUser(name string) (*user.User, *syscall.Credential, error) {
	if name == "" || name == "root" {
		return nil, nil, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, nil, fmt.Errorf("user %q not found: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("parse uid for %q: %w", name, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("parse gid for %q: %w", name, err)
	}
	return u, &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

// eventEmitter is runProcess's sink — shared by gRPC Start, /exec, and
// /exec/stream. Contract: invoked from a single goroutine. Fanning out
// would corrupt the response on both HTTP endpoints.
type eventEmitter func(*pb.ProcessEvent) error

func (s *processService) Start(ctx context.Context, req *connect.Request[pb.StartRequest], stream *connect.ServerStream[pb.ProcessEvent]) error {
	// Only the interactive bridge sets stdin; build steps and execs leave it off.
	return s.runProcess(ctx, req.Msg, stream.Send, req.Msg.GetStdin())
}

func (s *processService) runProcess(ctx context.Context, msg *pb.StartRequest, emit eventEmitter, wantStdin bool) error {
	cmdName := msg.GetCmd()
	if cmdName == "" {
		cmdName = defaultShell
	}
	args := msg.GetArgs()

	// Resolve effective user: explicit request wins, else template default
	// (from /init), else boxd's own uid (root).
	_, defaultUser, defaultWorkdir := s.ctx.snapshot()
	effectiveUser := msg.GetUser()
	if effectiveUser == "" {
		effectiveUser = defaultUser
	}
	usr, cred, err := resolveUser(effectiveUser)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Resolve cwd: explicit request wins, else template default, else
	// user's home dir (if we resolved a user), else boxd's defaultHome.
	cwd := msg.GetCwd()
	if cwd == "" {
		cwd = defaultWorkdir
	}
	if cwd == "" {
		if usr != nil && usr.HomeDir != "" {
			cwd = usr.HomeDir
		} else {
			cwd = defaultHome
		}
	}

	// cmdCtx must be separate from the stream context so the timeout kills
	// only the child process — the stream stays alive to deliver the End
	// event with the timeout exit code.
	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	var timedOut atomic.Bool
	if timeoutMs := msg.GetTimeoutMs(); timeoutMs > 0 {
		timer := time.AfterFunc(time.Duration(timeoutMs)*time.Millisecond, func() {
			timedOut.Store(true)
			cmdCancel()
		})
		defer timer.Stop()
	}

	// Resolve bare command names against the CHILD's PATH, not boxd's own.
	// Go's exec.Command would otherwise call exec.LookPath against
	// os.Getenv("PATH") — which is boxd's inherited PATH (often empty when
	// boxd is started by a minimal init). Rebuilding the child env first
	// lets us look up `python` / `node` / `sh` against the PATH the child
	// is actually about to receive, including any per-request overrides.
	childEnv := s.buildEnv(msg.GetEnvs(), usr)
	resolvedCmd := cmdName
	if filepath.Base(cmdName) == cmdName {
		p, err := lookPathIn(cmdName, pathFromEnv(childEnv))
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("resolve %q: %w", cmdName, err))
		}
		resolvedCmd = p
	}

	cmd := exec.CommandContext(cmdCtx, resolvedCmd, args...)
	cmd.Dir = cwd
	cmd.Env = childEnv
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}

	isPTY := msg.GetPty() != nil
	if !isPTY {
		// Kill the whole pgid on timeout — killing the shell alone leaves
		// orphaned children (e.g. `sleep` under `sh -c`) running.
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Setpgid = true
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return nil
			}
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		cmd.WaitDelay = time.Second
		return s.startPipes(ctx, cmd, emit, &timedOut, wantStdin)
	}
	return s.startPTY(ctx, cmd, msg, emit, &timedOut)
}

// timeoutExitCode matches GNU coreutils `timeout(1)`.
const timeoutExitCode int32 = 124

// finalExitCode maps a finished cmd's state into the exit code the caller
// sees: 124 on timeout, 128+signal on signal-kill (default 137 for SIGKILL
// when WaitStatus is unavailable), pass-through otherwise.
func finalExitCode(ps *os.ProcessState, timedOut bool) int32 {
	if timedOut {
		return timeoutExitCode
	}
	if ps == nil {
		return 0
	}
	code := int32(ps.ExitCode())
	if code != -1 {
		return code
	}
	if status, ok := ps.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return int32(128 + status.Signal())
	}
	return 137
}

func (s *processService) startPTY(ctx context.Context, cmd *exec.Cmd, msg *pb.StartRequest, emit eventEmitter, timedOut *atomic.Bool) error {
	cols := uint16(msg.GetPty().GetSize().GetCols())
	rows := uint16(msg.GetPty().GetSize().GetRows())
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	cmd.Env = append(cmd.Env, "TERM=xterm-256color")

	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("start pty: %w", err))
	}
	defer tty.Close()

	pid := uint32(cmd.Process.Pid)
	s.processes.Store(pid, &runningProcess{cmd: cmd, tty: tty})
	defer s.processes.Delete(pid)

	// Send start event.
	if err := emit(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_Start{Start: &pb.StartEvent{Pid: pid}},
	}); err != nil {
		return err
	}

	// Stream PTY output.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16*1024)
		for {
			n, readErr := tty.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				_ = emit(&pb.ProcessEvent{
					Event: &pb.ProcessEvent_Data{Data: &pb.DataEvent{
						Output: &pb.DataEvent_PtyData{PtyData: data},
					}},
				})
			}
			if readErr != nil {
				return
			}
		}
	}()

	<-done
	_ = cmd.Wait()

	status := ""
	if cmd.ProcessState != nil {
		status = cmd.ProcessState.String()
	}
	return emit(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_End{End: &pb.EndEvent{
			ExitCode: finalExitCode(cmd.ProcessState, timedOut.Load()),
			Exited:   cmd.ProcessState != nil && cmd.ProcessState.Exited(),
			Status:   status,
		}},
	})
}

func (s *processService) startPipes(ctx context.Context, cmd *exec.Cmd, emit eventEmitter, timedOut *atomic.Bool, wantStdin bool) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	// Only open a stdin pipe when the caller can feed it (the streaming RPC).
	// Otherwise leave cmd.Stdin nil so the child reads /dev/null and sees EOF
	// immediately, instead of blocking on a pipe nobody will close.
	var stdin io.WriteCloser
	if wantStdin {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
	}

	if err := cmd.Start(); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	pid := uint32(cmd.Process.Pid)
	s.processes.Store(pid, &runningProcess{cmd: cmd, stdin: stdin})
	defer s.processes.Delete(pid)

	if err := emit(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_Start{Start: &pb.StartEvent{Pid: pid}},
	}); err != nil {
		return err
	}

	// Fan stdout + stderr through a multiplex so emit is invoked from a
	// single goroutine. ServerStream is not safe for concurrent Send
	// (manifests as "bare LF" / "invalid byte in chunk length" under
	// load), and the HTTP emitters share the same single-writer need.
	mux := NewMultiplexedChannel[*pb.ProcessEvent](256)
	consumer, _ := mux.Fork()

	sendDone := make(chan error, 1)
	go func() {
		var firstErr error
		for ev := range consumer {
			if firstErr != nil {
				continue // keep draining so the mux can close cleanly
			}
			if err := emit(ev); err != nil {
				firstErr = err
			}
		}
		sendDone <- firstErr
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				mux.Source <- &pb.ProcessEvent{
					Event: &pb.ProcessEvent_Data{Data: &pb.DataEvent{
						Output: &pb.DataEvent_Stdout{Stdout: data},
					}},
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := stderr.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				mux.Source <- &pb.ProcessEvent{
					Event: &pb.ProcessEvent_Data{Data: &pb.DataEvent{
						Output: &pb.DataEvent_Stderr{Stderr: data},
					}},
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	_ = cmd.Wait()

	// Flush data events to the stream before sending End. Closing the
	// mux drains it, closes the consumer channel, and unblocks sendDone.
	close(mux.Source)
	if sendErr := <-sendDone; sendErr != nil {
		return sendErr
	}

	status := ""
	if cmd.ProcessState != nil {
		status = cmd.ProcessState.String()
	}
	return emit(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_End{End: &pb.EndEvent{
			ExitCode: finalExitCode(cmd.ProcessState, timedOut.Load()),
			Exited:   cmd.ProcessState != nil && cmd.ProcessState.Exited(),
			Status:   status,
		}},
	})
}

func (s *processService) SendInput(ctx context.Context, req *connect.Request[pb.SendInputRequest]) (*connect.Response[pb.SendInputResponse], error) {
	pid := req.Msg.GetPid()
	val, ok := s.processes.Load(pid)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("process %d not found", pid))
	}
	proc := val.(*runningProcess)

	// PTY mode: input goes to the terminal master; EOF is ignored.
	if proc.tty != nil {
		if _, err := proc.tty.Write(req.Msg.GetData()); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		return connect.NewResponse(&pb.SendInputResponse{}), nil
	}

	// Non-PTY: write to the process's stdin pipe, then optionally close it
	// to signal EOF.
	if proc.stdin != nil {
		if data := req.Msg.GetData(); len(data) > 0 {
			if _, err := proc.stdin.Write(data); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
		}
		if req.Msg.GetEof() {
			if err := proc.stdin.Close(); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
		}
	}

	return connect.NewResponse(&pb.SendInputResponse{}), nil
}

func (s *processService) Resize(ctx context.Context, req *connect.Request[pb.ResizeRequest]) (*connect.Response[pb.ResizeResponse], error) {
	pid := req.Msg.GetPid()
	val, ok := s.processes.Load(pid)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("process %d not found", pid))
	}
	proc := val.(*runningProcess)

	if proc.tty == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("not a PTY process"))
	}

	if err := pty.Setsize(proc.tty, &pty.Winsize{
		Cols: uint16(req.Msg.GetSize().GetCols()),
		Rows: uint16(req.Msg.GetSize().GetRows()),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pb.ResizeResponse{}), nil
}

func (s *processService) Signal(ctx context.Context, req *connect.Request[pb.SignalRequest]) (*connect.Response[pb.SignalResponse], error) {
	pid := req.Msg.GetPid()
	val, ok := s.processes.Load(pid)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("process %d not found", pid))
	}
	proc := val.(*runningProcess)

	if proc.cmd.Process == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("process not started"))
	}

	sig := syscall.Signal(req.Msg.GetSignal())
	// Non-PTY commands are their own process group (Setpgid), so signal the
	// group — otherwise a child like `sleep` under `sh -c` survives. PTY keeps
	// direct delivery.
	if proc.tty == nil {
		if err := syscall.Kill(-proc.cmd.Process.Pid, sig); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	} else if err := proc.cmd.Process.Signal(sig); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pb.SignalResponse{}), nil
}

// ---------------------------------------------------------------------------
// Filesystem service (Connect RPC)
// ---------------------------------------------------------------------------

type filesystemService struct {
	boxdpbconnect.UnimplementedFilesystemServiceHandler
}

func (s *filesystemService) Stat(ctx context.Context, req *connect.Request[pb.StatRequest]) (*connect.Response[pb.StatResponse], error) {
	path, err := safePath(req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pb.StatResponse{
		Name:         info.Name(),
		Size:         info.Size(),
		IsDir:        info.IsDir(),
		Mode:         info.Mode().String(),
		ModifiedUnix: info.ModTime().Unix(),
	}), nil
}

func (s *filesystemService) ListDir(ctx context.Context, req *connect.Request[pb.ListDirRequest]) (*connect.Response[pb.ListDirResponse], error) {
	path, err := safePath(req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var result []*pb.FileEntry
	for _, e := range entries {
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		result = append(result, &pb.FileEntry{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Size:  size,
		})
	}

	return connect.NewResponse(&pb.ListDirResponse{Entries: result}), nil
}

func (s *filesystemService) MakeDir(ctx context.Context, req *connect.Request[pb.MakeDirRequest]) (*connect.Response[pb.MakeDirResponse], error) {
	path, err := safePath(req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.MakeDirResponse{}), nil
}

func (s *filesystemService) Remove(ctx context.Context, req *connect.Request[pb.RemoveRequest]) (*connect.Response[pb.RemoveResponse], error) {
	path, err := safePath(req.Msg.GetPath())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := os.RemoveAll(path); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.RemoveResponse{}), nil
}

func (s *filesystemService) Move(ctx context.Context, req *connect.Request[pb.MoveRequest]) (*connect.Response[pb.MoveResponse], error) {
	src, err := safePath(req.Msg.GetSource())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	dst, err := safePath(req.Msg.GetDestination())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := os.Rename(src, dst); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&pb.MoveResponse{}), nil
}

// ---------------------------------------------------------------------------
// Raw HTTP file content transfer (upload/download)
// ---------------------------------------------------------------------------

func handleFiles(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("path")
	if raw == "" {
		http.Error(w, `{"error":"path query parameter is required"}`, http.StatusBadRequest)
		return
	}
	path, err := safePath(raw)
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(errJSON), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleFileDownload(w, r, path)
	case http.MethodPost:
		handleFileUpload(w, r, path)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func handleFileDownload(w http.ResponseWriter, r *http.Request, path string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		} else {
			errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
			http.Error(w, string(errJSON), http.StatusInternalServerError)
		}
		return
	}
	if info.IsDir() {
		// A directory is only downloadable when the caller explicitly opts in to
		// an archive via ?format=zip. Without the flag we keep the original 400,
		// so the SDK's files.read()/readText() (which never send it) still throw
		// on a directory, exactly as before.
		if r.URL.Query().Get("format") != "zip" {
			http.Error(w, `{"error":"use FilesystemService.ListDir for directories"}`, http.StatusBadRequest)
			return
		}
		serveDirAsZip(w, path)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filepath.Base(path)))
	http.ServeContent(w, r, filepath.Base(path), info.ModTime(), f)
}

// serveDirAsZip streams a ZIP archive of dirPath's contents. Entry names are
// relative to dirPath and prefixed with its base name, so the archive expands
// to `<base>/...`.
//
// The directory's contents are attacker-controlled and can change mid-walk (the
// sandbox runs untrusted code), so the walk is hardened against it:
//
//   - The whole walk and every file open go through an os.Root anchored at
//     dirPath. os.Root errors on any path that resolves outside the root, so no
//     entry — including one reached through a symlink swapped in mid-walk — can
//     escape the requested directory.
//   - Only directories and regular files are archived. Symlinks, FIFOs, sockets
//     and device nodes are skipped, so a named pipe can't block the download and
//     special files never land in the archive. (os.Root on its own does not
//     exclude /proc or device files, hence this filter plus the safePath check.)
//   - Each file is opened through the root with O_NOFOLLOW (a regular file
//     swapped for a symlink fails with ELOOP instead of being followed) and
//     O_NONBLOCK (a swap for a FIFO can't block the open); the open fd is then
//     re-stat'd and skipped unless it is still a regular file, closing the
//     time-of-check/time-of-use window.
//   - safePath is re-applied to every descendant so the blocklist (/proc, /sys,
//     /dev, the boxd binary, ...) is enforced below the top-level argument too.
//
// os.OpenRoot validates the directory before the first byte, so a bad request
// still gets a clean error. Once the archive starts streaming the HTTP status is
// committed, so per-file errors are logged and skipped rather than aborting the
// whole download. Entries are written as the walk proceeds — constant memory,
// no temp file.
func serveDirAsZip(w http.ResponseWriter, dirPath string) {
	// Open the requested directory WITHOUT following a symlink at its final
	// component. handleFileDownload's os.Stat and a plain os.OpenRoot(dirPath)
	// both follow a symlink at dirPath, so a request for "/home/user/export"
	// where export -> /etc (or /, /proc) would make the archive root the symlink
	// target — escaping the requested directory and bypassing safePath's
	// blocklist. Anchor at the parent and reach the leaf through the parent's
	// Root: a no-follow Lstat refuses a symlinked leaf, and Root.OpenRoot
	// resolves it relative to the parent's open fd, so there is no
	// Lstat-then-open TOCTOU window and a leaf swapped for an escaping symlink is
	// rejected rather than followed.
	parent, err := os.OpenRoot(filepath.Dir(dirPath))
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}
	defer parent.Close()

	base := filepath.Base(dirPath)
	if li, err := parent.Lstat(base); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, `{"error":"file not found"}`, http.StatusNotFound)
		} else {
			errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
			http.Error(w, string(errJSON), http.StatusInternalServerError)
		}
		return
	} else if li.Mode()&fs.ModeSymlink != 0 {
		http.Error(w, `{"error":"refusing to archive a symlinked directory"}`, http.StatusBadRequest)
		return
	}

	// Anchor every subsequent open to the real directory. OpenRoot also
	// validates it before we commit a 200 + headers and confines the walk.
	root, err := parent.OpenRoot(base)
	if err != nil {
		errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}
	defer root.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipDownloadFilename(base)))

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Walking root.FS() confines traversal to the tree and never follows
	// symlinks while descending; rel is a slash path relative to dirPath.
	_ = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Unreadable entry mid-walk: log and skip, keep the archive going.
			log.Printf("files: zip walk skip %q: %v", rel, walkErr)
			return nil
		}
		if rel == "." {
			return nil // the directory itself; entries carry the base prefix
		}
		// Enforce the blocklist on descendants, not just the top-level path.
		if _, err := safePath(filepath.Join(dirPath, rel)); err != nil {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		name := filepath.Join(base, rel)

		if d.IsDir() {
			// Trailing slash marks a directory entry; preserves empty dirs.
			if _, err := zw.Create(name + "/"); err != nil {
				log.Printf("files: zip create dir %q: %v", name, err)
			}
			return nil
		}
		// Only regular files are archived — skip symlinks, FIFOs, sockets and
		// device nodes before opening anything.
		if !d.Type().IsRegular() {
			return nil
		}

		// Open through the root (can't escape) with no-follow + non-blocking, so
		// a TOCTOU swap to a symlink or FIFO can't be followed or block us.
		f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			log.Printf("files: zip skip %q: %v", rel, err)
			return nil
		}
		// Re-check the opened descriptor: only copy if it is still a regular
		// file (defeats a swap that happened between WalkDir and the open).
		if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
			f.Close()
			log.Printf("files: zip skip non-regular %q", rel)
			return nil
		}
		fw, err := zw.Create(name)
		if err != nil {
			f.Close()
			log.Printf("files: zip create %q: %v", name, err)
			return nil
		}
		if _, err := io.Copy(fw, f); err != nil {
			log.Printf("files: zip copy %q: %v", rel, err)
		}
		f.Close()
		return nil
	})
}

// zipDownloadFilename builds the quoted Content-Disposition filename for a
// directory archive. The base name comes from the filesystem and can contain a
// literal double-quote, which would break the quoted-string, or control bytes;
// strip those. (Go's header writer already rejects CR/LF.)
func zipDownloadFilename(base string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 {
			return -1
		}
		return r
	}, base)
	if cleaned == "" {
		cleaned = "download"
	}
	return cleaned + ".zip"
}

// storageFullResponse is the canonical 507 body we return whenever a
// write fails because the sandbox has run out of disk space. It's a
// stable shape (code + message) so SDKs and the eventual web UI can
// branch on `error.code == "sandbox_storage_full"` rather than parsing
// free-form text.
const storageFullResponse = `{"error":{"code":"sandbox_storage_full","message":"Sandbox storage limit reached."}}`

// writeStorageFull sends the canonical 507 + cleans up any partial
// file that may have been left behind by a failed write. Extracted
// because we handle ENOSPC at two distinct syscall boundaries (open
// and write) and both need the same response.
func writeStorageFull(w http.ResponseWriter, partialPath string) {
	if partialPath != "" {
		// Best-effort: reclaim the bytes that did land before the
		// kernel returned ENOSPC. If the remove itself fails (disk
		// problem, race with a concurrent process), we swallow it —
		// leaving an empty/partial file on a full disk is strictly
		// better than failing the request a second time.
		_ = os.Remove(partialPath)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInsufficientStorage) // 507
	_, _ = w.Write([]byte(storageFullResponse))
}

func handleFileUpload(w http.ResponseWriter, r *http.Request, path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		// mkdir itself can hit ENOSPC if the sandbox is already
		// brimming — inodes exhausted, no room for a new directory
		// entry. Surface it as the same storage-full error so users
		// get one consistent code for "you're out of disk" regardless
		// of which syscall tripped it.
		if errors.Is(err, syscall.ENOSPC) {
			writeStorageFull(w, "")
			return
		}
		errJSON, _ := json.Marshal(map[string]string{"error": "mkdir: " + err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			writeStorageFull(w, "")
			return
		}
		errJSON, _ := json.Marshal(map[string]string{"error": "create file: " + err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}

	written, err := io.Copy(f, r.Body)
	f.Close()
	if err != nil {
		// Remove the partial file — a truncated upload is never useful
		// to the caller. This handles both ENOSPC (disk full) and
		// client disconnect (network drop, cancel) so interrupted
		// uploads don't leave orphaned files eating disk space.
		_ = os.Remove(path)

		if errors.Is(err, syscall.ENOSPC) {
			writeStorageFull(w, "")
			return
		}
		errJSON, _ := json.Marshal(map[string]string{"error": "write: " + err.Error()})
		http.Error(w, string(errJSON), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"path": path, "size": written})
}
