package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

	// Raw HTTP endpoints (file content transfer + health + init).
	mux.HandleFunc("/files", handleFiles)
	mux.HandleFunc("/init", handleInit(ctx))
	mux.HandleFunc("/health", handleHealth)

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

// setHostname sets the kernel hostname and writes /etc/hostname.
func setHostname(name string) error {
	if err := syscall.Sethostname([]byte(name)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := os.WriteFile("/etc/hostname", []byte(name+"\n"), 0o644); err != nil {
		return fmt.Errorf("write /etc/hostname: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Process service (Connect RPC)
// ---------------------------------------------------------------------------

type runningProcess struct {
	cmd *exec.Cmd
	tty *os.File // nil for non-PTY processes.
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

func (s *processService) Start(ctx context.Context, req *connect.Request[pb.StartRequest], stream *connect.ServerStream[pb.ProcessEvent]) error {
	msg := req.Msg

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

	timeout := time.Duration(msg.GetTimeoutMs()) * time.Millisecond
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
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

	cmd := exec.CommandContext(ctx, resolvedCmd, args...)
	cmd.Dir = cwd
	cmd.Env = childEnv
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}

	isPTY := msg.GetPty() != nil
	if isPTY {
		return s.startPTY(ctx, cmd, msg, stream)
	}
	return s.startPipes(ctx, cmd, stream)
}

func (s *processService) startPTY(ctx context.Context, cmd *exec.Cmd, msg *pb.StartRequest, stream *connect.ServerStream[pb.ProcessEvent]) error {
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
	if err := stream.Send(&pb.ProcessEvent{
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
				_ = stream.Send(&pb.ProcessEvent{
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
	waitErr := cmd.Wait()

	exitCode := int32(0)
	errMsg := ""
	if cmd.ProcessState != nil {
		exitCode = int32(cmd.ProcessState.ExitCode())
		// Signal-killed processes report ExitCode -1. Map to 128+signal convention.
		if exitCode == -1 && waitErr != nil {
			exitCode = 137 // default to SIGKILL
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				exitCode = int32(128 + status.Signal())
			}
		}
	}

	return stream.Send(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_End{End: &pb.EndEvent{
			ExitCode: exitCode,
			Exited:   cmd.ProcessState != nil && cmd.ProcessState.Exited(),
			Status:   cmd.ProcessState.String(),
			Error:    errMsg,
		}},
	})
}

func (s *processService) startPipes(ctx context.Context, cmd *exec.Cmd, stream *connect.ServerStream[pb.ProcessEvent]) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	if err := cmd.Start(); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	pid := uint32(cmd.Process.Pid)
	s.processes.Store(pid, &runningProcess{cmd: cmd})
	defer s.processes.Delete(pid)

	if err := stream.Send(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_Start{Start: &pb.StartEvent{Pid: pid}},
	}); err != nil {
		return err
	}

	// Fan stdout + stderr through a multiplex so a single consumer owns
	// stream.Send. connect-go's ServerStream is not safe for concurrent
	// use — direct Send from both readers races the HTTP/1.1 chunked
	// writer and produces malformed frames ("bare LF", "invalid byte in
	// chunk length") observed under load.
	mux := NewMultiplexedChannel[*pb.ProcessEvent](256)
	consumer, _ := mux.Fork()

	sendDone := make(chan error, 1)
	go func() {
		var firstErr error
		for ev := range consumer {
			if firstErr != nil {
				continue // keep draining so the mux can close cleanly
			}
			if err := stream.Send(ev); err != nil {
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
	cmd.Wait()

	// Flush data events to the stream before sending End. Closing the
	// mux drains it, closes the consumer channel, and unblocks sendDone.
	close(mux.Source)
	if sendErr := <-sendDone; sendErr != nil {
		return sendErr
	}

	exitCode := int32(0)
	if cmd.ProcessState != nil {
		exitCode = int32(cmd.ProcessState.ExitCode())
	}

	return stream.Send(&pb.ProcessEvent{
		Event: &pb.ProcessEvent_End{End: &pb.EndEvent{
			ExitCode: exitCode,
			Exited:   cmd.ProcessState != nil && cmd.ProcessState.Exited(),
			Status:   cmd.ProcessState.String(),
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

	if proc.tty != nil {
		if _, err := proc.tty.Write(req.Msg.GetData()); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
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
	if err := proc.cmd.Process.Signal(sig); err != nil {
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
		http.Error(w, `{"error":"use FilesystemService.ListDir for directories"}`, http.StatusBadRequest)
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
