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
	"path/filepath"
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

	mux := http.NewServeMux()

	env := &sandboxEnv{}

	// Connect RPC services.
	procService := &processService{
		processes: &sync.Map{},
		env:       env,
	}
	mux.Handle(boxdpbconnect.NewProcessServiceHandler(procService))
	mux.Handle(boxdpbconnect.NewFilesystemServiceHandler(&filesystemService{}))

	// Raw HTTP endpoints (file content transfer + health + init).
	mux.HandleFunc("/files", handleFiles)
	mux.HandleFunc("/init", handleInit(env))
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

func handleInit(env *sandboxEnv) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			EnvVars map[string]string `json:"env_vars"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if len(body.EnvVars) > 0 {
			env.set(body.EnvVars)
			log.Printf("init: set %d env var(s)", len(body.EnvVars))
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// ---------------------------------------------------------------------------
// Process service (Connect RPC)
// ---------------------------------------------------------------------------

type runningProcess struct {
	cmd *exec.Cmd
	tty *os.File // nil for non-PTY processes.
}

// sandboxEnv holds sandbox-level environment variables set via POST /init.
// These are injected into every process boxd spawns, underneath per-request
// overrides from StartRequest.envs.
type sandboxEnv struct {
	mu   sync.RWMutex
	vars map[string]string
}

func (e *sandboxEnv) set(vars map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vars = vars
}

func (e *sandboxEnv) environ() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.vars))
	for k, v := range e.vars {
		out = append(out, k+"="+v)
	}
	return out
}

type processService struct {
	boxdpbconnect.UnimplementedProcessServiceHandler
	processes *sync.Map // pid → *runningProcess
	env       *sandboxEnv
}

// buildEnv assembles the environment for a child process. Layers (last wins):
// 1. OS base env  2. system defaults (PATH, HOME, USER)  3. sandbox-level
// env vars from /init  4. per-request env vars from StartRequest.envs.
func (s *processService) buildEnv(requestEnvs map[string]string) []string {
	env := append(os.Environ(),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME="+defaultHome,
		"USER=user",
	)
	env = append(env, s.env.environ()...)
	for k, v := range requestEnvs {
		env = append(env, k+"="+v)
	}
	return env
}

func (s *processService) Start(ctx context.Context, req *connect.Request[pb.StartRequest], stream *connect.ServerStream[pb.ProcessEvent]) error {
	msg := req.Msg

	cmdName := msg.GetCmd()
	if cmdName == "" {
		cmdName = defaultShell
	}

	args := msg.GetArgs()
	cmd := exec.Command(cmdName, args...)
	cmd.Dir = msg.GetCwd()
	if cmd.Dir == "" {
		cmd.Dir = defaultHome
	}

	cmd.Env = s.buildEnv(msg.GetEnvs())

	timeout := time.Duration(msg.GetTimeoutMs()) * time.Millisecond
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, cmdName, args...)
		cmd.Dir = msg.GetCwd()
		if cmd.Dir == "" {
			cmd.Dir = defaultHome
		}
		cmd.Env = s.buildEnv(msg.GetEnvs())
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
				_ = stream.Send(&pb.ProcessEvent{
					Event: &pb.ProcessEvent_Data{Data: &pb.DataEvent{
						Output: &pb.DataEvent_Stdout{Stdout: data},
					}},
				})
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
				_ = stream.Send(&pb.ProcessEvent{
					Event: &pb.ProcessEvent_Data{Data: &pb.DataEvent{
						Output: &pb.DataEvent_Stderr{Stderr: data},
					}},
				})
			}
			if readErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	cmd.Wait()

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
