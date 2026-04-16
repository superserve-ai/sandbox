package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"connectrpc.com/connect"

	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// ExecResult holds the result of a command execution inside a VM.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// boxdPort must match httpPort in cmd/boxd/main.go.
const boxdPort = 49983

// boxdProcessClient returns a Connect RPC client for the ProcessService.
func boxdProcessClient(vmIP string) boxdpbconnect.ProcessServiceClient {
	baseURL := fmt.Sprintf("http://%s:%d", vmIP, boxdPort)
	return boxdpbconnect.NewProcessServiceClient(http.DefaultClient, baseURL)
}

// ExecOptions holds optional parameters for command execution.
type ExecOptions struct {
	Args       []string
	Env        map[string]string
	WorkingDir string
}

// defaultExecEnv is the baseline environment passed to every command
// executed inside a VM. Without at least PATH, /bin/sh can't find
// binaries in /usr/local/bin (where pip, node, etc. live in most OCI
// base images). Callers can override individual keys via ExecOptions.Env.
var defaultExecEnv = map[string]string{
	"PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME":  "/home/user",
	"USER":  "user",
	"TERM":  "xterm",
	"LANG":  "C.UTF-8",
	"SHELL": "/bin/sh",
}

// mergedEnv returns defaultExecEnv with caller-supplied overrides applied.
func mergedEnv(caller map[string]string) map[string]string {
	env := make(map[string]string, len(defaultExecEnv)+len(caller))
	for k, v := range defaultExecEnv {
		env[k] = v
	}
	for k, v := range caller {
		env[k] = v
	}
	return env
}

// httpExec runs a command via Connect RPC ProcessService.Start and collects the result.
func httpExec(ctx context.Context, vmIP string, command string, timeout time.Duration, opts *ExecOptions) (*ExecResult, error) {
	client := boxdProcessClient(vmIP)

	timeoutMs := uint32(0)
	if timeout > 0 {
		timeoutMs = uint32(timeout.Milliseconds())
	}

	req := &pb.StartRequest{
		TimeoutMs: timeoutMs,
	}

	// If args are provided, use command as the binary directly.
	// Otherwise, wrap in /bin/sh -c for shell execution.
	if opts != nil && len(opts.Args) > 0 {
		req.Cmd = command
		req.Args = opts.Args
	} else {
		req.Cmd = "/bin/sh"
		req.Args = []string{"-c", command}
	}
	var callerEnv map[string]string
	if opts != nil {
		callerEnv = opts.Env
		req.Cwd = opts.WorkingDir
	}
	req.Envs = mergedEnv(callerEnv)

	stream, err := client.Start(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, fmt.Errorf("start exec: %w", err)
	}

	var result ExecResult

	for stream.Receive() {
		event := stream.Msg()
		switch e := event.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch o := e.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				result.Stdout = append(result.Stdout, o.Stdout...)
			case *pb.DataEvent_Stderr:
				result.Stderr = append(result.Stderr, o.Stderr...)
			case *pb.DataEvent_PtyData:
				result.Stdout = append(result.Stdout, o.PtyData...)
			}
		case *pb.ProcessEvent_End:
			result.ExitCode = int(e.End.ExitCode)
		}
	}

	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("exec stream: %w", err)
	}

	return &result, nil
}

// httpExecStream runs a command via Connect RPC and calls onChunk for each
// stdout/stderr chunk as it arrives, delivering true streaming output.
func httpExecStream(ctx context.Context, vmIP string, command string, timeout time.Duration, opts *ExecOptions,
	onChunk func(stdout, stderr []byte, exitCode int32, finished bool),
) error {
	client := boxdProcessClient(vmIP)

	timeoutMs := uint32(0)
	if timeout > 0 {
		timeoutMs = uint32(timeout.Milliseconds())
	}

	req := &pb.StartRequest{
		TimeoutMs: timeoutMs,
	}
	if opts != nil && len(opts.Args) > 0 {
		req.Cmd = command
		req.Args = opts.Args
	} else {
		req.Cmd = "/bin/sh"
		req.Args = []string{"-c", command}
	}
	var callerEnv map[string]string
	if opts != nil {
		callerEnv = opts.Env
		req.Cwd = opts.WorkingDir
	}
	req.Envs = mergedEnv(callerEnv)

	stream, err := client.Start(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("start exec: %w", err)
	}

	for stream.Receive() {
		event := stream.Msg()
		switch e := event.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch o := e.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				onChunk(o.Stdout, nil, 0, false)
			case *pb.DataEvent_Stderr:
				onChunk(nil, o.Stderr, 0, false)
			case *pb.DataEvent_PtyData:
				onChunk(o.PtyData, nil, 0, false)
			}
		case *pb.ProcessEvent_End:
			onChunk(nil, nil, e.End.ExitCode, true)
		}
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("exec stream: %w", err)
	}

	return nil
}

// waitForHTTPHealth polls boxd's /health endpoint until it responds or timeout.
func waitForHTTPHealth(ctx context.Context, vmIP string, timeout time.Duration) error {
	url := fmt.Sprintf("http://%s:%d/health", vmIP, boxdPort)
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("boxd health check not ready after %s", timeout)
}

var boxdInitClient = &http.Client{Timeout: 5 * time.Second}


// postBoxdInit sends sandbox-level environment variables to boxd's /init
// endpoint. These vars are injected into every process boxd spawns.
func postBoxdInit(ctx context.Context, vmIP string, envVars map[string]string) error {
	if len(envVars) == 0 {
		return nil
	}

	body := struct {
		EnvVars map[string]string `json:"env_vars"`
	}{EnvVars: envVars}

	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal init body: %w", err)
	}

	url := fmt.Sprintf("http://%s:%d/init", vmIP, boxdPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("create init request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := boxdInitClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /init: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /init: status %d", resp.StatusCode)
	}
	return nil
}

// boxdFilesystemClient returns a Connect RPC client for boxd's
// FilesystemService, used for metadata ops (Remove, Move, etc.) inside
// a VM. File byte transfer goes through the edge proxy directly.
func boxdFilesystemClient(vmIP string) boxdpbconnect.FilesystemServiceClient {
	baseURL := fmt.Sprintf("http://%s:%d", vmIP, boxdPort)
	return boxdpbconnect.NewFilesystemServiceClient(http.DefaultClient, baseURL)
}
