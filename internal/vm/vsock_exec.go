package vm

import (
	"context"
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
	if opts != nil {
		req.Envs = opts.Env
		req.Cwd = opts.WorkingDir
	}

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
	if opts != nil {
		req.Envs = opts.Env
		req.Cwd = opts.WorkingDir
	}

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

// boxdFilesystemClient returns a Connect RPC client for the FilesystemService.
// This is the only surviving boxd file client on the VMD side — raw HTTP
// content transfer (uploadFile/downloadFile, boxdFileURL) was removed
// when file bytes moved onto the edge proxy's /files path. Metadata
// operations (Remove, Move, etc.) still go through this Connect client.
func boxdFilesystemClient(vmIP string) boxdpbconnect.FilesystemServiceClient {
	baseURL := fmt.Sprintf("http://%s:%d", vmIP, boxdPort)
	return boxdpbconnect.NewFilesystemServiceClient(http.DefaultClient, baseURL)
}
