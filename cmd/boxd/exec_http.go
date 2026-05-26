package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// writeRunError maps a runProcess() error onto an HTTP response code +
// JSON body. CodeInvalidArgument (command not in PATH, invalid user)
// becomes 400 to match the controlplane's behavior; everything else is
// 500.
func writeRunError(w http.ResponseWriter, err error) {
	var ce *connect.Error
	if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
		http.Error(w, ce.Message(), http.StatusBadRequest)
		return
	}
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// runErrorCode names the SSE error event code for a runProcess() error.
// Matches the controlplane streaming.go convention (bad_request /
// exec_failed) so SDK error parsing is identical across transports.
func runErrorCode(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
		return "bad_request"
	}
	return "exec_failed"
}

// HTTP /exec request shape, mirrors the controlplane sandboxExecRequest
// shape (handlers.go) so the SDK can target either with the same body.
type execRequest struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	TimeoutS   int               `json:"timeout_s,omitempty"`
}

// HTTP /exec response shape, mirrors the controlplane ExecSandbox
// response (handlers.go:1597).
type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int32  `json:"exit_code"`
}

// toStartRequest maps the HTTP-friendly shape onto the gRPC StartRequest.
// Empty timeout becomes 30s (matches controlplane default in handlers.go
// and streaming.go).
func (r *execRequest) toStartRequest() *pb.StartRequest {
	timeoutMs := uint32(r.TimeoutS) * 1000
	if timeoutMs == 0 {
		timeoutMs = 30 * 1000
	}
	return &pb.StartRequest{
		Cmd:       r.Command,
		Args:      r.Args,
		Envs:      r.Env,
		Cwd:       r.WorkingDir,
		TimeoutMs: timeoutMs,
	}
}

// handleExec is the synchronous data-plane exec endpoint. Reads a JSON
// body, runs the command to completion in-VM, and returns
// {stdout, stderr, exit_code}. Same response shape as the controlplane's
// POST /sandboxes/{id}/exec so SDK error/parsing code paths are shared.
func (s *processService) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Command == "" {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}

	var (
		mu       sync.Mutex
		stdout   []byte
		stderr   []byte
		exitCode int32
	)
	emit := func(ev *pb.ProcessEvent) error {
		mu.Lock()
		defer mu.Unlock()
		switch x := ev.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch out := x.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				stdout = append(stdout, out.Stdout...)
			case *pb.DataEvent_Stderr:
				stderr = append(stderr, out.Stderr...)
			case *pb.DataEvent_PtyData:
				// Synchronous /exec never sets pty; if a future caller does,
				// route pty output to stdout so it's not silently lost.
				stdout = append(stdout, out.PtyData...)
			}
		case *pb.ProcessEvent_End:
			exitCode = x.End.ExitCode
		}
		return nil
	}

	if err := s.runProcess(r.Context(), req.toStartRequest(), emit); err != nil {
		// Same fail-loud surface as the gRPC handler: ConnectError carries
		// a code we map to HTTP status. CodeInvalidArgument (e.g. command
		// not in PATH) → 400 to match controlplane behavior.
		writeRunError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(execResponse{
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		ExitCode: exitCode,
	})
}

// handleExecStream is the SSE data-plane exec endpoint. Same input
// shape as handleExec; emits incremental {timestamp, stdout?, stderr?,
// exit_code?, finished?} events matching the controlplane's
// POST /sandboxes/{id}/exec/stream shape (streaming.go).
func (s *processService) handleExecStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Command == "" {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Single writer to satisfy emit's documented single-consumer
	// contract — runProcess multiplexes stdout/stderr already, so all
	// emit calls happen serially from the goroutine that drains the
	// internal channel.
	emit := func(ev *pb.ProcessEvent) error {
		payload := map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		}
		switch x := ev.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch out := x.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				payload["stdout"] = string(out.Stdout)
			case *pb.DataEvent_Stderr:
				payload["stderr"] = string(out.Stderr)
			case *pb.DataEvent_PtyData:
				payload["stdout"] = string(out.PtyData)
			}
		case *pb.ProcessEvent_End:
			payload["exit_code"] = x.End.ExitCode
			payload["finished"] = true
		case *pb.ProcessEvent_Start:
			// Start events are internal-only; clients only care about
			// data + end. Suppress to keep the SSE wire compact and
			// match the controlplane's externally-observed shape.
			return nil
		}

		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if err := s.runProcess(r.Context(), req.toStartRequest(), emit); err != nil {
		// Headers are already committed — surface the failure as a coded
		// error event so the client can distinguish it from a normal exit.
		errEvent, _ := json.Marshal(map[string]any{
			"error":    err.Error(),
			"code":     runErrorCode(err),
			"finished": true,
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", errEvent)
		flusher.Flush()
	}
}
