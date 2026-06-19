package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// var, not const, so tests can shorten it.
var sseKeepaliveInterval = 15 * time.Second

// CodeInvalidArgument → 400, everything else → 500.
func writeRunError(w http.ResponseWriter, err error) {
	var ce *connect.Error
	if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
		http.Error(w, ce.Message(), http.StatusBadRequest)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func runErrorCode(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
		return "bad_request"
	}
	return "exec_failed"
}

// execRequest shape mirrors the controlplane exec body so the SDK can
// target either with the same payload.
type execRequest struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	TimeoutS   int               `json:"timeout_s,omitempty"`
}

type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int32  `json:"exit_code"`
}

func (r *execRequest) toStartRequest() *pb.StartRequest {
	timeoutMs := uint32(r.TimeoutS) * 1000
	if timeoutMs == 0 {
		timeoutMs = 30 * 1000
	}
	// No args → wrap in /bin/sh -c (shell-string mode). Args provided
	// → run command raw. Matches OpenAPI ExecRequest contract.
	cmd, args := r.Command, r.Args
	if len(args) == 0 {
		cmd = "/bin/sh"
		args = []string{"-c", r.Command}
	}
	return &pb.StartRequest{
		Cmd:       cmd,
		Args:      args,
		Envs:      r.Env,
		Cwd:       r.WorkingDir,
		TimeoutMs: timeoutMs,
	}
}

// handleExec runs the command to completion and returns the result in
// one JSON body.
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
				stdout = append(stdout, out.PtyData...)
			}
		case *pb.ProcessEvent_End:
			exitCode = x.End.ExitCode
		}
		return nil
	}

	if err := s.runProcess(r.Context(), req.toStartRequest(), emit, false); err != nil {
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

// handleExecStream streams stdout/stderr/end events as SSE.
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

	// emit and the keepalive ticker both write to w; serialize them.
	var writeMu sync.Mutex

	keepaliveCtx, stopKeepalive := context.WithCancel(r.Context())
	defer stopKeepalive()
	go func() {
		ticker := time.NewTicker(sseKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-keepaliveCtx.Done():
				return
			case <-ticker.C:
				writeMu.Lock()
				_, _ = fmt.Fprint(w, ": keepalive\n\n")
				flusher.Flush()
				writeMu.Unlock()
			}
		}
	}()

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
			return nil
		}

		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if err := s.runProcess(r.Context(), req.toStartRequest(), emit, false); err != nil {
		errEvent, _ := json.Marshal(map[string]any{
			"error":    err.Error(),
			"code":     runErrorCode(err),
			"finished": true,
		})
		writeMu.Lock()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", errEvent)
		flusher.Flush()
		writeMu.Unlock()
	}
}
