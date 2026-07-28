package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	pb "github.com/superserve-ai/sandbox/proto/boxdpb"
)

// var, not const, so tests can shorten it.
var sseKeepaliveInterval = 15 * time.Second

// Budget for the sync exec handler's buffered stdout+stderr, measured in
// JSON-encoded bytes so the reply body stays bounded regardless of content —
// unbounded, a single chatty command can exhaust the guest's RAM, and clients
// bound how much of a buffered reply they read anyway. Output past the cap is
// still drained (a full pipe would block the child) but dropped, and the
// reply is flagged truncated; streaming exec forwards instead of holding, so
// it needs no cap.
// var, not const, so tests can shrink it.
var maxSyncExecOutputBytes = 8 << 20

// jsonRuneCost returns how many bytes the rune starting b occupies inside an
// encoding/json string (HTML escaping on) and how many input bytes it spans:
// backslash-escapable characters cost two, characters the encoder writes as
// \uXXXX cost six — including each invalid UTF-8 byte, which encodes as
// \ufffd — and everything else passes through at its own width. A rune split
// across output chunks is charged as invalid bytes: an overcount, never an
// undercount, so the encoded body stays within budget.
func jsonRuneCost(b []byte) (cost, size int) {
	r, size := utf8.DecodeRune(b)
	switch {
	case r == utf8.RuneError && size <= 1:
		return 6, 1
	case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
		return 2, size
	case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
		return 6, size
	default:
		return size, size
	}
}

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
	// Truncated reports that combined output exceeded the sync buffer cap
	// and the tail was dropped; stream the command instead for full output.
	Truncated bool `json:"truncated,omitempty"`
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

	// tRecv..tSpawn covers decode + spawn queueing + fork; the Start event
	// marks the moment the process exists. Returned as response headers so
	// the data-plane proxy can log the guest-side split — boxd's own logs
	// are not collected off the guest.
	tRecv := time.Now()
	var (
		mu        sync.Mutex
		stdout    []byte
		stderr    []byte
		truncated bool
		exitCode  int32
		tSpawn    time.Time
	)
	// appendCapped retains the longest prefix whose encoded cost fits the
	// shared budget. The first dropped rune ends retention for good — a
	// cheaper rune in a later event must not splice past the gap, so each
	// stream stays a prefix of what the command wrote. Callers hold mu.
	budget := maxSyncExecOutputBytes
	appendCapped := func(dst, b []byte) []byte {
		if truncated {
			return dst
		}
		i := 0
		for i < len(b) {
			cost, size := jsonRuneCost(b[i:])
			if cost > budget {
				break
			}
			budget -= cost
			i += size
		}
		if i < len(b) {
			truncated = true
		}
		return append(dst, b[:i]...)
	}
	emit := func(ev *pb.ProcessEvent) error {
		mu.Lock()
		defer mu.Unlock()
		switch x := ev.Event.(type) {
		case *pb.ProcessEvent_Data:
			switch out := x.Data.Output.(type) {
			case *pb.DataEvent_Stdout:
				stdout = appendCapped(stdout, out.Stdout)
			case *pb.DataEvent_Stderr:
				stderr = appendCapped(stderr, out.Stderr)
			case *pb.DataEvent_PtyData:
				stdout = appendCapped(stdout, out.PtyData)
			}
		case *pb.ProcessEvent_Start:
			if tSpawn.IsZero() {
				tSpawn = time.Now()
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

	// The marker rides in stderr so every consumer sees why the output ends
	// early, not only clients that read the structured flag. Appended past
	// the budget; its fixed size keeps the reply bounded.
	if truncated {
		stderr = append(stderr, fmt.Sprintf(
			"\n[superserve] output truncated: combined stdout/stderr exceeded the sync exec limit (%d bytes); use /exec/stream or redirect output to a file for full output\n",
			maxSyncExecOutputBytes)...)
	}

	if !tSpawn.IsZero() {
		w.Header().Set("X-Boxd-Spawn-Ms", fmt.Sprintf("%d", tSpawn.Sub(tRecv).Milliseconds()))
		w.Header().Set("X-Boxd-Run-Ms", fmt.Sprintf("%d", time.Since(tSpawn).Milliseconds()))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(execResponse{
		Stdout:    string(stdout),
		Stderr:    string(stderr),
		ExitCode:  exitCode,
		Truncated: truncated,
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
