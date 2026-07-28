package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func newProcessService() *processService {
	return &processService{
		processes: &sync.Map{},
		ctx:       &sandboxContext{},
	}
}

func TestHandleExec_Success(t *testing.T) {
	s := newProcessService()
	body := `{"command":"/bin/sh","args":["-c","printf hi; printf err 1>&2; exit 0"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v; body: %s", err, w.Body.String())
	}
	if resp.Stdout != "hi" {
		t.Errorf("stdout = %q, want %q", resp.Stdout, "hi")
	}
	if resp.Stderr != "err" {
		t.Errorf("stderr = %q, want %q", resp.Stderr, "err")
	}
	if resp.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", resp.ExitCode)
	}
	for _, hdr := range []string{"X-Boxd-Spawn-Ms", "X-Boxd-Run-Ms"} {
		if w.Header().Get(hdr) == "" {
			t.Errorf("missing timing header %s", hdr)
		}
	}
}

func TestHandleExec_OutputCapped(t *testing.T) {
	old := maxSyncExecOutputBytes
	maxSyncExecOutputBytes = 16
	defer func() { maxSyncExecOutputBytes = old }()

	s := newProcessService()
	// 64 bytes of stdout against a 16-byte cap; the command must still run
	// to completion (drained, not blocked) and exit 0.
	body := `{"command":"/bin/sh","args":["-c","printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v; body: %s", err, w.Body.String())
	}
	if len(resp.Stdout) != 16 {
		t.Errorf("stdout length = %d, want 16 (capped)", len(resp.Stdout))
	}
	if !resp.Truncated {
		t.Error("truncated = false, want true")
	}
	if !strings.Contains(resp.Stderr, "output truncated") {
		t.Errorf("stderr = %q, want the truncation marker", resp.Stderr)
	}
	if resp.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", resp.ExitCode)
	}
}

func TestHandleExec_OutputCapCountsEncodedSize(t *testing.T) {
	old := maxSyncExecOutputBytes
	maxSyncExecOutputBytes = 16
	defer func() { maxSyncExecOutputBytes = old }()

	s := newProcessService()
	// NUL bytes encode as six-byte \u0000 escapes, so a 16-byte encoded
	// budget retains only two of the four despite 4 < 16 raw bytes.
	body := `{"command":"/bin/sh","args":["-c","head -c 4 /dev/zero"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v; body: %s", err, w.Body.String())
	}
	if len(resp.Stdout) != 2 {
		t.Errorf("stdout length = %d, want 2 (two 6-byte escapes fit a 16-byte budget)", len(resp.Stdout))
	}
	if !resp.Truncated {
		t.Error("truncated = false, want true")
	}
}

func TestHandleExec_OutputCapChargesInvalidUTF8(t *testing.T) {
	old := maxSyncExecOutputBytes
	maxSyncExecOutputBytes = 16
	defer func() { maxSyncExecOutputBytes = old }()

	s := newProcessService()
	// Each invalid byte encodes as a six-byte replacement-rune escape, so a
	// 16-byte encoded budget retains only two of the four 0xff bytes.
	body := `{"command":"/bin/sh","args":["-c","printf '\\377\\377\\377\\377'"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v; body: %s", err, w.Body.String())
	}
	if want := strings.Repeat(string(utf8.RuneError), 2); resp.Stdout != want {
		t.Errorf("stdout = %q, want %q (two replacement runes)", resp.Stdout, want)
	}
	if !resp.Truncated {
		t.Error("truncated = false, want true")
	}
}

func TestHandleExec_NoRetentionAfterFirstDrop(t *testing.T) {
	old := maxSyncExecOutputBytes
	maxSyncExecOutputBytes = 2
	defer func() { maxSyncExecOutputBytes = old }()

	s := newProcessService()
	// Three separate writes: 'a' fits (budget 1 left), the newline costs 2
	// and is dropped, and the trailing 'x' would fit the leftover budget but
	// must not — retained output stays a prefix, never a splice.
	body := `{"command":"/bin/sh","args":["-c","printf a; sleep 0.3; printf '\\n'; sleep 0.3; printf x"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v; body: %s", err, w.Body.String())
	}
	if resp.Stdout != "a" {
		t.Errorf("stdout = %q, want %q (no bytes retained past the first drop)", resp.Stdout, "a")
	}
	if !resp.Truncated {
		t.Error("truncated = false, want true")
	}
}

func TestHandleExec_NonzeroExit(t *testing.T) {
	s := newProcessService()
	body := `{"command":"/bin/sh","args":["-c","exit 7"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (non-zero exit is NOT an HTTP error)", w.Code, http.StatusOK)
	}
	var resp execResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ExitCode != 7 {
		t.Errorf("exit_code = %d, want 7", resp.ExitCode)
	}
}

func TestHandleExec_BadJSON(t *testing.T) {
	s := newProcessService()
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(`{not json`))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleExec_MissingCommand(t *testing.T) {
	s := newProcessService()
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleExec_WrongMethod(t *testing.T) {
	s := newProcessService()
	req := httptest.NewRequest(http.MethodGet, "/exec", nil)
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleExec_CommandNotFound_400(t *testing.T) {
	s := newProcessService()
	// args mode bypasses shell-wrap so we test the PATH-lookup branch.
	body := `{"command":"this-binary-does-not-exist-anywhere","args":["x"]}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (resolve error → 400)", w.Code, http.StatusBadRequest)
	}
}

func TestHandleExec_ShellWrapsWhenNoArgs(t *testing.T) {
	s := newProcessService()
	body := `{"command":"echo hello world","working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Stdout != "hello world\n" {
		t.Errorf("stdout = %q, want %q", resp.Stdout, "hello world\n")
	}
	if resp.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", resp.ExitCode)
	}
}

func TestHandleExec_ArgsModeSkipsShellWrap(t *testing.T) {
	s := newProcessService()
	// Shell metacharacters as literal args — would be interpreted in
	// shell-wrap mode; here they should reach echo unchanged.
	body := `{"command":"echo","args":["$HOME","|","wc"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExec(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp execResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Stdout != "$HOME | wc\n" {
		t.Errorf("stdout = %q, want %q (literal, no shell expansion)", resp.Stdout, "$HOME | wc\n")
	}
}

// parseSSEEvents extracts each `data: {...}\n\n` block from an SSE
// response body and decodes the JSON payload.
func parseSSEEvents(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var ev map[string]any
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("decode SSE payload %q: %v", payload, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestHandleExecStream_Success(t *testing.T) {
	s := newProcessService()
	body := `{"command":"/bin/sh","args":["-c","printf one; printf two; exit 0"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec/stream", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExecStream(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	events := parseSSEEvents(t, w.Body.Bytes())
	if len(events) < 2 {
		t.Fatalf("expected ≥2 events (data + end); got %d: %v", len(events), events)
	}

	// Concatenate all stdout chunks; SSE may emit them in 1+ events.
	var stdout strings.Builder
	var sawFinished bool
	var exitCode float64
	for _, ev := range events {
		if v, ok := ev["stdout"].(string); ok {
			stdout.WriteString(v)
		}
		if f, ok := ev["finished"].(bool); ok && f {
			sawFinished = true
			if c, ok := ev["exit_code"].(float64); ok {
				exitCode = c
			}
		}
	}
	if stdout.String() != "onetwo" {
		t.Errorf("aggregated stdout = %q, want %q", stdout.String(), "onetwo")
	}
	if !sawFinished {
		t.Error("never saw finished=true event")
	}
	if exitCode != 0 {
		t.Errorf("exit_code = %v, want 0", exitCode)
	}
}

func TestHandleExecStream_WrongMethod(t *testing.T) {
	s := newProcessService()
	req := httptest.NewRequest(http.MethodGet, "/exec/stream", nil)
	w := httptest.NewRecorder()

	s.handleExecStream(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// Keepalive frame appears + emit still works; under -race, also catches
// any future regression that drops writeMu.
func TestHandleExecStream_KeepaliveFiresAndDoesNotRaceWithEmit(t *testing.T) {
	prev := sseKeepaliveInterval
	sseKeepaliveInterval = 20 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = prev })

	s := newProcessService()
	body := `{"command":"/bin/sh","args":["-c","printf one; sleep 0.1; printf two; exit 0"],"working_dir":"/tmp"}`
	req := httptest.NewRequest(http.MethodPost, "/exec/stream", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExecStream(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	raw := w.Body.String()
	if !strings.Contains(raw, ": keepalive") {
		t.Errorf("no keepalive comment frame in body; got: %q", raw)
	}

	events := parseSSEEvents(t, w.Body.Bytes())
	var stdout strings.Builder
	var sawFinished bool
	for _, ev := range events {
		if v, ok := ev["stdout"].(string); ok {
			stdout.WriteString(v)
		}
		if f, ok := ev["finished"].(bool); ok && f {
			sawFinished = true
		}
	}
	if stdout.String() != "onetwo" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "onetwo")
	}
	if !sawFinished {
		t.Error("never saw finished=true event")
	}
}

func TestHandleExecStream_BadCommand_EmitsErrorEvent(t *testing.T) {
	s := newProcessService()
	// args mode bypasses shell-wrap so missing-binary surfaces as an error event.
	body := `{"command":"this-binary-does-not-exist-anywhere","args":["x"]}`
	req := httptest.NewRequest(http.MethodPost, "/exec/stream", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleExecStream(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (headers commit before runProcess fails)", w.Code)
	}
	events := parseSSEEvents(t, w.Body.Bytes())
	if len(events) == 0 {
		t.Fatal("no events emitted")
	}
	last := events[len(events)-1]
	if last["code"] != "bad_request" {
		t.Errorf("last event code = %q, want bad_request", last["code"])
	}
	if last["finished"] != true {
		t.Errorf("last event finished = %v, want true", last["finished"])
	}
}
