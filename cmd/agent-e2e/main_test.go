package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBoxd mimics boxd's /exec/stream: it reads the exec request (command/args +
// env), runs the harness logic that a real boxd would (echo $ACTOR_EVENT), and
// streams the reply back as boxd-format SSE (`data: {json}\n\n`). This lets the
// full agent-loop runtime be exercised end to end in CI without a VM — the same
// path validated on real hardware with a real boxd.
func fakeBoxd(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/exec/stream") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		event := req.Env["ACTOR_EVENT"] // how boxddeliver delivers the turn event

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		// The harness turn is `printf 'REPLY[%s]' "$ACTOR_EVENT"`; mirror its output.
		out, _ := json.Marshal(map[string]any{"stdout": "REPLY[" + event + "]"})
		_, _ = w.Write([]byte("data: " + string(out) + "\n\n"))
		if fl != nil {
			fl.Flush()
		}
		fin, _ := json.Marshal(map[string]any{"exit_code": 0, "finished": true})
		_, _ = w.Write([]byte("data: " + string(fin) + "\n\n"))
		if fl != nil {
			fl.Flush()
		}
	}))
}

// TestAgentLoopEndToEnd drives the real runtime (Registry+lease → Router+inbox →
// vmdwaker → boxddeliver → /exec/stream → Relay) across multiple turns against a
// boxd-shaped HTTP server, asserting each event reaches the harness (via
// $ACTOR_EVENT) and its reply streams back through the loop in order.
func TestAgentLoopEndToEnd(t *testing.T) {
	srv := fakeBoxd(t)
	defer srv.Close()

	const turns = 3
	results, err := driveTurns(srv.URL+"/exec/stream", "agent-1", turns, harnessTurnArgv)
	if err != nil {
		t.Fatalf("driveTurns: %v", err)
	}
	if len(results) != turns {
		t.Fatalf("got %d turn results, want %d", len(results), turns)
	}
	for i, r := range results {
		want := "REPLY[" + r.payload + "]"
		if r.reply != want {
			t.Errorf("turn %d (%q): reply = %q, want %q", i+1, r.payload, r.reply, want)
		}
	}
}

// TestAgentLoopHarnessFailureSurfaces: a boxd error event ends the turn with the
// error rather than a phantom success — the delivery path propagates failures.
func TestAgentLoopHarnessFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		ev, _ := json.Marshal(map[string]any{"error": "harness crashed", "finished": true})
		_, _ = w.Write([]byte("data: " + string(ev) + "\n\n"))
	}))
	defer srv.Close()

	// The turn errors (the streamer returns the harness error), so the Relay
	// closes with no stdout — driveTurns records an empty reply, not a fake one.
	results, err := driveTurns(srv.URL+"/exec/stream", "agent-err", 1, harnessTurnArgv)
	if err != nil {
		t.Fatalf("driveTurns returned a transport error: %v", err)
	}
	if got := results[0].reply; strings.Contains(got, "REPLY[") {
		t.Errorf("a failed turn must not yield a harness reply, got %q", got)
	}
}
