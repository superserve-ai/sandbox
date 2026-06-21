package boxddeliver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/actor"
)

// sseExecServer emulates boxd /exec/stream: it records the request and writes an
// SSE reply (data: {json}\n\n), including a keepalive comment to exercise the
// decoder's skip path.
func sseExecServer(t *testing.T, captured *execRequest, tokenOut *string, stdoutChunks ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*tokenOut = r.Header.Get(AccessTokenHeader)
		_ = json.NewDecoder(r.Body).Decode(captured)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		writeData := func(v map[string]any) {
			raw, _ := json.Marshal(v)
			_, _ = io.WriteString(w, "data: "+string(raw)+"\n\n")
			if fl != nil {
				fl.Flush()
			}
		}
		_, _ = io.WriteString(w, ": keepalive\n\n") // must be skipped
		for _, c := range stdoutChunks {
			writeData(map[string]any{"stdout": c})
		}
		writeData(map[string]any{"stderr": "warn: ignored"}) // stderr must not reach the reply
		writeData(map[string]any{"exit_code": 0, "finished": true})
	}))
}

func TestHTTPExecStreamerSSE(t *testing.T) {
	var got execRequest
	var token string
	srv := sseExecServer(t, &got, &token, "hello ", "world")
	defer srv.Close()

	exec := NewHTTPExecStreamer(srv.Client(),
		func(string) string { return srv.URL },
		func(string) (string, error) { return "tok-123", nil },
	)

	var out strings.Builder
	err := exec.ExecStream(context.Background(), "sbx-1", []string{"sh", "-c", "claude -p"}, []byte("ping"), func(b []byte) {
		out.Write(b)
	})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	if out.String() != "hello world" {
		t.Errorf("streamed stdout = %q, want %q (stderr/keepalive must be skipped)", out.String(), "hello world")
	}
	if token != "tok-123" {
		t.Errorf("token = %q", token)
	}
	if got.Command != "sh" || strings.Join(got.Args, " ") != "-c claude -p" {
		t.Errorf("command/args = %q %v", got.Command, got.Args)
	}
	// The event payload reaches the harness via $ACTOR_EVENT, not stdin.
	if got.Env[EventEnvVar] != "ping" {
		t.Errorf("event env %s = %q, want ping", EventEnvVar, got.Env[EventEnvVar])
	}
}

func TestHTTPExecStreamerErrorEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"error":"command not found","finished":true}`+"\n\n")
	}))
	defer srv.Close()
	exec := NewHTTPExecStreamer(srv.Client(), func(string) string { return srv.URL }, func(string) (string, error) { return "t", nil })
	if err := exec.ExecStream(context.Background(), "s", []string{"nope"}, nil, func([]byte) {}); err == nil {
		t.Fatal("an SSE error event should surface as an error")
	}
}

func TestHTTPExecStreamerBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	exec := NewHTTPExecStreamer(srv.Client(), func(string) string { return srv.URL }, func(string) (string, error) { return "t", nil })
	if err := exec.ExecStream(context.Background(), "s", []string{"x"}, nil, func([]byte) {}); err == nil {
		t.Fatal("non-2xx should error")
	}
}

// TestExecSSEToRelayEndToEnd: HTTPExecStreamer behind the Deliverer streams the
// harness reply into the turn's Relay — the full production delivery path
// (minus the real proxy), over httptest with boxd's real SSE shape.
func TestExecSSEToRelayEndToEnd(t *testing.T) {
	var got execRequest
	var token string
	srv := sseExecServer(t, &got, &token, "the ", "answer ", "is 42")
	defer srv.Close()
	exec := NewHTTPExecStreamer(srv.Client(), func(string) string { return srv.URL }, func(string) (string, error) { return "t", nil })
	d := New(exec, []string{"harness"})

	relay := actor.NewRelay()
	if err := d.Deliver(context.Background(), "sbx", actor.Event{ID: "e", Payload: []byte("q"), Out: relay}); err != nil {
		t.Fatal(err)
	}
	relay.Close()

	var out strings.Builder
	cur := int64(0)
	for {
		c, ok, err := relay.ReadFrom(context.Background(), cur)
		if err != nil || !ok {
			break
		}
		out.WriteString(string(c.Data))
		cur = c.Seq
	}
	if out.String() != "the answer is 42" {
		t.Fatalf("end-to-end output = %q", out.String())
	}
}
