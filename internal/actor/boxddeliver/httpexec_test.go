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

func TestHTTPExecStreamer(t *testing.T) {
	var gotToken, gotCommand, gotStdin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get(AccessTokenHeader)
		var req execRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotCommand = req.Command
		gotStdin = req.Stdin
		// Stream a reply in two writes (flush between) to exercise chunked read.
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "hello ")
		if fl != nil {
			fl.Flush()
		}
		_, _ = io.WriteString(w, "world")
	}))
	defer srv.Close()

	exec := NewHTTPExecStreamer(srv.Client(),
		func(string) string { return srv.URL },
		func(string) (string, error) { return "tok-123", nil },
	)

	var out strings.Builder
	err := exec.ExecStream(context.Background(), "sbx-1", []string{"claude", "-p"}, []byte("ping"), func(b []byte) {
		out.Write(b)
	})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	if out.String() != "hello world" {
		t.Errorf("streamed output = %q, want %q", out.String(), "hello world")
	}
	if gotToken != "tok-123" {
		t.Errorf("token = %q, want tok-123", gotToken)
	}
	if gotCommand != "claude -p" {
		t.Errorf("command = %q, want 'claude -p'", gotCommand)
	}
	if gotStdin != "ping" {
		t.Errorf("stdin = %q, want ping", gotStdin)
	}
}

func TestHTTPExecStreamerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	exec := NewHTTPExecStreamer(srv.Client(), func(string) string { return srv.URL }, func(string) (string, error) { return "t", nil })
	if err := exec.ExecStream(context.Background(), "s", []string{"x"}, nil, func([]byte) {}); err == nil {
		t.Fatal("non-2xx exec should error")
	}
}

// TestHTTPExecStreamerEndToEnd: the HTTP exec streamer behind the Deliverer
// streams a harness reply into the turn's Relay — the full production delivery
// path (minus the real proxy), exercised over httptest.
func TestHTTPExecStreamerEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "the answer is 42")
	}))
	defer srv.Close()
	exec := NewHTTPExecStreamer(srv.Client(), func(string) string { return srv.URL }, func(string) (string, error) { return "t", nil })
	d := New(exec, []string{"harness"})

	relay := actor.NewRelay()
	if err := d.Deliver(context.Background(), "sbx", actor.Event{ID: "e", Payload: []byte("q"), Out: relay}); err != nil {
		t.Fatal(err)
	}
	relay.Close()

	var got strings.Builder
	cur := int64(0)
	for {
		c, ok, err := relay.ReadFrom(context.Background(), cur)
		if err != nil || !ok {
			break
		}
		got.WriteString(string(c.Data))
		cur = c.Seq
	}
	if got.String() != "the answer is 42" {
		t.Fatalf("end-to-end delivered output = %q", got.String())
	}
}
