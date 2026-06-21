package boxddeliver

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestHTTPExecStreamerAgainstRealBoxd drives the production streamer against a
// REAL boxd over its /exec/stream endpoint. Gated on BOXD_ADDR (host:port of a
// running boxd). It proves the full wire contract end to end: the request shape
// (command/args + the event in $ACTOR_EVENT), boxd actually running the command
// with that env, and decoding boxd's SSE reply back into the Relay's onOut.
//
// Run it against a boxd started on a Linux host:
//
//	boxd &                                  # listens on 0.0.0.0:49983
//	BOXD_ADDR=127.0.0.1:49983 go test -run TestHTTPExecStreamerAgainstRealBoxd ./internal/actor/boxddeliver/
func TestHTTPExecStreamerAgainstRealBoxd(t *testing.T) {
	addr := os.Getenv("BOXD_ADDR")
	if addr == "" {
		t.Skip("set BOXD_ADDR=host:port of a running boxd to run the live exec test")
	}

	s := NewHTTPExecStreamer(
		&http.Client{Timeout: 15 * time.Second},
		func(string) string { return "http://" + addr + "/exec/stream" },
		// boxd itself does not authenticate /exec/stream (the edge proxy does), so
		// no token is needed when hitting boxd directly.
		func(string) (string, error) { return "", nil },
	)

	var out bytes.Buffer
	const payload = "hello-event-42"
	err := s.ExecStream(
		context.Background(),
		"sbx-live",
		// The harness "turn": echo the event payload back. A real harness reads
		// $ACTOR_EVENT the same way.
		[]string{"sh", "-c", "printf 'reply:%s' \"$ACTOR_EVENT\""},
		[]byte(payload),
		func(b []byte) { out.Write(b) },
	)
	if err != nil {
		t.Fatalf("ExecStream against real boxd: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "reply:"+payload) {
		t.Fatalf("harness reply did not carry the event payload; got %q, want it to contain %q",
			got, "reply:"+payload)
	}
}
