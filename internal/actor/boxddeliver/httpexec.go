package boxddeliver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// HTTPExecStreamer is the production ExecStreamer over the sandbox exec path. It
// POSTs the harness turn command to the sandbox's exec-stream endpoint
// (proxy → boxd /exec/stream) with the sandbox access token and forwards the
// harness's stdout into the turn's Relay. The wire contract is matched to boxd's
// server (cmd/boxd/exec_http.go): a JSON request and an SSE response.
//
// The per-sandbox URL and access token are injected resolvers, so this stays
// decoupled from the control plane's URL scheme / token-minting and unit-testable.
type HTTPExecStreamer struct {
	client   *http.Client
	urlFor   func(sandboxID string) string
	tokenFor func(sandboxID string) (string, error)
}

// AccessTokenHeader is the header the sandbox edge (proxy/boxd) authenticates
// exec requests with.
const AccessTokenHeader = "X-Access-Token"

// EventEnvVar is how the turn's event payload reaches the in-guest harness:
// boxd's exec has no stdin, so the payload is passed as an environment variable
// the harness reads at the start of its turn.
const EventEnvVar = "ACTOR_EVENT"

// NewHTTPExecStreamer builds a streamer. urlFor returns the exec-stream URL for a
// sandbox (e.g. https://boxd-<id>.sandbox.superserve.ai/exec/stream); tokenFor
// returns its per-sandbox access token.
func NewHTTPExecStreamer(client *http.Client, urlFor func(string) string, tokenFor func(string) (string, error)) *HTTPExecStreamer {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPExecStreamer{client: client, urlFor: urlFor, tokenFor: tokenFor}
}

var _ ExecStreamer = (*HTTPExecStreamer)(nil)

// execRequest mirrors boxd's exec request (cmd/boxd/exec_http.go). No stdin
// field exists; the event payload is delivered via Env[EventEnvVar].
type execRequest struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// ExecStream runs the harness turn command in the sandbox with the event in
// $ACTOR_EVENT and streams the harness stdout into onOut, decoding boxd's SSE
// response (`data: {json}\n\n` with stdout/stderr/exit_code fields). Returns
// when the stream ends.
func (h *HTTPExecStreamer) ExecStream(ctx context.Context, sandboxID string, argv []string, eventPayload []byte, onOut func([]byte)) error {
	if len(argv) == 0 {
		return fmt.Errorf("exec: empty turn command")
	}
	token, err := h.tokenFor(sandboxID)
	if err != nil {
		return fmt.Errorf("exec: resolve token for %s: %w", sandboxID, err)
	}
	reqBody := execRequest{Command: argv[0], Env: map[string]string{EventEnvVar: string(eventPayload)}}
	if len(argv) > 1 {
		reqBody.Args = argv[1:]
	}
	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.urlFor(sandboxID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(AccessTokenHeader, token)

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("exec %s: status %d", sandboxID, resp.StatusCode)
	}
	return decodeExecSSE(resp.Body, onOut)
}

// sseEvent is the per-event payload boxd writes (cmd/boxd/exec_http.go).
type sseEvent struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error"`
	ExitCode *int32 `json:"exit_code"`
	Finished bool   `json:"finished"`
}

// decodeExecSSE parses boxd's SSE stream and forwards stdout (only) to onOut.
// `: keepalive` comments and blank lines are skipped; an error event ends the
// stream with that error.
func decodeExecSSE(r interface{ Read([]byte) (int, error) }, onOut func([]byte)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue // ": keepalive" comments, blank separators
		}
		var ev sseEvent
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Error != "" {
			return fmt.Errorf("harness turn failed: %s", ev.Error)
		}
		if ev.Stdout != "" {
			onOut([]byte(ev.Stdout))
		}
		// stderr is captured by the platform log path, not the reply stream.
	}
	return sc.Err()
}
