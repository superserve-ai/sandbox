package boxddeliver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPExecStreamer is the production ExecStreamer over the sandbox exec path:
// it POSTs the harness turn command to the sandbox's exec-stream endpoint
// (proxy → boxd) with the sandbox's access token and streams the response body
// into onOut. The per-sandbox URL and access token are injected resolvers so
// this stays testable and decoupled from the control plane's URL scheme /
// token-minting.
//
// Wire it in controlplane main:
//
//	exec := boxddeliver.NewHTTPExecStreamer(httpClient, urlForSandbox, tokenForSandbox)
//	deliverer := boxddeliver.New(exec, harnessTurnArgv)
type HTTPExecStreamer struct {
	client   *http.Client
	urlFor   func(sandboxID string) string
	tokenFor func(sandboxID string) (string, error)
}

// AccessTokenHeader is the header the sandbox edge (proxy/boxd) authenticates
// exec requests with.
const AccessTokenHeader = "X-Access-Token"

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

// execRequest mirrors boxd's exec request shape (command as a single string).
type execRequest struct {
	Command string `json:"command"`
	Stdin   string `json:"stdin,omitempty"`
}

// ExecStream POSTs the command to the sandbox and streams the response into
// onOut.
//
// NOTE (live-protocol detail to validate against running boxd): boxd's
// streaming exec surface is a connect-go/protobuf server stream (stdout/stderr
// framed messages), not a raw byte body. This implements the transport-level
// contract — URL, X-Access-Token, request body, and chunked streaming copy —
// which is what's unit-testable here; the production build should decode the
// connect-go ExecChunk frames (stdout only → the outbox) rather than copy the
// raw body. Swapping the decode is local to this method; the Deliverer/Relay
// path above is unaffected.
func (h *HTTPExecStreamer) ExecStream(ctx context.Context, sandboxID string, argv []string, stdin []byte, onOut func([]byte)) error {
	token, err := h.tokenFor(sandboxID)
	if err != nil {
		return fmt.Errorf("exec: resolve token for %s: %w", sandboxID, err)
	}
	body, _ := json.Marshal(execRequest{Command: strings.Join(argv, " "), Stdin: string(stdin)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.urlFor(sandboxID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(AccessTokenHeader, token)

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("exec %s: status %d", sandboxID, resp.StatusCode)
	}
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			out := make([]byte, n)
			copy(out, buf[:n])
			onOut(out)
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}
