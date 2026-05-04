// Package client is a thin HTTP-over-unix-socket wrapper used by vmd
// to talk to the local secrets proxy.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/superserve-ai/sandbox/internal/secretsproxy/api"
)

// Client posts control RPCs to the local secretsproxy daemon over a Unix
// socket. Safe for concurrent use. Construct once per process.
type Client struct {
	http       *http.Client
	socketPath string
}

// New returns a Client that talks to the secretsproxy on socketPath.
// The path doesn't need to exist when New runs — connection failures
// surface on the first RPC.
func New(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
				MaxIdleConns:    8,
				IdleConnTimeout: 60 * time.Second,
			},
			Timeout: 5 * time.Second,
		},
	}
}

// Register installs (or replaces) the proxy's view of a sandbox.
func (c *Client) Register(ctx context.Context, req api.RegisterRequest) error {
	return c.do(ctx, http.MethodPost, "/sandboxes/register", req)
}

// Unregister removes a sandbox from the proxy. Idempotent.
func (c *Client) Unregister(ctx context.Context, sandboxID string) error {
	return c.do(ctx, http.MethodPost, "/sandboxes/"+sandboxID+"/unregister", nil)
}

// UpdateBindings replaces a sandbox's binding set (rotation, revoke).
func (c *Client) UpdateBindings(ctx context.Context, sandboxID string, req api.UpdateBindingsRequest) error {
	return c.do(ctx, http.MethodPost, "/sandboxes/"+sandboxID+"/bindings", req)
}

// UpdateEgress replaces a sandbox's egress policy.
func (c *Client) UpdateEgress(ctx context.Context, sandboxID string, req api.UpdateEgressRequest) error {
	return c.do(ctx, http.MethodPost, "/sandboxes/"+sandboxID+"/egress", req)
}

// PropagateSecret pushes a new real value (or revocation) for the given
// secret to every sandbox on this host that holds a binding for it.
func (c *Client) PropagateSecret(ctx context.Context, req api.PropagateSecretRequest) error {
	return c.do(ctx, http.MethodPost, "/secrets/propagate", req)
}

// Health pings the proxy. Returns nil on 200.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/health", nil)
}

func (c *Client) do(ctx context.Context, method, path string, body any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("secretsproxy %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}
