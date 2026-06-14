package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// SecretsBrokerClient is vmd's unix-socket client for the local secretsproxy
// daemon. With the JWT-scoped daemon design the only remaining server-side
// operation is cache invalidation; sandbox registration is implicit in the
// per-request JWT and needs no out-of-band setup. Empty socketPath disables
// every method (silent no-op).
type SecretsBrokerClient struct {
	socketPath string
	httpClient *http.Client
}

// NewSecretsBrokerClient builds a client; empty socketPath disables every call.
func NewSecretsBrokerClient(socketPath string) *SecretsBrokerClient {
	c := &SecretsBrokerClient{socketPath: socketPath}
	if socketPath != "" {
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 5 * time.Second,
		}
	}
	return c
}

// Enabled reports whether the client will actually talk to the daemon.
func (c *SecretsBrokerClient) Enabled() bool { return c.socketPath != "" }

// ErrDaemonRefused is returned when the daemon rejects a call with a 4xx.
var ErrDaemonRefused = errors.New("secretsproxy daemon rejected call")

// InvalidateSecret tells the daemon to drop any cached cleartext for secretID. Idempotent.
func (c *SecretsBrokerClient) InvalidateSecret(ctx context.Context, secretID string) error {
	if !c.Enabled() {
		return nil
	}
	url := "http://unix/v1/secrets/" + secretID + "/invalidate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("daemon invalidate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: status %d: %s", ErrDaemonRefused, resp.StatusCode, string(raw))
	}
	return nil
}

// RevokeSandbox tells the daemon that sandboxID's JWT must no longer authorize requests. Idempotent.
func (c *SecretsBrokerClient) RevokeSandbox(ctx context.Context, sandboxID string) error {
	if !c.Enabled() {
		return nil
	}
	url := "http://unix/v1/sandboxes/" + sandboxID + "/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("daemon revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: status %d: %s", ErrDaemonRefused, resp.StatusCode, string(raw))
	}
	return nil
}

// InvalidateSandboxRules tells the daemon to drop cached egress rules for sandboxID. Idempotent.
func (c *SecretsBrokerClient) InvalidateSandboxRules(ctx context.Context, sandboxID string) error {
	if !c.Enabled() {
		return nil
	}
	url := "http://unix/v1/sandboxes/" + sandboxID + "/rules"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("daemon invalidate rules: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: status %d: %s", ErrDaemonRefused, resp.StatusCode, string(raw))
	}
	return nil
}

// RequireProxyForJWT errors when a JWT is present but no proxy is configured.
func RequireProxyForJWT(jwt, proxyURL string) error {
	if jwt != "" && proxyURL == "" {
		return errors.New("sandbox has secrets but SECRETSPROXY_SANDBOX_ADDR is unset on vmd")
	}
	return nil
}

// Trust-store paths. Must match what injectProxyCA writes into the rootfs.
const (
	systemTrustBundle = "/etc/ssl/certs/ca-certificates.crt"
	systemTrustDir    = "/etc/ssl/certs"
	proxyCAOnlyCert   = "/usr/local/share/ca-certificates/superserve-proxy.crt"
)

// InjectHTTPSProxyEnvWithJWT returns a copy of envVars with HTTPS_PROXY and the
// CA-trust env vars set so the sandbox routes HTTPS egress through the daemon
// and trusts its MITM cert. No-op when sandboxAddr or jwt is empty.
//
// HTTP_PROXY is intentionally omitted: the daemon is CONNECT-only and never
// injects secrets into cleartext HTTP, so plain-HTTP egress flows direct.
func InjectHTTPSProxyEnvWithJWT(envVars map[string]string, sandboxAddr, jwt string) map[string]string {
	if sandboxAddr == "" || jwt == "" {
		return envVars
	}
	proxyURL := fmt.Sprintf("https://sb:%s@%s", jwt, sandboxAddr)
	out := make(map[string]string, len(envVars)+6)
	for k, v := range envVars {
		out[k] = v
	}
	out["HTTPS_PROXY"] = proxyURL
	out["SSL_CERT_FILE"] = systemTrustBundle
	out["SSL_CERT_DIR"] = systemTrustDir
	out["CURL_CA_BUNDLE"] = systemTrustBundle
	out["REQUESTS_CA_BUNDLE"] = systemTrustBundle
	out["NODE_EXTRA_CA_CERTS"] = proxyCAOnlyCert
	return out
}
