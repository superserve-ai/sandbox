package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/superserve-ai/sandbox/proto/boxdpb/boxdpbconnect"
)

// boxdPort must match httpPort in cmd/boxd/main.go.
const boxdPort = 49983

// boxdHTTPClient is a dedicated HTTP client for boxd Connect RPC calls.
// Keep-alives are disabled: slot recycling reuses host IPs, so a pooled
// connection to a recycled slot points at a dead TCP endpoint on the
// next VM. Fresh connects over veth are sub-millisecond.
var boxdHTTPClient = &http.Client{
	Transport: &http.Transport{
		DisableKeepAlives: true,
	},
}

// waitForHTTPHealth polls boxd's /health endpoint until it responds or timeout.
func waitForHTTPHealth(ctx context.Context, vmIP string, timeout time.Duration) error {
	url := fmt.Sprintf("http://%s:%d/health", vmIP, boxdPort)
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("boxd health check not ready after %s", timeout)
}

var boxdInitClient = &http.Client{Timeout: 5 * time.Second}


// postBoxdInit sends sandbox-level configuration (env vars, hostname) to
// boxd's /init endpoint.
func postBoxdInit(ctx context.Context, vmIP string, envVars map[string]string, hostname string) error {
	if len(envVars) == 0 && hostname == "" {
		return nil
	}

	body := struct {
		EnvVars  map[string]string `json:"env_vars,omitempty"`
		Hostname string            `json:"hostname,omitempty"`
	}{EnvVars: envVars, Hostname: hostname}

	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal init body: %w", err)
	}

	url := fmt.Sprintf("http://%s:%d/init", vmIP, boxdPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("create init request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := boxdInitClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /init: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /init: status %d", resp.StatusCode)
	}
	return nil
}

// boxdFilesystemClient returns a Connect RPC client for boxd's
// FilesystemService, used for metadata ops (Remove, Move, etc.) inside
// a VM. File byte transfer goes through the edge proxy directly.
func boxdFilesystemClient(vmIP string) boxdpbconnect.FilesystemServiceClient {
	baseURL := fmt.Sprintf("http://%s:%d", vmIP, boxdPort)
	return boxdpbconnect.NewFilesystemServiceClient(boxdHTTPClient, baseURL)
}
