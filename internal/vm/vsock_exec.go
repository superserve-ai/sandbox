package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
//
// The probe interval ramps 1ms → 10ms (doubling): readiness in the tens of
// milliseconds would otherwise be quantized to the poll interval, so the
// early probes must be dense; the cap keeps the steady-state cost of a slow
// boot negligible. Probes ride the host↔guest veth, so each costs well
// under a millisecond.
// ErrGuestClockUnready: the guest cannot correct its clock; waiting longer
// cannot help, and this host should restore the unfrozen way.
var ErrGuestClockUnready = errors.New("guest clock could not be corrected")

// ErrGuestThawFailed: the guest corrected its clock but could not release its
// workload. Not a clock problem; retrying unfrozen would not help.
var ErrGuestThawFailed = errors.New("guest workload could not be released")

// clockUnreadyPolls is how many consecutive such answers make it final: the
// first may be mid-correction.
const clockUnreadyPolls = 3

func waitForHTTPHealth(ctx context.Context, vmIP string, timeout time.Duration) error {
	url := fmt.Sprintf("http://%s:%d/health", vmIP, boxdPort)
	deadline := time.Now().Add(timeout)
	client := &http.Client{
		Timeout:   500 * time.Millisecond,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	const maxProbeInterval = 10 * time.Millisecond
	interval := time.Millisecond
	var lastErr error
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
			err = fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		lastErr = err

		time.Sleep(interval)
		interval = min(interval*2, maxProbeInterval)
	}
	if lastErr != nil {
		return fmt.Errorf("boxd health check not ready after %s: %w", timeout, lastErr)
	}
	return fmt.Errorf("boxd health check not ready after %s", timeout)
}

// Keep-alives disabled for the same IP-reuse reason as boxdHTTPClient.
// The timeout absorbs transient in-guest stalls (a freshly-restored guest's
// first disk write can block for several seconds), so a slow-but-healthy
// init isn't misread as a dead one.
var boxdInitClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

// postBoxdInitRetried retries a failed /init once. /init merges env vars and
// re-applies the hostname, so a duplicate delivery to the same VM is
// harmless. stillOwner re-checks that the target VM still owns vmIP before
// the retry fires: a destroy (which bypasses the lifecycle lock) can release
// the slot after the first attempt, and the payload may carry credentials
// that must never reach whatever VM claims the IP next.
func postBoxdInitRetried(ctx context.Context, vmIP string, envVars map[string]string, hostname string, stillOwner func() bool) error {
	err := postBoxdInit(ctx, vmIP, envVars, hostname)
	if err == nil || ctx.Err() != nil {
		return err
	}
	if stillOwner != nil && !stillOwner() {
		return err
	}
	return postBoxdInit(ctx, vmIP, envVars, hostname)
}

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

// postBoxdFreeze asks the guest to stop its workload ahead of a snapshot.
func postBoxdFreeze(ctx context.Context, vmIP string) error {
	// The guest's budget is shorter than ours, so it gives up and thaws first.
	var body []byte
	if dl, ok := ctx.Deadline(); ok {
		budget := time.Until(dl) - 200*time.Millisecond
		if budget <= 0 {
			return context.DeadlineExceeded
		}
		body, _ = json.Marshal(struct {
			BudgetMs int64 `json:"budget_ms"`
		}{budget.Milliseconds()})
	}
	return postBoxd(ctx, vmIP, "/freeze", body)
}

// postBoxdThaw undoes a freeze whose snapshot did not happen.
func postBoxdThaw(ctx context.Context, vmIP string) error {
	return postBoxd(ctx, vmIP, "/thaw", nil)
}

func postBoxd(ctx context.Context, vmIP, path string, body []byte) error {
	url := fmt.Sprintf("http://%s:%d%s", vmIP, boxdPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create %s request: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := boxdHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(reply)))
	}
	return nil
}

// waitForGuestWake tells a restored guest to correct its clock and release its
// workload, and waits for it to confirm. clockFrozen is the policy the restore
// used, so the guest knows whether correction is required. Returns
// ErrGuestClockUnready as soon as the guest reports it cannot, so the caller
// can retry the restore the unfrozen way instead of waiting out the budget.
func waitForGuestWake(ctx context.Context, vmIP string, timeout time.Duration, clockFrozen bool) error {
	url := fmt.Sprintf("http://%s:%d/wake", vmIP, boxdPort)
	body, _ := json.Marshal(struct {
		ClockFrozen bool `json:"clock_frozen"`
	}{clockFrozen})
	deadline := time.Now().Add(timeout)
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	const maxProbeInterval = 10 * time.Millisecond
	interval := time.Millisecond
	var lastErr error
	clockUnready := 0
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			reply, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("unexpected status %d", resp.StatusCode)
			if resp.StatusCode == http.StatusServiceUnavailable {
				var r struct {
					Status    string `json:"status"`
					WallClock struct {
						Error string `json:"error"`
					} `json:"wall_clock"`
				}
				if json.Unmarshal(reply, &r) == nil && (r.Status == "clock" || r.Status == "thaw") {
					if clockUnready++; clockUnready >= clockUnreadyPolls {
						sentinel := ErrGuestClockUnready
						if r.Status == "thaw" {
							sentinel = ErrGuestThawFailed
						}
						return fmt.Errorf("%w (%s)", sentinel, r.WallClock.Error)
					}
				}
			}
		}
		lastErr = err
		time.Sleep(interval)
		interval = min(interval*2, maxProbeInterval)
	}
	if lastErr != nil {
		return fmt.Errorf("guest not awake after %s: %w", timeout, lastErr)
	}
	return fmt.Errorf("guest not awake after %s", timeout)
}

// Seams so the pause and restore paths can be tested without a guest.
var (
	boxdFreezeGuest = postBoxdFreeze
	boxdThawGuest   = postBoxdThaw
	boxdWakeGuest   = waitForGuestWake
)

// boxdFilesystemClient returns a Connect RPC client for boxd's
// FilesystemService, used for metadata ops (Remove, Move, etc.) inside
// a VM. File byte transfer goes through the edge proxy directly.
func boxdFilesystemClient(vmIP string) boxdpbconnect.FilesystemServiceClient {
	baseURL := fmt.Sprintf("http://%s:%d", vmIP, boxdPort)
	return boxdpbconnect.NewFilesystemServiceClient(boxdHTTPClient, baseURL)
}
