package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The heartbeat reports the machine's next announced maintenance window so
// the control plane can drain the host (pause its active sandboxes) before
// the restart destroys their memory state. The signal rides the heartbeat
// deliberately: it re-fires every interval, needs no new auth path, and a
// host too broken to report it is already being handled by the
// missed-heartbeat detector.

// maintenanceMetadataURL is GCE's upcoming-maintenance endpoint. Two
// correctness rules, inherited from the fleet's shell watcher: the
// Metadata-Flavor header is mandatory, and only an HTTP 200 is meaningful —
// any other outcome is "don't know", never "nothing scheduled".
var maintenanceMetadataURL = "http://metadata.google.internal/computeMetadata/v1/instance/upcoming-maintenance?alt=json"

type upcomingMaintenance struct {
	WindowStartTime string `json:"windowStartTime"`
	// startTime is the pre-window-fields spelling some GCE variants emit.
	StartTime string `json:"startTime"`
}

// probeMaintenanceWindow returns the start of the machine's next announced
// maintenance window, or nil when none is announced, or an error when the
// answer is unknowable (metadata unreachable, non-200, malformed) — callers
// must treat the error case as "omit", never as "cleared".
func probeMaintenanceWindow(ctx context.Context, client *http.Client) (*time.Time, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, maintenanceMetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request metadata: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("read metadata response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// No maintenance resource at all — nothing announced.
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata returned %d", resp.StatusCode)
	}
	trimmed := string(body)
	if trimmed == "" || trimmed == "NONE" || trimmed == "NONE\n" {
		return nil, nil
	}
	var m upcomingMaintenance
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("decode metadata response: %w", err)
	}
	raw := m.WindowStartTime
	if raw == "" {
		raw = m.StartTime
	}
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("parse window start %q: %w", raw, err)
	}
	return &t, nil
}
