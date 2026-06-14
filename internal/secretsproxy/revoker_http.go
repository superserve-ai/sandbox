package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type revokedSandboxesResponse struct {
	Sandboxes []string `json:"sandboxes"`
}

// FetchRevokedSandboxes pulls active sandbox revocations from the control plane.
func FetchRevokedSandboxes(ctx context.Context, baseURL, authToken string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/internal/sandbox_revocations", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch revocations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, string(raw))
	}
	var out revokedSandboxesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode revocations response: %w", err)
	}
	return out.Sandboxes, nil
}
