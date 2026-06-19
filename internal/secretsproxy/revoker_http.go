package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type revokedProxyTokenJSON struct {
	SandboxID  string `json:"sandbox_id"`
	ProxyToken string `json:"proxy_token"`
}

type revokedSandboxesResponse struct {
	Sandboxes   []string                `json:"sandboxes"`
	ProxyTokens []revokedProxyTokenJSON `json:"proxy_tokens"`
}

// FetchRevokedSandboxes pulls active revocations from the control plane: whole
// sandboxes and individual proxy tokens.
func FetchRevokedSandboxes(ctx context.Context, baseURL, authToken string) ([]string, []RevokedProxyToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/internal/sandbox_revocations", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch revocations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, nil, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, string(raw))
	}
	var out revokedSandboxesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("decode revocations response: %w", err)
	}
	tokens := make([]RevokedProxyToken, 0, len(out.ProxyTokens))
	for _, t := range out.ProxyTokens {
		tokens = append(tokens, RevokedProxyToken{SandboxID: t.SandboxID, ProxyToken: t.ProxyToken})
	}
	return out.Sandboxes, tokens, nil
}
