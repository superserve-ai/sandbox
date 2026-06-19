package secretsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPVaultClient fetches credential values from the control plane's decrypt endpoint.
type HTTPVaultClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewHTTPVaultClient builds a client that POSTs to {baseURL}/internal/secrets/decrypt with Bearer auth.
func NewHTTPVaultClient(baseURL, authToken string) *HTTPVaultClient {
	return &HTTPVaultClient{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type decryptRequest struct {
	TeamID   string `json:"team_id"`
	SecretID string `json:"secret_id"`
}

type decryptResponse struct {
	Value string `json:"value"`
}

// FetchCredential resolves (teamID, secretID) to cleartext; 404/410 → ErrCredentialRevoked.
// Retries once on transient upstream errors (502/503/504) so a single control-plane
// hiccup doesn't fail a user request.
func (c *HTTPVaultClient) FetchCredential(ctx context.Context, teamID, secretID string) (string, error) {
	body, err := json.Marshal(decryptRequest{TeamID: teamID, SecretID: secretID})
	if err != nil {
		return "", fmt.Errorf("marshal decrypt request: %w", err)
	}

	resp, err := c.doDecryptWithRetry(ctx, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return "", ErrCredentialRevoked
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("control plane rejected daemon auth (%d): check DAEMON_AUTH_TOKEN matches control plane INTERNAL_API_TOKEN", resp.StatusCode)
	default:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("control plane returned %d: %s", resp.StatusCode, string(raw))
	}

	var dr decryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return "", fmt.Errorf("decode decrypt response: %w", err)
	}
	if dr.Value == "" {
		// Empty plaintext is pathological but legal — map to revoked so the
		// request path returns 503 rather than a confusing internal error.
		return "", ErrCredentialRevoked
	}
	return dr.Value, nil
}

// doDecryptWithRetry posts to /internal/secrets/decrypt with one retry on
// 502/503/504. Body is reset per attempt; ctx cancellation aborts both.
func (c *HTTPVaultClient) doDecryptWithRetry(ctx context.Context, body []byte) (*http.Response, error) {
	const attempts = 2
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.baseURL+"/internal/secrets/decrypt", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build decrypt request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.authToken)
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("decrypt request: %w", err)
			if ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}
		if resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout {
			lastErr = fmt.Errorf("control plane returned %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}
