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
func (c *HTTPVaultClient) FetchCredential(ctx context.Context, teamID, secretID string) (string, error) {
	body, err := json.Marshal(decryptRequest{TeamID: teamID, SecretID: secretID})
	if err != nil {
		return "", fmt.Errorf("marshal decrypt request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/internal/secrets/decrypt", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build decrypt request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("decrypt request: %w", err)
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
		return "", fmt.Errorf("control plane returned empty value for secret_id=%s", secretID)
	}
	return dr.Value, nil
}
