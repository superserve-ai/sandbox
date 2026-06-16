package secretsproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPRulesClient fetches a sandbox's egress rules from the control plane.
type HTTPRulesClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewHTTPRulesClient builds a client that GETs {baseURL}/internal/sandboxes/{id}/egress_rules with Bearer auth.
func NewHTTPRulesClient(baseURL, authToken string) *HTTPRulesClient {
	return &HTTPRulesClient{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type egressRulesResponse struct {
	Allow               []string `json:"allow"`
	Deny                []string `json:"deny"`
	UnmatchedHostPolicy string   `json:"unmatched_host_policy"`
}

// FetchRules resolves sandboxID to its current egress rules. A 404 (sandbox
// gone) yields empty rules so the dispatcher treats it as no policy rather than
// erroring; transient 5xx are surfaced so the cache serves last-known-good.
func (c *HTTPRulesClient) FetchRules(ctx context.Context, sandboxID string) (EgressRules, error) {
	u := c.baseURL + "/internal/sandboxes/" + url.PathEscape(sandboxID) + "/egress_rules"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return EgressRules{}, fmt.Errorf("build egress_rules request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return EgressRules{}, fmt.Errorf("egress_rules request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return EgressRules{}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return EgressRules{}, fmt.Errorf("control plane rejected daemon auth (%d)", resp.StatusCode)
	default:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return EgressRules{}, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, string(raw))
	}

	var rr egressRulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return EgressRules{}, fmt.Errorf("decode egress_rules response: %w", err)
	}
	return EgressRules{Allow: rr.Allow, Deny: rr.Deny, UnmatchedHostPolicy: rr.UnmatchedHostPolicy}, nil
}
