package steps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// Checking the tenant's model provider key.
//
// qm-api accepts the key on shape alone at create time and leaves whether
// the provider accepts it to the provisioner, which is the right division:
// a key is only really testable against the provider. So the smoke step
// tests it, and a key the provider rejects outright fails the provision —
// a tenant whose agent cannot call a model is not a working tenant, and
// finding out at the first message instead is a much worse experience.
//
// Only an unambiguous rejection counts. A timeout, a rate limit, a 5xx from
// the provider or an egress policy in the way all pass: none of them says
// the key is wrong, and failing a provision on a provider's bad afternoon
// would be its own outage.

// modelKeyTimeout bounds the one request made to the provider.
const modelKeyTimeout = 10 * time.Second

// modelKeyProbe is the cheapest authenticated request each provider offers.
type modelKeyProbe struct {
	url     string
	headers func(key string) map[string]string
}

var modelKeyProbes = map[string]modelKeyProbe{
	"anthropic": {
		url: "https://api.anthropic.com/v1/models?limit=1",
		headers: func(key string) map[string]string {
			return map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}
		},
	},
	"openai": {
		url:     "https://api.openai.com/v1/models",
		headers: func(key string) map[string]string { return map[string]string{"Authorization": "Bearer " + key} },
	},
	"openrouter": {
		url:     "https://openrouter.ai/api/v1/key",
		headers: func(key string) map[string]string { return map[string]string{"Authorization": "Bearer " + key} },
	},
}

// checkModelKey reports an error only when the provider says the key is not
// valid. Anything else — including not being able to reach the provider at
// all — passes.
func checkModelKey(ctx context.Context, c Clients, t *provisioner.Tenant) error {
	probe, known := modelKeyProbes[t.Row.ModelProvider]
	if !known {
		return nil
	}
	if c.Secrets == nil {
		return errNoSecretStore
	}
	key, err := c.Secrets.Get(ctx, t.SecretName(secrets.ModelKeyName(t.Row.ModelProvider)))
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			// qm-api writes this before the run is triggered, so its
			// absence is not something a retry fixes.
			return fmt.Errorf("the tenant has no %s key in Secret Manager", t.Row.ModelProvider)
		}
		return fmt.Errorf("read the tenant's model key: %w", err)
	}

	client := c.HTTP
	if client == nil {
		client = defaultProbeClient()
	}
	ctx, cancel := context.WithTimeout(ctx, modelKeyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
	if err != nil {
		return nil
	}
	for name, value := range probe.headers(string(key)) {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Could not ask. Not the same as being told no.
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyLimit))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// The status only; the provider's body can echo the key back.
		return fmt.Errorf("%s rejected the tenant's model key (%d): replace it and retry", t.Row.ModelProvider, resp.StatusCode)
	}
	return nil
}
