// Package modelkey answers the one question that cannot be answered by
// looking at a model provider key: does the provider accept it?
//
// Both ends of hosted QM ask. qm-api asks before it creates a tenant,
// because a tenant slug is consumed for good the moment the row exists —
// a key the provider rejects has to be a 400 the caller can fix, not a
// tenant that can never be provisioned under that name. The provisioner's
// smoke step asks again before it calls a tenant ready, because a key can
// be revoked between the two.
//
// Only an unambiguous rejection counts. A timeout, a rate limit, a 5xx
// from the provider or an egress policy in the way all pass: none of them
// says the key is wrong, and failing on a provider's bad afternoon would
// be its own outage.
package modelkey

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// ErrRejected means the provider answered that the key is not valid.
var ErrRejected = errors.New("the model provider rejected this key")

// Timeout bounds the one request made to the provider.
const Timeout = 10 * time.Second

// bodyLimit bounds the response read before it is discarded. The body is
// never kept: a provider's error page can echo the key back.
const bodyLimit = 4096

// probe is the cheapest authenticated request each provider offers.
type probe struct {
	url     string
	headers func(key string) map[string]string
}

var probes = map[string]probe{
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

// Supported reports whether a provider can be checked at all.
func Supported(provider string) bool {
	_, ok := probes[provider]
	return ok
}

// Verify returns ErrRejected when the provider says the key is not valid,
// and nil for everything else — including not being able to ask.
func Verify(ctx context.Context, client *http.Client, provider, key string) error {
	p, known := probes[provider]
	if !known {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil
	}
	for name, value := range p.headers(key) {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Could not ask. Not the same as being told no.
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyLimit))
	// 401 only. A 403 says the key is authentic but not allowed to make
	// this particular call, which a restricted key legitimately can be:
	// an OpenAI project key scoped to responses answers 403 to
	// GET /v1/models while working perfectly for everything the tenant
	// does. Rejecting on that would turn a usable key into a 400.
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrRejected
	}
	return nil
}
