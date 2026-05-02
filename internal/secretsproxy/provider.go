package secretsproxy

import (
	"fmt"
	"net/http"
	"strings"
)

// ServiceConfig describes one upstream provider. Each provider has its
// own path prefix (so requests can be routed by URL), a key header, and
// the format string for that header.
type ServiceConfig struct {
	Name       string
	PathPrefix string // e.g. "/anthropic" — stripped before forwarding
	Upstream   string // e.g. "https://api.anthropic.com"
	KeyHeader  string // e.g. "x-api-key" or "Authorization"
	KeyFormat  string // e.g. "%s" or "Bearer %s"
}

// SetKey writes the real key into the outgoing request using the
// provider's header conventions.
func (s ServiceConfig) SetKey(req *http.Request, real string) {
	req.Header.Set(s.KeyHeader, fmt.Sprintf(s.KeyFormat, real))
}

// AnthropicConfig is the Phase 1 upstream. Anthropic auth uses the
// `x-api-key` header (no Bearer prefix).
var AnthropicConfig = ServiceConfig{
	Name:       "anthropic",
	PathPrefix: "/anthropic",
	Upstream:   "https://api.anthropic.com",
	KeyHeader:  "x-api-key",
	KeyFormat:  "%s",
}

// Registry resolves provider configs by name and by request path.
type Registry struct {
	byName   map[string]ServiceConfig
	byPrefix []ServiceConfig // ordered, most-specific first
}

func NewRegistry(configs ...ServiceConfig) *Registry {
	r := &Registry{
		byName:   make(map[string]ServiceConfig, len(configs)),
		byPrefix: make([]ServiceConfig, 0, len(configs)),
	}
	for _, c := range configs {
		r.byName[c.Name] = c
		r.byPrefix = append(r.byPrefix, c)
	}
	return r
}

// MatchPath finds the provider whose PathPrefix matches the request path
// and returns the remainder (the path to forward upstream). Returns
// (cfg, "", false) if no provider matches.
func (r *Registry) MatchPath(path string) (ServiceConfig, string, bool) {
	for _, c := range r.byPrefix {
		if strings.HasPrefix(path, c.PathPrefix+"/") || path == c.PathPrefix {
			rest := strings.TrimPrefix(path, c.PathPrefix)
			if rest == "" {
				rest = "/"
			}
			return c, rest, true
		}
	}
	return ServiceConfig{}, "", false
}

// ByName fetches a provider by its name.
func (r *Registry) ByName(name string) (ServiceConfig, bool) {
	c, ok := r.byName[name]
	return c, ok
}
