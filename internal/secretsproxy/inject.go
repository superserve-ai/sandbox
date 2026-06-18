package secretsproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/superserve-ai/sandbox/internal/egresspolicy"
)

// InjectOutcome describes what the proxy decided for one request.
type InjectOutcome struct {
	// Action is "allow", "deny", or "revoked".
	Action string
	// Reason is a short machine-readable code for rejection responses.
	Reason string
	// MatchedSecretIDs lists every secret swapped for this request, or — on
	// deny/revoked — the binding that triggered the rejection. Empty = passthrough.
	MatchedSecretIDs []string
}

const (
	allowAction   = "allow"
	denyAction    = "deny"
	revokedAction = "revoked"
)

// injectRequest applies the egress + credential-injection pipeline to an
// outbound request, mutating headers in place under a strip-then-set invariant.
// If the request carries proxy tokens for multiple bindings, each is swapped
// independently — every binding's credential reaches its intended slot.
func injectRequest(
	ctx context.Context,
	scope *Scope,
	vault VaultClient,
	req *http.Request,
	upstreamHost string,
	upstreamIP net.IP,
	rules EgressRules,
	tokenRevoked func(proxyToken string) bool,
) (InjectOutcome, error) {
	if allowed, reason := hostAllowedByEgress(upstreamHost, upstreamIP, rules); !allowed {
		return InjectOutcome{Action: denyAction, Reason: reason}, nil
	}

	matches := findAllMatchingBindings(req, scope)
	if len(matches) == 0 {
		return InjectOutcome{Action: allowAction}, nil
	}

	// A request carrying a detached binding's token is refused, even though the
	// JWT it authenticated with still lists the binding.
	if tokenRevoked != nil {
		for _, m := range matches {
			if tokenRevoked(m.proxyToken) {
				return InjectOutcome{
					Action:           revokedAction,
					Reason:           "proxy_token_revoked",
					MatchedSecretIDs: []string{m.binding.SecretID},
				}, nil
			}
		}
	}

	// Phase 1: resolve every match before mutating headers, so a failure
	// surfaces cleanly without leaving the request half-swapped.
	type resolvedSwap struct {
		secretID   string
		authType   string
		authConfig map[string]any
		value      string
	}
	swaps := make([]resolvedSwap, 0, len(matches))
	for _, m := range matches {
		binding := m.binding
		if !hostMatchesCredential(upstreamHost, binding.Hosts) {
			return InjectOutcome{
				Action:           denyAction,
				Reason:           "credential_host_mismatch",
				MatchedSecretIDs: []string{binding.SecretID},
			}, nil
		}
		authType, authConfig, ok := dispatchAuthShape(binding, upstreamHost)
		if !ok {
			return InjectOutcome{
				Action:           denyAction,
				Reason:           "credential_host_mismatch",
				MatchedSecretIDs: []string{binding.SecretID},
			}, nil
		}
		value, err := vault.FetchCredential(ctx, scope.TeamID, binding.SecretID)
		if err != nil {
			if errors.Is(err, ErrCredentialRevoked) {
				return InjectOutcome{
					Action:           revokedAction,
					Reason:           "credential_revoked",
					MatchedSecretIDs: []string{binding.SecretID},
				}, nil
			}
			return InjectOutcome{}, err
		}
		swaps = append(swaps, resolvedSwap{
			secretID:   binding.SecretID,
			authType:   authType,
			authConfig: authConfig,
			value:      value,
		})
	}

	// Phase 2: apply every swap.
	matched := make([]string, 0, len(swaps))
	for _, s := range swaps {
		if err := applyInjectionShape(req, s.authType, s.authConfig, s.value); err != nil {
			return InjectOutcome{}, fmt.Errorf("apply injection: %w", err)
		}
		matched = append(matched, s.secretID)
	}

	return InjectOutcome{
		Action:           allowAction,
		MatchedSecretIDs: matched,
	}, nil
}

// dispatchAuthShape returns the (authType, authConfig) the writer should use
// for upstreamHost. For multi-rule bindings, it picks the first rule whose
// host list includes upstreamHost; ok=false if none match (binding allowlist
// reaches the host but no rule covers it — fail closed). For legacy single-rule
// bindings, it returns the binding's top-level shape directly.
func dispatchAuthShape(b Binding, upstreamHost string) (string, map[string]any, bool) {
	if len(b.Rules) == 0 {
		return b.AuthType, b.AuthConfig, true
	}
	for _, r := range b.Rules {
		if hostMatchesCredential(upstreamHost, r.Hosts) {
			return r.AuthType, r.AuthConfig, true
		}
	}
	return "", nil, false
}

// hostAllowedByEgress evaluates the fetched egress policy; upstreamIP is used
// for CIDR rules.
func hostAllowedByEgress(host string, upstreamIP net.IP, rules EgressRules) (bool, string) {
	return egresspolicy.EvalEgress(host, upstreamIP, rules.Allow, rules.Deny, rules.UnmatchedHostPolicy)
}

// hostMatchesCredential checks host against the credential's allowed list using
// strict single-label wildcards, so a credential can't be routed to an
// unintended deep subdomain. An empty list fails closed.
func hostMatchesCredential(host string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, p := range allowed {
		if egresspolicy.MatchHostStrict(host, p) {
			return true
		}
	}
	return false
}

// matchedBinding pairs a matched binding with the proxy token that matched it,
// so the caller can check the token against the revoked set.
type matchedBinding struct {
	binding    Binding
	proxyToken string
}

// findAllMatchingBindings returns every binding whose proxy token appears in
// the request. Multi-rule bindings are scanned against every rule's shape.
// Output is sorted by SecretID for deterministic ordering across runs.
func findAllMatchingBindings(req *http.Request, scope *Scope) []matchedBinding {
	var out []matchedBinding
	for proxyToken, binding := range scope.Bindings {
		if len(binding.Rules) > 0 {
			for _, r := range binding.Rules {
				if shapeHasToken(req, r.AuthType, r.AuthConfig, proxyToken) {
					out = append(out, matchedBinding{binding: binding, proxyToken: proxyToken})
					break
				}
			}
			continue
		}
		if shapeHasToken(req, binding.AuthType, binding.AuthConfig, proxyToken) {
			out = append(out, matchedBinding{binding: binding, proxyToken: proxyToken})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].binding.SecretID < out[j].binding.SecretID })
	return out
}

// shapeHasToken reports whether req carries proxyToken in the (authType, cfg)
// shape. Shared by the legacy single-rule scan and the multi-rule scan.
func shapeHasToken(req *http.Request, authType string, cfg map[string]any, proxyToken string) bool {
	switch authType {
	case "bearer":
		got := req.Header.Get("Authorization")
		return strings.EqualFold(got, "Bearer "+proxyToken)
	case "basic":
		_, pw, ok := decodeBasicAuth(req.Header.Get("Authorization"))
		if !ok {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(pw), []byte(proxyToken)) == 1
	case "api-key":
		name, _ := stringFromAuthConfig(cfg, "header")
		if name == "" {
			name = "Authorization"
		}
		prefix, _ := stringFromAuthConfig(cfg, "prefix")
		got := req.Header.Get(name)
		return got == prefix+proxyToken
	case "custom":
		headers, _ := mapStringFromAuthConfig(cfg, "headers")
		for name, tmpl := range headers {
			expected := strings.ReplaceAll(tmpl, "{{ value }}", proxyToken)
			if req.Header.Get(name) == expected {
				return true
			}
		}
		return false
	}
	return false
}

// applyInjectionShape strips auth-owned headers and sets them to the real value(s).
// The strip is unconditional so a client-set value can never be preserved.
// For basic, a configured username overrides preserve-inbound so the writer
// can pin a required username regardless of what the client sent.
func applyInjectionShape(req *http.Request, authType string, cfg map[string]any, real string) error {
	switch authType {
	case "bearer":
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", "Bearer "+real)
		return nil
	case "basic":
		user, _ := stringFromAuthConfig(cfg, "username")
		if user == "" {
			// Preserve the inbound username; fall back to "x" for empty-user inputs.
			inbound, _, ok := decodeBasicAuth(req.Header.Get("Authorization"))
			if ok && inbound != "" {
				user = inbound
			} else {
				user = "x"
			}
		}
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+real)))
		return nil
	case "api-key":
		name, _ := stringFromAuthConfig(cfg, "header")
		if name == "" {
			name = "Authorization"
		}
		prefix, _ := stringFromAuthConfig(cfg, "prefix")
		req.Header.Del(name)
		req.Header.Set(name, prefix+real)
		return nil
	case "custom":
		headers, _ := mapStringFromAuthConfig(cfg, "headers")
		for name := range headers {
			req.Header.Del(name)
		}
		for name, tmpl := range headers {
			rendered := strings.ReplaceAll(tmpl, "{{ value }}", real)
			if strings.ContainsAny(rendered, "\r\n") {
				return fmt.Errorf("custom auth: header %q resolved to a value with CR/LF (injection guard)", name)
			}
			req.Header.Set(name, rendered)
		}
		return nil
	}
	return fmt.Errorf("unknown auth_type %q", authType)
}

// decodeBasicAuth parses `Basic <base64(user:password)>`; ok=false on any malformed input.
func decodeBasicAuth(header string) (user, password string, ok bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}
	raw := strings.TrimSpace(header[len("Basic "):])
	if raw == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if d2, err2 := base64.RawURLEncoding.DecodeString(raw); err2 == nil {
			decoded = d2
		} else {
			return "", "", false
		}
	}
	creds := string(decoded)
	idx := strings.IndexByte(creds, ':')
	if idx < 0 {
		return "", "", false
	}
	return creds[:idx], creds[idx+1:], true
}

func stringFromAuthConfig(cfg map[string]any, key string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	v, ok := cfg[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func mapStringFromAuthConfig(cfg map[string]any, key string) (map[string]string, bool) {
	if cfg == nil {
		return nil, false
	}
	v, ok := cfg[key]
	if !ok {
		return nil, false
	}
	// JSON unmarshal yields map[string]any; convert.
	asAny, ok := v.(map[string]any)
	if !ok {
		if asStr, ok := v.(map[string]string); ok {
			return asStr, true
		}
		return nil, false
	}
	out := make(map[string]string, len(asAny))
	for k, vv := range asAny {
		if s, ok := vv.(string); ok {
			out[k] = s
		}
	}
	return out, true
}
