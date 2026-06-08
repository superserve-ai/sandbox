package secretsproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// InjectOutcome describes what the proxy decided for one request.
type InjectOutcome struct {
	// Action is "allow", "deny", or "revoked".
	Action string
	// Reason is a short machine-readable code for rejection responses.
	Reason string
	// MatchedSecretID is the secret used for injection, captured for the audit row.
	MatchedSecretID string
}

const (
	allowAction   = "allow"
	denyAction    = "deny"
	revokedAction = "revoked"
)

// injectRequest applies the egress + credential-injection pipeline to an
// outbound request, mutating headers in place under a strip-then-set invariant.
func injectRequest(
	ctx context.Context,
	scope *Scope,
	vault VaultClient,
	req *http.Request,
	upstreamHost string,
) (InjectOutcome, error) {
	if allowed, reason := hostAllowedByEgress(upstreamHost, scope); !allowed {
		return InjectOutcome{Action: denyAction, Reason: reason}, nil
	}

	binding, found := findMatchingBinding(req, scope)
	if !found {
		return InjectOutcome{Action: allowAction}, nil
	}

	// Refuse to swap a credential onto a host outside its own allow list.
	if !hostMatchesCredential(upstreamHost, binding.Hosts) {
		return InjectOutcome{
			Action:          denyAction,
			Reason:          "credential_host_mismatch",
			MatchedSecretID: binding.SecretID,
		}, nil
	}

	value, err := vault.FetchCredential(ctx, scope.TeamID, binding.SecretID)
	if err != nil {
		if errors.Is(err, ErrCredentialRevoked) {
			return InjectOutcome{
				Action:          revokedAction,
				Reason:          "credential_revoked",
				MatchedSecretID: binding.SecretID,
			}, nil
		}
		return InjectOutcome{}, err
	}

	if err := applyInjection(req, binding, value); err != nil {
		return InjectOutcome{}, fmt.Errorf("apply injection: %w", err)
	}

	return InjectOutcome{
		Action:          allowAction,
		MatchedSecretID: binding.SecretID,
	}, nil
}

// hostAllowedByEgress applies allow → deny → unmatched_host_policy in order;
// an allow-list match short-circuits before deny is consulted.
func hostAllowedByEgress(host string, scope *Scope) (bool, string) {
	host = strings.ToLower(host)

	for _, a := range scope.Allow {
		if matchHost(host, a) {
			return true, ""
		}
	}
	for _, d := range scope.Deny {
		if matchHost(host, d) {
			return false, "host_denied"
		}
	}
	if len(scope.Allow) > 0 {
		return false, "host_not_allowed"
	}
	switch scope.UnmatchedHostPolicy {
	case "deny":
		return false, "unmatched_host_denied"
	default:
		return true, ""
	}
}

// matchHost compares host to pattern; supports exact and `*.suffix` wildcard.
func matchHost(host, pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return false
	}
	if p == host {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:]
		if strings.HasSuffix(host, suffix) && host != suffix[1:] {
			return true
		}
	}
	return false
}

// hostMatchesCredential checks host against the credential's allowed list.
// An empty list fails closed.
func hostMatchesCredential(host string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	host = strings.ToLower(host)
	for _, p := range allowed {
		if matchHost(host, p) {
			return true
		}
	}
	return false
}

// findMatchingBinding scans the binding's expected auth header for a known proxy token.
func findMatchingBinding(req *http.Request, scope *Scope) (Binding, bool) {
	for proxyToken, binding := range scope.Bindings {
		if headerHasToken(req, binding, proxyToken) {
			return binding, true
		}
	}
	return Binding{}, false
}

// headerHasToken reports whether req carries the proxy token in the shape b expects.
func headerHasToken(req *http.Request, b Binding, proxyToken string) bool {
	switch b.AuthType {
	case "bearer":
		got := req.Header.Get("Authorization")
		return strings.EqualFold(got, "Bearer "+proxyToken)
	case "basic":
		// Match by password portion; the client's username is preserved on inject.
		_, pw, ok := decodeBasicAuth(req.Header.Get("Authorization"))
		if !ok {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(pw), []byte(proxyToken)) == 1
	case "api-key":
		name, _ := stringFromAuthConfig(b.AuthConfig, "header")
		if name == "" {
			name = "Authorization"
		}
		prefix, _ := stringFromAuthConfig(b.AuthConfig, "prefix")
		got := req.Header.Get(name)
		return got == prefix+proxyToken
	case "custom":
		headers, _ := mapStringFromAuthConfig(b.AuthConfig, "headers")
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

// applyInjection strips auth-owned headers and sets them to the real value(s).
// The strip is unconditional so a client-set value can never be preserved.
func applyInjection(req *http.Request, b Binding, real string) error {
	switch b.AuthType {
	case "bearer":
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", "Bearer "+real)
		return nil
	case "basic":
		// Preserve the inbound username; fall back to "x" for empty-user inputs.
		user, _, ok := decodeBasicAuth(req.Header.Get("Authorization"))
		if !ok || user == "" {
			user = "x"
		}
		req.Header.Del("Authorization")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+real)))
		return nil
	case "api-key":
		name, _ := stringFromAuthConfig(b.AuthConfig, "header")
		if name == "" {
			name = "Authorization"
		}
		prefix, _ := stringFromAuthConfig(b.AuthConfig, "prefix")
		req.Header.Del(name)
		req.Header.Set(name, prefix+real)
		return nil
	case "custom":
		headers, _ := mapStringFromAuthConfig(b.AuthConfig, "headers")
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
	return fmt.Errorf("unknown auth_type %q", b.AuthType)
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
