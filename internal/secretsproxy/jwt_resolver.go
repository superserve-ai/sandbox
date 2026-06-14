package secretsproxy

import "context"

// ruleAuthConfig flattens a JWTRuleClaim's typed fields into the same
// map[string]any shape the injector already consumes for single-rule bindings,
// so the writers in inject.go can stay shape-agnostic.
func ruleAuthConfig(r JWTRuleClaim) map[string]any {
	switch r.AuthType {
	case "basic":
		if r.Username == "" {
			return nil
		}
		return map[string]any{"username": r.Username}
	case "api-key":
		cfg := map[string]any{"header": r.Header}
		if r.Prefix != "" {
			cfg["prefix"] = r.Prefix
		}
		return cfg
	case "custom":
		if len(r.Headers) == 0 {
			return nil
		}
		headers := make(map[string]any, len(r.Headers))
		for k, v := range r.Headers {
			headers[k] = v
		}
		return map[string]any{"headers": headers}
	}
	return nil
}

// JWTResolver authenticates a CONNECT by verifying the JWT against the
// JWKS-backed Verifier and translating the claims into a Scope.
type JWTResolver struct {
	verifier *Verifier
}

// NewJWTResolver returns a Resolver that authenticates each CONNECT via the
// supplied Verifier (which itself owns the JWKS cache and refresh policy).
func NewJWTResolver(v *Verifier) *JWTResolver {
	return &JWTResolver{verifier: v}
}

// Authenticate implements Resolver. Any verification failure surfaces as
// ErrUnknownSandbox so callers can map every rejection uniformly to 407.
func (r *JWTResolver) Authenticate(ctx context.Context, sourceIP, jwt string) (*Scope, error) {
	claims, err := r.verifier.Verify(ctx, jwt, sourceIP)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]Binding, len(claims.Bindings))
	for _, b := range claims.Bindings {
		binding := Binding{
			SecretID:   b.SecretID,
			EnvKey:     b.EnvKey,
			AuthType:   b.AuthType,
			AuthConfig: b.AuthConfig,
			Hosts:      b.Hosts,
		}
		if len(b.Rules) > 0 {
			binding.Rules = make([]BindingRule, 0, len(b.Rules))
			for _, r := range b.Rules {
				binding.Rules = append(binding.Rules, BindingRule{
					Hosts:      r.Hosts,
					AuthType:   r.AuthType,
					AuthConfig: ruleAuthConfig(r),
				})
			}
		}
		bindings[b.ProxyToken] = binding
	}
	return &Scope{
		SandboxID: claims.Subject,
		TeamID:    claims.TeamID,
		SourceIP:  claims.SourceIP,
		Bindings:  bindings,
	}, nil
}
