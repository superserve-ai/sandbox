package secretsproxy

import "context"

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
		bindings[b.ProxyToken] = Binding{
			SecretID:   b.SecretID,
			EnvKey:     b.EnvKey,
			AuthType:   b.AuthType,
			AuthConfig: b.AuthConfig,
			Hosts:      b.Hosts,
		}
	}
	return &Scope{
		SandboxID:           claims.Subject,
		TeamID:              claims.TeamID,
		SourceIP:            claims.SourceIP,
		UnmatchedHostPolicy: claims.UnmatchedHostPolicy,
		Allow:               claims.Allow,
		Deny:                claims.Deny,
		Bindings:            bindings,
	}, nil
}
