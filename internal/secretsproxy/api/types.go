// Package api is the JSON wire format shared by both ends of the
// secrets-proxy control IPC.
package api

type SecretBinding struct {
	SecretID  string `json:"secret_id"`
	Provider  string `json:"provider"`
	EnvKey    string `json:"env_key"`
	RealValue string `json:"real_value"`
}

type EgressRules struct {
	AllowOut []string `json:"allow_out,omitempty"`
	DenyOut  []string `json:"deny_out,omitempty"`
}

// RegisterRequest installs (or replaces) a sandbox's state. SourceIP is
// the post-SNAT address incoming connections will report.
type RegisterRequest struct {
	SandboxID string          `json:"sandbox_id"`
	TeamID    string          `json:"team_id"`
	SourceIP  string          `json:"source_ip"`
	Bindings  []SecretBinding `json:"bindings"`
	Egress    EgressRules     `json:"egress"`
}

type UpdateBindingsRequest struct {
	Bindings []SecretBinding `json:"bindings"`
}

type UpdateEgressRequest struct {
	Egress EgressRules `json:"egress"`
}

// PropagateSecretRequest pushes a new value (empty=revoke) for one
// secret across every binding that references it on this host.
type PropagateSecretRequest struct {
	SecretID  string `json:"secret_id"`
	RealValue string `json:"real_value,omitempty"`
}
