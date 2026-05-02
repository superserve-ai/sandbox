// Package api defines the IPC contract between vmd and secretsproxy.
// Both processes import these types so the wire format stays consistent.
package api

// SecretBinding pairs a stored credential id with its plaintext and the
// env-var name the agent will see. RealValue is never logged.
type SecretBinding struct {
	SecretID  string `json:"secret_id"`
	Provider  string `json:"provider"`
	EnvKey    string `json:"env_key"`
	RealValue string `json:"real_value"`
}

// EgressRules mirrors the customer's allow/deny lists. The proxy applies
// them when deciding whether to forward upstream — same semantics as the
// existing L4 egress proxy.
type EgressRules struct {
	AllowOut []string `json:"allow_out,omitempty"`
	DenyOut  []string `json:"deny_out,omitempty"`
}

// RegisterRequest is sent by vmd when a sandbox starts. SourceIP is the
// post-SNAT host-side IP that incoming connections will appear as; it
// keys the sandbox lookup on the proxy hot path.
type RegisterRequest struct {
	SandboxID string          `json:"sandbox_id"`
	TeamID    string          `json:"team_id"`
	SourceIP  string          `json:"source_ip"`
	Bindings  []SecretBinding `json:"bindings"`
	Egress    EgressRules     `json:"egress"`
}

// UpdateBindingsRequest replaces a sandbox's current bindings. Used both
// for rotation (push the freshly-decrypted real value) and for revocation
// (caller passes a binding list that omits the revoked secret_id).
type UpdateBindingsRequest struct {
	Bindings []SecretBinding `json:"bindings"`
}

// UpdateEgressRequest replaces a sandbox's egress rules.
type UpdateEgressRequest struct {
	Egress EgressRules `json:"egress"`
}
