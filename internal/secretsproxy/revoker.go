package secretsproxy

import "sync"

// RevokedProxyToken identifies one revoked binding by the sandbox it belonged to
// and its stand-in proxy token.
type RevokedProxyToken struct {
	SandboxID  string
	ProxyToken string
}

// Revoker tracks sandbox IDs and individual proxy tokens the control plane has
// revoked. A revoked sandbox refuses the whole JWT; a revoked proxy token refuses
// just that binding, so a detached credential stops working even for a process
// still holding a JWT that lists it.
type Revoker struct {
	mu        sync.RWMutex
	sandboxes map[string]struct{}
	tokens    map[string]struct{} // key: sandboxID + "\x00" + proxyToken
}

func NewRevoker() *Revoker {
	return &Revoker{sandboxes: map[string]struct{}{}, tokens: map[string]struct{}{}}
}

func proxyTokenKey(sandboxID, proxyToken string) string {
	return sandboxID + "\x00" + proxyToken
}

// RevokeSandbox adds sandboxID to the revoked set. Idempotent.
func (r *Revoker) RevokeSandbox(sandboxID string) {
	r.mu.Lock()
	r.sandboxes[sandboxID] = struct{}{}
	r.mu.Unlock()
}

// IsSandboxRevoked reports whether sandboxID was revoked.
func (r *Revoker) IsSandboxRevoked(sandboxID string) bool {
	r.mu.RLock()
	_, ok := r.sandboxes[sandboxID]
	r.mu.RUnlock()
	return ok
}

// Bootstrap replaces the revoked set with the supplied IDs. Used at startup.
func (r *Revoker) Bootstrap(sandboxIDs []string) {
	next := make(map[string]struct{}, len(sandboxIDs))
	for _, id := range sandboxIDs {
		next[id] = struct{}{}
	}
	r.mu.Lock()
	r.sandboxes = next
	r.mu.Unlock()
}

// Reconcile merges sandboxIDs into the revoked set without removing existing
// entries. Used by the periodic backstop so a dropped revocation push is picked
// up on the next fetch. Add-only on purpose: a blind replace could race a
// just-arrived push and briefly un-revoke a sandbox, and a revoked sandbox is
// never legitimately un-revoked (a destroyed one's stale entry is harmless).
func (r *Revoker) Reconcile(sandboxIDs []string) {
	r.mu.Lock()
	for _, id := range sandboxIDs {
		r.sandboxes[id] = struct{}{}
	}
	r.mu.Unlock()
}

// RevokeProxyToken adds one (sandbox, proxy token) pair to the revoked set. Idempotent.
func (r *Revoker) RevokeProxyToken(sandboxID, proxyToken string) {
	r.mu.Lock()
	r.tokens[proxyTokenKey(sandboxID, proxyToken)] = struct{}{}
	r.mu.Unlock()
}

// IsProxyTokenRevoked reports whether proxyToken was revoked for sandboxID.
func (r *Revoker) IsProxyTokenRevoked(sandboxID, proxyToken string) bool {
	r.mu.RLock()
	_, ok := r.tokens[proxyTokenKey(sandboxID, proxyToken)]
	r.mu.RUnlock()
	return ok
}

// BootstrapProxyTokens replaces the revoked-token set with the supplied pairs.
// Used at startup, where a full replace prunes tokens whose JWT has since expired.
func (r *Revoker) BootstrapProxyTokens(toks []RevokedProxyToken) {
	next := make(map[string]struct{}, len(toks))
	for _, t := range toks {
		next[proxyTokenKey(t.SandboxID, t.ProxyToken)] = struct{}{}
	}
	r.mu.Lock()
	r.tokens = next
	r.mu.Unlock()
}

// ReconcileProxyTokens merges pairs into the revoked-token set without removing
// existing entries. Add-only for the same reason as Reconcile: a revoked binding
// is never legitimately un-revoked.
func (r *Revoker) ReconcileProxyTokens(toks []RevokedProxyToken) {
	r.mu.Lock()
	for _, t := range toks {
		r.tokens[proxyTokenKey(t.SandboxID, t.ProxyToken)] = struct{}{}
	}
	r.mu.Unlock()
}
