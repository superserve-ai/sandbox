package secretsproxy

import "sync"

// Revoker tracks sandbox IDs the control plane has revoked.
type Revoker struct {
	mu        sync.RWMutex
	sandboxes map[string]struct{}
}

func NewRevoker() *Revoker {
	return &Revoker{sandboxes: map[string]struct{}{}}
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
