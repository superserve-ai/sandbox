package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
)

// sandboxKey issues the tenant's Superserve API key — the credential its QM
// uses to create sandboxes — and records it on the row. Output:
// Row.SandboxApiKeyID.
//
// Minting is not implemented yet, but the teardown half is real in every
// mode and deliberately so: the key is bound to this cell, and team
// migration refuses a region cutover while a tenant still references an
// unrevoked one, so a teardown that only forgot the reference would strand
// the team.
type sandboxKey struct {
	stubOnly
	c Clients
}

func (sandboxKey) Name() string { return "sandbox_key" }

func (s sandboxKey) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Row.SandboxApiKeyID.Valid {
		return provisioner.Skip("sandbox key already recorded")
	}
	if t.Env.Stub {
		// A placeholder is not available here as it is for the other
		// steps: the column references api_key, so there is nothing to
		// record without a key that really exists.
		return provisioner.Skip("no sandbox key is issued in stub mode")
	}
	return provisioner.NotImplemented(s.Name())
}

func (s sandboxKey) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	had, err := t.RevokeSandboxKey(ctx)
	if err != nil {
		return err
	}
	if !had {
		return provisioner.Skip("no sandbox key recorded")
	}
	return nil
}
