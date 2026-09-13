package steps

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// sandboxKeyBytes of entropy in the random half of an issued key.
const sandboxKeyBytes = 24

// sandboxKey issues the tenant's Superserve API key — the credential its QM
// uses to create sandboxes — writes it to Secret Manager and records it on
// the row. Outputs: Row.SandboxApiKeyID and the SUPERSERVE_API_KEY secret.
//
// Teardown revokes the key rather than merely forgetting the reference: the
// key is bound to this cell, and team migration refuses a region cutover
// while a tenant still references an unrevoked one, so a teardown that only
// dropped the row would strand the team.
type sandboxKey struct {
	c Clients
}

func (sandboxKey) Name() string { return "sandbox_key" }

// Ready: the key is minted in Postgres and stored in Secret Manager, so
// unlike the GCP steps this one is real in stub mode too and needs a secret
// store either way.
func (s sandboxKey) Ready(provisioner.Env) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	return nil
}

func (s sandboxKey) Run(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	if t.Row.SandboxApiKeyID.Valid {
		return provisioner.Skip("sandbox key already recorded")
	}
	raw, err := NewSandboxKey(t.Env.SandboxKeyRegion)
	if err != nil {
		return err
	}
	// The secret before the key row, deliberately. The row is what teardown
	// revokes from, so a key that exists in Postgres and nowhere else is a
	// live credential the tenant cannot use; a secret holding a key that
	// was never issued is inert, and the next attempt overwrites it.
	ref, err := s.c.Secrets.Put(ctx, t.SecretName(secretSandboxAPIKey), []byte(raw))
	if err != nil {
		return fmt.Errorf("write the tenant's sandbox key: %w", err)
	}
	if err := t.SetSecretRef(ctx, secretSandboxAPIKey, ref); err != nil {
		return err
	}
	keyID, err := t.IssueSandboxKey(ctx, qm.HashAPIKey(raw))
	if err != nil {
		return fmt.Errorf("issue the tenant's sandbox key: %w", err)
	}
	// Already atomic in the database; this is what refreshes the row so the
	// steps after this one see the key.
	return t.Record(ctx, tenantstore.Resources{SandboxAPIKeyID: &keyID})
}

// Rollback revokes the key and removes the secret holding it. Both halves
// run whatever the row says: the secret can outlive an attempt that failed
// before the key was issued.
func (s sandboxKey) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	had, err := t.RevokeSandboxKey(ctx)
	if err != nil {
		return err
	}
	if err := s.c.Secrets.Delete(ctx, t.SecretName(secretSandboxAPIKey)); err != nil {
		return fmt.Errorf("delete the tenant's sandbox key: %w", err)
	}
	if err := t.DeleteSecretRef(ctx, secretSandboxAPIKey); err != nil {
		return err
	}
	if !had {
		return provisioner.Skip("no sandbox key recorded")
	}
	return nil
}

// NewSandboxKey mints a raw API key in the control plane's format:
// ss_live_<region>_<random>, or ss_live_<random> when the cell has no
// region token. The region is plaintext by design — it is how a key
// presented to the wrong cell gets told where it belongs.
func NewSandboxKey(region string) (string, error) {
	b := make([]byte, sandboxKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate sandbox key: %w", err)
	}
	random := base64.RawURLEncoding.EncodeToString(b)
	if region == "" {
		return "ss_live_" + random, nil
	}
	return "ss_live_" + region + "_" + random, nil
}
