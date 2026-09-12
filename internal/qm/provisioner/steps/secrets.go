package steps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// Generated per tenant. The model provider key is not in this list: qm-api
// writes it at create time, before the run is triggered.
var generatedSecrets = []struct {
	name  string
	bytes int
}{
	{secrets.PortalSessionSecret, 32},
	{"DATABASE_PASSWORD", 24},
	{"CORE_SESSION_SECRET", 32},
}

// secretsStep generates the tenant's runtime secrets into Secret Manager
// and records their references. It runs first: the database step reads
// DATABASE_PASSWORD from here and the service_account step grants the
// tenant identity access to these names. It goes through the
// secrets.Store abstraction only, so it is real in every mode.
type secretsStep struct {
	c Clients
}

func (secretsStep) Name() string { return "secrets" }

func (s secretsStep) Run(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errors.New("secrets: no store configured")
	}
	existing, err := t.SecretRefs(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, ref := range existing {
		have[ref.Name] = true
	}
	generated := 0
	for _, spec := range generatedSecrets {
		if have[spec.name] {
			continue
		}
		value, err := randomHex(spec.bytes)
		if err != nil {
			return err
		}
		ref, err := s.c.Secrets.Put(ctx, t.SecretName(spec.name), []byte(value))
		if err != nil {
			return fmt.Errorf("write %s: %w", spec.name, err)
		}
		if err := t.SetSecretRef(ctx, spec.name, ref); err != nil {
			return err
		}
		generated++
	}
	if generated == 0 {
		return provisioner.Skip("all runtime secrets already recorded")
	}
	return nil
}

// Rollback removes every secret the tenant could own — the recorded
// references plus the names derived from the tenant itself, so a model key
// whose reference never landed (qm-api failed between Put and SetSecretRef)
// is still cleaned up — and forgets the references. Delete is idempotent,
// so names that were never written cost one no-op call each.
func (s secretsStep) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errors.New("secrets: no store configured")
	}
	refs, err := t.SecretRefs(ctx)
	if err != nil {
		return err
	}
	names := map[string]bool{secrets.ModelKeyName(t.Row.ModelProvider): true}
	for _, spec := range generatedSecrets {
		names[spec.name] = true
	}
	for _, ref := range refs {
		names[ref.Name] = true
	}
	for name := range names {
		if err := s.c.Secrets.Delete(ctx, t.SecretName(name)); err != nil {
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}
	for _, ref := range refs {
		if err := t.DeleteSecretRef(ctx, ref.Name); err != nil {
			return err
		}
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
