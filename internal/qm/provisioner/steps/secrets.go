package steps

import (
	"context"
	"errors"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// errNoSecretStore is what the Secret Manager-backed steps report when no
// store was wired in; they have no placeholder mode to fall back to.
var errNoSecretStore = errors.New("no secret store configured")

// Generated per tenant, in plan order of nothing in particular: the step
// writes whichever are missing. See generated.go for what is deliberately
// absent.
var generatedSecrets = []generatedSecret{
	{name: secrets.PortalSessionSecret, value: randomSecret(32)},
	{name: secretDatabasePassword, value: randomSecret(24)},
	// QM's production boot check requires all five, each distinct.
	{name: "CORE_SIGNING_SECRET", value: randomSecret(32)},
	{name: "CAPABILITY_SECRET", value: randomSecret(32)},
	{name: "PORTAL_IDENTITY_SECRET", value: randomSecret(32)},
	{name: "CONNECTOR_SECRET_KEY", value: randomSecret(32)},
	{name: "SKILL_SIGNING_SECRET", value: randomSecret(32)},
	// The embedded sign-in broker's own credentials. AUTH_CLIENT_SECRET
	// must differ from AUTH_TOKEN_SECRET, which independent generation
	// gives us.
	{name: "AUTH_TOKEN_SECRET", value: randomSecret(32)},
	{name: "AUTH_CLIENT_SECRET", value: randomSecret(32)},
	{name: "AUTH_SIGNING_JWK", value: newSigningJWK},
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

// Ready: this step is real in every mode, so it needs a store even under
// QM_PROVISIONER_STUB.
func (s secretsStep) Ready(provisioner.Env) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	return nil
}

func (s secretsStep) Run(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
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
		value, err := spec.value()
		if err != nil {
			return fmt.Errorf("generate %s: %w", spec.name, err)
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
		return errNoSecretStore
	}
	refs, err := t.SecretRefs(ctx)
	if err != nil {
		return err
	}
	names := map[string]bool{secrets.ModelKeyName(t.Row.ModelProvider): true}
	for _, spec := range generatedSecrets {
		names[spec.name] = true
	}
	// The secrets later steps derive rather than generate. Their own
	// rollbacks remove them, but this step runs last on teardown and is the
	// backstop for one that failed before it got there: a leaked
	// DATABASE_URL or sandbox key is a live credential.
	for _, name := range derivedSecrets {
		names[name] = true
	}
	for _, ref := range refs {
		if ref.Name == sharedSecretRef {
			// A reference to a secret the platform owns and every other
			// tenant shares. Deleting it here would take the whole fleet's
			// email transport with it.
			continue
		}
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
