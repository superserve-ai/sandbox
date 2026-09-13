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
		if err := putTenantSecret(ctx, s.c, t, spec.name, value); err != nil {
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
		if err := deleteTenantSecret(ctx, s.c, t, name); err != nil {
			return err
		}
	}
	for _, ref := range refs {
		if err := t.DeleteSecretRef(ctx, ref.Name); err != nil {
			return err
		}
	}
	return nil
}

// readTenantSecret reads one of the tenant's own secrets, having first
// confirmed it is the tenant's.
//
// The check is here and not only where secrets are written because the
// secrets step skips a secret whose reference is already recorded: a
// recorded secret deleted and recreated by something else is never
// re-verified on the write path, and a step that then consumed its value —
// setting the tenant's database password to one that workload knows, say —
// would have done the damage before any later check ran.
func readTenantSecret(ctx context.Context, c Clients, t *provisioner.Tenant, name string) ([]byte, error) {
	full := t.SecretName(name)
	if err := checkSecretOwner(ctx, c, t, full); err != nil {
		return nil, err
	}
	return c.Secrets.Get(ctx, full)
}

// checkSecretOwner refuses a secret that belongs to another tenant. It is
// the one place the rule lives, so the read, grant and write paths cannot
// disagree — an unlabelled secret that Put would adopt but Get refused
// would just be a bug.
//
// Unlabelled is adoptable: see secrets.GCP.checkOwner for why the deploy
// window makes that necessary and why a tenant secret's name shape makes it
// safe. It is claimed here too, not just read, so the tolerance lasts for
// one visit rather than for as long as something never calls Put on it
// again — true of the model key, which qm-api writes once at tenant
// creation and this layer only ever reads or grants. Left unclaimed, a
// secret deleted and recreated unlabelled later would pass this check
// forever instead of only across the deploy window it exists for.
func checkSecretOwner(ctx context.Context, c Clients, t *provisioner.Tenant, fullName string) error {
	owner, exists, err := c.Secrets.Owner(ctx, fullName)
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", fullName, err)
	}
	if !exists {
		return nil
	}
	if owner != "" {
		if owner != t.Row.ID.String() {
			return fmt.Errorf("%w: secret %s", ErrNotOwned, fullName)
		}
		return nil
	}
	if err := c.Secrets.Claim(ctx, fullName, t.Row.ID.String()); err != nil {
		// Claim's own read-back can lose a race against another claim on the
		// same unlabelled secret and report ErrNotOwned; the steps layer
		// speaks one sentinel whatever the resource, so that comes back the
		// same way a labelled mismatch would.
		if errors.Is(err, secrets.ErrNotOwned) {
			return fmt.Errorf("%w: secret %s", ErrNotOwned, fullName)
		}
		return fmt.Errorf("claim %s: %w", fullName, err)
	}
	return nil
}

// putTenantSecret writes one of the tenant's secrets, labelled as its own,
// and records the reference. A secret of that name belonging to something
// else comes back as ErrNotOwned so the steps layer speaks one sentinel
// whatever the resource is.
func putTenantSecret(ctx context.Context, c Clients, t *provisioner.Tenant, name, value string) error {
	ref, err := c.Secrets.Put(ctx, t.SecretName(name), []byte(value), t.Row.ID.String())
	if errors.Is(err, secrets.ErrNotOwned) {
		return fmt.Errorf("%w: secret %s", ErrNotOwned, t.SecretName(name))
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return t.SetSecretRef(ctx, name, ref)
}

// deleteTenantSecret removes one of the tenant's secrets, and treats a
// secret that is not this tenant's as nothing to remove.
//
// Skipping rather than failing is the point: the name is derived from a
// slug, so a secret under that name may belong to something else — and a
// teardown that stopped there would leave the tenant undeletable forever
// over a secret it never created.
func deleteTenantSecret(ctx context.Context, c Clients, t *provisioner.Tenant, name string) error {
	err := c.Secrets.Delete(ctx, t.SecretName(name), t.Row.ID.String())
	if err == nil || errors.Is(err, secrets.ErrNotOwned) {
		return nil
	}
	return fmt.Errorf("delete %s: %w", name, err)
}
