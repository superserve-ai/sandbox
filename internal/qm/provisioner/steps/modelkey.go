package steps

import (
	"context"
	"errors"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm/modelkey"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// checkModelKey fails the smoke step when the tenant's provider says its
// key is not valid. qm-api asks the same question before it creates the
// tenant, so reaching here normally means the key was revoked or rotated in
// between — but a tenant whose agent cannot call a model is not a working
// tenant, and finding that out at the first message instead is much worse.
func checkModelKey(ctx context.Context, c Clients, t *provisioner.Tenant) error {
	if !modelkey.Supported(t.Row.ModelProvider) {
		return nil
	}
	if c.Secrets == nil {
		return errNoSecretStore
	}
	key, err := readTenantSecret(ctx, c, t, secrets.ModelKeyName(t.Row.ModelProvider))
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			// qm-api writes this before the run is triggered, so its
			// absence is not something a retry fixes.
			return fmt.Errorf("the tenant has no %s key in Secret Manager", t.Row.ModelProvider)
		}
		return fmt.Errorf("read the tenant's model key: %w", err)
	}
	if err := modelkey.Verify(ctx, c.HTTP, t.Row.ModelProvider, string(key)); err != nil {
		// Named, not quoted: the provider's own wording can echo the key.
		return fmt.Errorf("%s rejected the tenant's model key: replace it and create the tenant again", t.Row.ModelProvider)
	}
	return nil
}
