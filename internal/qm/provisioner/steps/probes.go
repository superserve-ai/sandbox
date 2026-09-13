package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// healthCheck waits for the tenant to answer on its public URL through the
// load balancer (Clients.HTTP). Read-only, so Rollback has nothing to do.
type healthCheck struct {
	stubOnly
	c Clients
}

func (healthCheck) Name() string { return "health_check" }

func (s healthCheck) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}

func (healthCheck) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}

// smoke exercises the deployed stack end to end (sign-in page renders, the
// admin API answers with the tenant's credentials). Read-only.
type smoke struct {
	stubOnly
	c Clients
}

func (smoke) Name() string { return "smoke" }

func (s smoke) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}

func (smoke) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}

// adminLink proves the tenant is ready for the console's admin sign-in:
// the portal session secret exists and a link can be minted against the
// public URL. The link itself is discarded, never recorded.
type adminLink struct {
	c Clients
}

func (adminLink) Name() string { return "admin_link" }

// Ready: minting a link needs the tenant's portal session secret, so this
// step needs a store in every mode.
func (s adminLink) Ready(provisioner.Env) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	return nil
}

func (s adminLink) Run(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	if t.Row.PublicUrl == nil {
		return provisioner.Skip("no public URL recorded yet")
	}
	secret, err := s.c.Secrets.Get(ctx, t.SecretName(secrets.PortalSessionSecret))
	if err != nil {
		return err
	}
	jti, err := adminlink.NewJTI()
	if err != nil {
		return err
	}
	_, err = adminlink.Mint(*t.Row.PublicUrl, string(secret), t.Row.AdminEmail, timeNow(), jti)
	return err
}

func (adminLink) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}
