package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// ServiceAccountAdmin manages the tenant's runtime identity (IAM API,
// iam/v1 projects.serviceAccounts) and the bindings that let it read its
// own secrets (Secret Manager IAM; the secrets step has already created
// them by the time this runs) and bucket (Storage IAM).
type ServiceAccountAdmin interface {
	Exists(ctx context.Context, email string) (bool, error)
	Create(ctx context.Context, accountID, displayName string) (email string, err error)
	Delete(ctx context.Context, email string) error
	// GrantSecretAccess binds roles/secretmanager.secretAccessor on one
	// secret to the account.
	GrantSecretAccess(ctx context.Context, secretName, email string) error
}

// serviceAccount creates the tenant's identity. Output: Row.ServiceAccount.
type serviceAccount struct {
	c Clients
}

func (serviceAccount) Name() string { return "service_account" }

func (s serviceAccount) Run(ctx context.Context, t *provisioner.Tenant) error {
	email := ServiceAccountEmail(t.Env.Project, t.Row.Slug)
	if t.Env.Stub {
		if t.Row.ServiceAccount != nil {
			return provisioner.Skip("service account " + *t.Row.ServiceAccount + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{ServiceAccount: &email})
	}
	return provisioner.NotImplemented(s.Name())
}

func (s serviceAccount) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Row.ServiceAccount == nil {
		return provisioner.Skip("no service account recorded")
	}
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}
