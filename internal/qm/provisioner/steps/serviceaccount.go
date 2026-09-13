package steps

import (
	"context"
	"errors"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// ServiceAccountAdmin manages the tenant's runtime identity (IAM API,
// iam/v1 projects.serviceAccounts) and the bindings that let it read the
// secrets its service mounts (Secret Manager IAM).
//
// Every method must be idempotent. Create on an account that already exists
// returns that account rather than an error; Delete on one that does not is
// a no-op; GrantSecretAccess adds a binding that is already there without
// complaint.
type ServiceAccountAdmin interface {
	Exists(ctx context.Context, email string) (bool, error)
	Create(ctx context.Context, accountID, displayName string) (email string, err error)
	Delete(ctx context.Context, email string) error
	// GrantSecretAccess binds roles/secretmanager.secretAccessor on one
	// secret to the account.
	GrantSecretAccess(ctx context.Context, secretName, email string) error
	// RevokeSecretAccess removes that binding. Needed only for secrets the
	// tenant does not own: deleting a tenant's own secret takes its policy
	// with it, but the platform's shared ones outlive every tenant, and
	// deleting a service account does not remove the bindings naming it.
	RevokeSecretAccess(ctx context.Context, secretName, email string) error
}

var errNoServiceAccountAdmin = errors.New("no service account client configured")

// serviceAccount creates the tenant's identity, and nothing else: the
// bindings that let it read secrets are granted by the cloud_run step, on
// exactly the set that service mounts. Splitting them that way is what
// keeps the two from drifting — a secret added to the service spec without
// a matching grant is a container that crashes on boot.
//
// Output: Row.ServiceAccount.
type serviceAccount struct {
	c Clients
}

func (serviceAccount) Name() string { return "service_account" }

func (s serviceAccount) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	if s.c.Accounts == nil {
		return errNoServiceAccountAdmin
	}
	return env.Require("GCP_PROJECT", env.Project)
}

func (s serviceAccount) Run(ctx context.Context, t *provisioner.Tenant) error {
	email := ServiceAccountEmail(t.Env.Project, t.Row.Slug)
	if t.Env.Stub {
		if t.Row.ServiceAccount != nil {
			return provisioner.Skip("service account " + *t.Row.ServiceAccount + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{ServiceAccount: &email})
	}
	if s.c.Accounts == nil {
		return errNoServiceAccountAdmin
	}
	// Check-then-create against the cloud, not against the row: a run that
	// created the account and died before recording it must converge, not
	// fail on a name that is already taken.
	exists, err := s.c.Accounts.Exists(ctx, email)
	if err != nil {
		return fmt.Errorf("look up service account: %w", err)
	}
	if !exists {
		created, err := s.c.Accounts.Create(ctx, ServiceAccountID(t.Row.Slug), "QM tenant "+t.Row.Slug)
		if err != nil {
			return fmt.Errorf("create service account: %w", err)
		}
		email = created
	}
	if t.Row.ServiceAccount != nil && *t.Row.ServiceAccount == email {
		return provisioner.Skip("service account " + email + " already recorded")
	}
	return t.Record(ctx, tenantstore.Resources{ServiceAccount: &email})
}

// Rollback deletes the identity. It works from the name the slug derives
// rather than only from the recorded one, so an account created by a run
// that died before Record is still removed: a leaked service account is a
// standing principal on the project, and the next tenant to take the slug
// would inherit it.
func (s serviceAccount) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		if t.Row.ServiceAccount == nil {
			return provisioner.Skip("no service account recorded")
		}
		return nil
	}
	if s.c.Accounts == nil {
		return errNoServiceAccountAdmin
	}
	email := ServiceAccountEmail(t.Env.Project, t.Row.Slug)
	if t.Row.ServiceAccount != nil {
		email = *t.Row.ServiceAccount
	}
	if err := s.c.Accounts.Delete(ctx, email); err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	if t.Row.ServiceAccount == nil {
		return provisioner.Skip("no service account recorded")
	}
	return nil
}
