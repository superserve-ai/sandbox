package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// DatabaseAdmin manages per-tenant databases and users on the shared Cloud
// SQL instance (Cloud SQL Admin API, sqladmin/v1: instances.databases and
// instances.users). The instance itself is Terraform-owned.
type DatabaseAdmin interface {
	DatabaseExists(ctx context.Context, name string) (bool, error)
	CreateDatabase(ctx context.Context, name string) error
	DropDatabase(ctx context.Context, name string) error
	// EnsureUser creates the tenant's role or resets its password; the
	// password comes from the tenant's DATABASE_PASSWORD secret, which
	// the secrets step generated before this step runs.
	EnsureUser(ctx context.Context, name, password string) error
	DropUser(ctx context.Context, name string) error
}

// database creates the tenant's database and role. Output: Row.DbName.
type database struct {
	stubOnly
	c Clients
}

func (database) Name() string { return "database" }

func (s database) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := DatabaseName(t.Row.Slug)
	if t.Env.Stub {
		if t.Row.DbName != nil {
			return provisioner.Skip("database " + *t.Row.DbName + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{DBName: &name})
	}
	return provisioner.NotImplemented(s.Name())
}

func (s database) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Row.DbName == nil {
		return provisioner.Skip("no database recorded")
	}
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}
