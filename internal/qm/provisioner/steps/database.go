package steps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

// DatabaseAdmin manages per-tenant databases and roles on the shared Cloud
// SQL instance. The instance itself is Terraform-owned; this is the
// provisioner connecting to it as the instance admin role.
//
// Every method must be idempotent: CreateDatabase on a database that exists
// is a no-op, DropDatabase and DropUser on ones that do not are no-ops, and
// EnsureUser either creates the role or resets its password.
type DatabaseAdmin interface {
	// EnsureDatabase creates the database owned by owner if it is not
	// there, and either way reasserts the two things that isolate it: the
	// owner, and CONNECT taken away from PUBLIC. Reasserting rather than
	// only setting on create is what makes an interrupted first attempt
	// safe — those are separate statements, CREATE DATABASE cannot run in a
	// transaction, and a database left readable by every other tenant's
	// role is exactly the failure this step exists to prevent.
	EnsureDatabase(ctx context.Context, name, owner string) error
	DropDatabase(ctx context.Context, name string) error
	// EnsureUser creates the tenant's role or resets its password; the
	// password comes from the tenant's DATABASE_PASSWORD secret, which the
	// secrets step generated before this step runs.
	EnsureUser(ctx context.Context, name, password string) error
	DropUser(ctx context.Context, name string) error
}

var errNoDatabaseAdmin = errors.New("no database client configured")

// database creates the tenant's role, its database, and the DATABASE_URL
// secret its service mounts. Output: Row.DbName.
//
// Every call reconciles rather than creating once: the role's password is
// reset to the current secret, the database's owner and its closure to
// other roles are reasserted, and DATABASE_URL is rewritten. That is what
// makes a run interrupted between any two of those statements converge on
// a retry instead of leaving a database another tenant could connect to.
//
// Order within the step matters too: the role is created before the
// database that will be owned by it, and DATABASE_URL is written last, so
// an interrupted run leaves at worst a database with no reference to it,
// which the next run adopts.
type database struct {
	c Clients
}

func (database) Name() string { return "database" }

func (s database) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	if env.ExecutesPlan && s.c.Databases == nil {
		return errNoDatabaseAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	return env.Require(
		"QM_SQL_PRIVATE_IP", env.SQLPrivateIP,
		"QM_SQL_ADMIN_USER", env.SQLAdminUser,
		"QM_SQL_ADMIN_SECRET", env.SQLAdminSecret,
	)
}

func (s database) Run(ctx context.Context, t *provisioner.Tenant) error {
	name := DatabaseName(t.Row.Slug)
	if t.Env.Stub {
		if t.Row.DbName != nil {
			return provisioner.Skip("database " + *t.Row.DbName + " already recorded")
		}
		return t.Record(ctx, tenantstore.Resources{DBName: &name})
	}
	if s.c.Databases == nil {
		return errNoDatabaseAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	password, err := s.c.Secrets.Get(ctx, t.SecretName(secretDatabasePassword))
	if err != nil {
		return fmt.Errorf("read the tenant's database password: %w", err)
	}
	role := RoleName(t.Row.Slug)
	// EnsureUser before the database: the database is created owned by the
	// role, so the role has to exist first. Re-running it resets the
	// password to the one DATABASE_URL is about to be composed from, which
	// is what makes a half-finished attempt converge.
	if err := s.c.Databases.EnsureUser(ctx, role, string(password)); err != nil {
		return fmt.Errorf("create the tenant's database role: %w", err)
	}
	if err := s.c.Databases.EnsureDatabase(ctx, name, role); err != nil {
		return fmt.Errorf("create the tenant's database: %w", err)
	}
	// Written every run, not only on the run that created the database: it
	// is derived from the password above, so a rotation has to reach the
	// secret the service mounts or the tenant stops being able to connect.
	ref, err := s.c.Secrets.Put(ctx, t.SecretName(secretDatabaseURL), []byte(DatabaseURL(t.Env, role, string(password), name)))
	if err != nil {
		return fmt.Errorf("write the tenant's database url: %w", err)
	}
	if err := t.SetSecretRef(ctx, secretDatabaseURL, ref); err != nil {
		return err
	}
	if t.Row.DbName != nil && *t.Row.DbName == name {
		return provisioner.Skip("database " + name + " already recorded")
	}
	return t.Record(ctx, tenantstore.Resources{DBName: &name})
}

// Rollback drops the database, then the role, then the DATABASE_URL secret.
// Like the identity, it works from the derived names as well as the
// recorded one: a run that created the database and died before recording
// it would otherwise leave a tenant's data on the shared instance forever.
func (s database) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		if t.Row.DbName == nil {
			return provisioner.Skip("no database recorded")
		}
		return nil
	}
	if s.c.Databases == nil {
		return errNoDatabaseAdmin
	}
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	name := DatabaseName(t.Row.Slug)
	if t.Row.DbName != nil {
		name = *t.Row.DbName
	}
	// The database before the role: Postgres refuses to drop a role that
	// still owns objects.
	if err := s.c.Databases.DropDatabase(ctx, name); err != nil {
		return fmt.Errorf("drop the tenant's database: %w", err)
	}
	if err := s.c.Databases.DropUser(ctx, RoleName(t.Row.Slug)); err != nil {
		return fmt.Errorf("drop the tenant's database role: %w", err)
	}
	if err := s.c.Secrets.Delete(ctx, t.SecretName(secretDatabaseURL)); err != nil {
		return fmt.Errorf("delete the tenant's database url: %w", err)
	}
	if err := t.DeleteSecretRef(ctx, secretDatabaseURL); err != nil {
		return err
	}
	if t.Row.DbName == nil {
		return provisioner.Skip("no database recorded")
	}
	return nil
}

// DatabaseURL is the connection string the tenant's container reads.
//
// sslmode=require, which is "encrypt, do not verify": the shared instance
// is configured to refuse unencrypted connections, and its server
// certificate is self-signed, so verification would need its CA
// distributed to every tenant for no gain — the only route to the instance
// is its private IP over the VPC, and reaching it at all means already
// being inside. Both the drivers involved (pgx for the provisioner, node's
// pg for the tenant) read require as TLS without certificate verification.
func DatabaseURL(env provisioner.Env, role, password, dbName string) string {
	host := env.SQLPrivateIP
	// SplitHostPort is how an already-qualified host is told from a bare
	// address, and it is the IPv6-safe way to add the port to one.
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "5432")
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(role, password),
		Host:     host,
		Path:     "/" + dbName,
		RawQuery: "sslmode=require",
	}
	return u.String()
}
