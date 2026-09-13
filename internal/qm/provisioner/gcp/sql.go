package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// Databases is the steps.DatabaseAdmin backed by a direct connection to the
// shared Cloud SQL instance as its admin role.
//
// Not the SQL Admin API, deliberately: that API can create a database and a
// user but cannot say who owns the database or take CONNECT away from
// PUBLIC, and without both of those every tenant's role could read every
// other tenant's data on the shared instance. Ownership and the revoke are
// the isolation, so they have to be in the same place the database is made.
type Databases struct {
	pool *pgxpool.Pool
}

var _ steps.DatabaseAdmin = (*Databases)(nil)

// Postgres error codes the create path treats as success.
const (
	pgDuplicateDatabase = "42P04"
	pgDuplicateObject   = "42710"
	pgObjectInUse       = "55006"
)

// dropRetries bounds how long DropDatabase waits out sessions the tenant's
// own container may still hold on the database it is being torn down with.
const (
	dropRetries = 5
	dropBackoff = 2 * time.Second
)

// NewDatabases connects to the instance's maintenance database as the admin
// role. adminDSN reaches the instance's private IP; the caller composes it
// from the Terraform-owned admin credentials.
func NewDatabases(ctx context.Context, adminDSN string) (*Databases, error) {
	if adminDSN == "" {
		return nil, errors.New("cloud sql: an admin connection string is required")
	}
	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		return nil, fmt.Errorf("cloud sql: parse the admin connection string: %w", err)
	}
	// A provisioner run touches the instance a handful of times; a big pool
	// would only eat into the connection budget tenants are sized against.
	cfg.MaxConns = 2
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cloud sql: connect as the admin role: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("cloud sql: ping the instance: %w", err)
	}
	return &Databases{pool: pool}, nil
}

func (d *Databases) Close() {
	d.pool.Close()
}

// identifierRe bounds what may be interpolated into DDL. Database and role
// names are derived from the slug (qm_<slug> with hyphens replaced), which
// this always matches — the check is here because DDL cannot take
// parameters, so an identifier that reached these statements unchecked
// would be an injection point.
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func quoteIdentifier(name string) (string, error) {
	if !identifierRe.MatchString(name) {
		return "", fmt.Errorf("cloud sql: refusing %q as an identifier", name)
	}
	return `"` + name + `"`, nil
}

func (d *Databases) DatabaseExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("look up database %s: %w", name, err)
	}
	return exists, nil
}

// CreateDatabase makes the database owned by the tenant's role and closes it
// to everyone else. CREATE DATABASE cannot run inside a transaction, so the
// two statements are separate and the revoke is repeated by the next run if
// this one dies between them — which is why Run calls this only after
// DatabaseExists says no, and why the revoke is idempotent.
func (d *Databases) CreateDatabase(ctx context.Context, name, owner string) error {
	dbIdent, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	ownerIdent, err := quoteIdentifier(owner)
	if err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx, `CREATE DATABASE `+dbIdent+` OWNER `+ownerIdent)
	if err != nil && !isPGCode(err, pgDuplicateDatabase) {
		return fmt.Errorf("create database %s: %w", name, err)
	}
	// Without this every role on the shared instance — that is, every other
	// tenant — could connect to this database.
	if _, err := d.pool.Exec(ctx, `REVOKE CONNECT ON DATABASE `+dbIdent+` FROM PUBLIC`); err != nil {
		return fmt.Errorf("close database %s to other roles: %w", name, err)
	}
	return nil
}

// DropDatabase removes the database, waiting out sessions still attached to
// it: the tenant's own container may not have finished shutting down when
// teardown reaches this step.
func (d *Databases) DropDatabase(ctx context.Context, name string) error {
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < dropRetries; attempt++ {
		if attempt > 0 {
			// Terminate what is still attached, then try again. Sessions
			// can reconnect, which is why this is a loop and not one call.
			if _, err := d.pool.Exec(ctx,
				`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
				name); err != nil {
				return fmt.Errorf("disconnect sessions from %s: %w", name, err)
			}
		}
		_, err := d.pool.Exec(ctx, `DROP DATABASE IF EXISTS `+ident)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isPGCode(err, pgObjectInUse) {
			return fmt.Errorf("drop database %s: %w", name, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dropBackoff):
		}
	}
	return fmt.Errorf("drop database %s: still in use after %d attempts: %w", name, dropRetries, lastErr)
}

// EnsureUser creates the role or resets its password to the tenant's
// current one, so a retry converges on the password DATABASE_URL carries.
// The role gets LOGIN and nothing else: it owns its own database and has no
// standing rights anywhere on the instance.
func (d *Databases) EnsureUser(ctx context.Context, name, password string) error {
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	// The password is a literal, not an identifier, so it goes through
	// pgx's quoting rather than string concatenation.
	quoted, err := quoteLiteral(ctx, d.pool, password)
	if err != nil {
		return err
	}
	_, err = d.pool.Exec(ctx, `CREATE ROLE `+ident+` WITH LOGIN PASSWORD `+quoted)
	if err != nil && !isPGCode(err, pgDuplicateObject) {
		return fmt.Errorf("create role %s: %w", name, err)
	}
	if _, err := d.pool.Exec(ctx, `ALTER ROLE `+ident+` WITH LOGIN PASSWORD `+quoted); err != nil {
		return fmt.Errorf("set the password of role %s: %w", name, err)
	}
	return nil
}

func (d *Databases) DropUser(ctx context.Context, name string) error {
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	// The tenant's database is dropped first, so by here the role owns
	// nothing; DROP ROLE still fails loudly if that ever stops being true,
	// which is the behaviour we want rather than a silent leak.
	if _, err := d.pool.Exec(ctx, `DROP ROLE IF EXISTS `+ident); err != nil {
		return fmt.Errorf("drop role %s: %w", name, err)
	}
	return nil
}

// quoteLiteral asks Postgres to quote the value, so no escaping rule is
// reimplemented here.
func quoteLiteral(ctx context.Context, pool *pgxpool.Pool, value string) (string, error) {
	var quoted string
	if err := pool.QueryRow(ctx, `SELECT quote_literal($1::text)`, value).Scan(&quoted); err != nil {
		return "", fmt.Errorf("quote a password: %w", err)
	}
	return quoted, nil
}

func isPGCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
