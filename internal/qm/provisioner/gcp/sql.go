package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
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
	dsn func(context.Context) (string, error)

	mu   sync.Mutex
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

// NewDatabases prepares the client without connecting. dsn is resolved on
// first use, because it needs the instance's admin password out of Secret
// Manager and the qm-api *service* never calls any of these methods — it
// only queues the job that does. Dialing the tenant instance at startup
// would put an outage there (or in Secret Manager) in front of the control
// API, which has nothing to do with either.
func NewDatabases(dsn func(context.Context) (string, error)) *Databases {
	return &Databases{dsn: dsn}
}

// connect returns the pool, dialing on the first call. A failed attempt is
// not cached: the next call retries, so a run started while the instance
// was briefly unreachable converges instead of failing for the life of the
// process.
func (d *Databases) connect(ctx context.Context) (*pgxpool.Pool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pool != nil {
		return d.pool, nil
	}
	if d.dsn == nil {
		return nil, errors.New("cloud sql: no admin connection string")
	}
	adminDSN, err := d.dsn(ctx)
	if err != nil {
		return nil, err
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
	d.pool = pool
	return pool, nil
}

// Close releases the pool if one was ever opened.
func (d *Databases) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pool != nil {
		d.pool.Close()
		d.pool = nil
	}
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

// EnsureDatabase creates the database if it is not there and, either way,
// reasserts its isolation: owned by the tenant's role, and closed to
// everyone else on the shared instance.
//
// The order is what makes it safe on a shared instance, and none of it is
// interchangeable:
//
//  1. CREATE DATABASE with connections disallowed, owned by the admin. A
//     database created owned by the tenant cannot then have CONNECT
//     revoked from PUBLIC by the admin — the revoke is a no-op with a
//     warning — and a database created connectable is one every other
//     tenant's role can reach for as long as the gap lasts. A session
//     opened in that gap survives the later revoke.
//  2. Revoke CONNECT from PUBLIC while the admin still owns it.
//  3. Hand ownership to the tenant. The database owner is what gives the
//     tenant rights on its public schema, which from Postgres 15 is owned
//     by pg_database_owner rather than granted to PUBLIC.
//  4. Allow connections.
//
// Reasserting the last three on every call is deliberate: CREATE DATABASE
// cannot run inside a transaction, so a run that died between any two of
// them would otherwise leave a database either unreachable by its own
// tenant or reachable by every other one, and no later run would notice.
func (d *Databases) EnsureDatabase(ctx context.Context, name, owner string) error {
	pool, err := d.connect(ctx)
	if err != nil {
		return err
	}
	dbIdent, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	ownerIdent, err := quoteIdentifier(owner)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `CREATE DATABASE `+dbIdent+` ALLOW_CONNECTIONS false`)
	if err != nil && !isPGCode(err, pgDuplicateDatabase) {
		return fmt.Errorf("create database %s: %w", name, err)
	}
	// Without this every role on the shared instance — that is, every other
	// tenant — could connect to this database.
	if _, err := pool.Exec(ctx, `REVOKE CONNECT ON DATABASE `+dbIdent+` FROM PUBLIC`); err != nil {
		return fmt.Errorf("close database %s to other roles: %w", name, err)
	}
	if _, err := pool.Exec(ctx, `ALTER DATABASE `+dbIdent+` OWNER TO `+ownerIdent); err != nil {
		return fmt.Errorf("set the owner of database %s: %w", name, err)
	}
	if _, err := pool.Exec(ctx, `ALTER DATABASE `+dbIdent+` WITH ALLOW_CONNECTIONS true`); err != nil {
		return fmt.Errorf("open database %s to its tenant: %w", name, err)
	}
	return nil
}

// DropDatabase removes the database, waiting out sessions still attached to
// it: the tenant's own container may not have finished shutting down when
// teardown reaches this step.
func (d *Databases) DropDatabase(ctx context.Context, name string) error {
	pool, err := d.connect(ctx)
	if err != nil {
		return err
	}
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < dropRetries; attempt++ {
		if attempt > 0 {
			// Terminate what is still attached, then try again. Sessions
			// can reconnect, which is why this is a loop and not one call.
			if _, err := pool.Exec(ctx,
				`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
				name); err != nil {
				return fmt.Errorf("disconnect sessions from %s: %w", name, err)
			}
		}
		_, err := pool.Exec(ctx, `DROP DATABASE IF EXISTS `+ident)
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
//
// It also grants the role to the admin. That is not a convenience: from
// Postgres 16 a CREATEROLE administrator is not automatically able to SET
// ROLE to the roles it creates, and without that it cannot hand a database
// over to one — ALTER DATABASE ... OWNER TO fails with "must be able to SET
// ROLE". The admin is already the more privileged of the two, so it gives
// away nothing.
func (d *Databases) EnsureUser(ctx context.Context, name, password string) error {
	pool, err := d.connect(ctx)
	if err != nil {
		return err
	}
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	// The password is a literal, not an identifier, so it goes through
	// Postgres's own quoting rather than string concatenation.
	quoted, err := quoteLiteral(ctx, pool, password)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `CREATE ROLE `+ident+` WITH LOGIN PASSWORD `+quoted)
	if err != nil && !isPGCode(err, pgDuplicateObject) {
		return fmt.Errorf("create role %s: %w", name, err)
	}
	if _, err := pool.Exec(ctx, `ALTER ROLE `+ident+` WITH LOGIN PASSWORD `+quoted); err != nil {
		return fmt.Errorf("set the password of role %s: %w", name, err)
	}
	// INHERIT as well as SET: the ownership checks on ALTER DATABASE read
	// the privileges the admin holds, not the ones it could assume.
	if _, err := pool.Exec(ctx, `GRANT `+ident+` TO CURRENT_USER WITH SET TRUE, INHERIT TRUE`); err != nil {
		return fmt.Errorf("let the admin act for role %s: %w", name, err)
	}
	return nil
}

func (d *Databases) DropUser(ctx context.Context, name string) error {
	pool, err := d.connect(ctx)
	if err != nil {
		return err
	}
	ident, err := quoteIdentifier(name)
	if err != nil {
		return err
	}
	// The tenant's database is dropped first, so by here the role owns
	// nothing; DROP ROLE still fails loudly if that ever stops being true,
	// which is the behaviour we want rather than a silent leak.
	if _, err := pool.Exec(ctx, `DROP ROLE IF EXISTS `+ident); err != nil {
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
