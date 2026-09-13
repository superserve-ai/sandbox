//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/gcp"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// The provisioner's database client is the one piece of this whose
// correctness cannot be established with a fake: what it does is DDL, and
// what makes it safe is Postgres's own ownership and ACL rules. So it runs
// here, against a real server, as a role with exactly the privileges Cloud
// SQL's instance admin has — CREATEDB and CREATEROLE, and nothing more.

const qmSQLAdminPassword = "qm-sql-admin-integration-test"

// qmSQLAdmin returns a client connected as a CREATEDB/CREATEROLE role, and
// registers cleanup for everything the test creates.
func qmSQLAdmin(t *testing.T, slugs ...string) *gcp.Databases {
	t.Helper()
	ctx := context.Background()
	admin := "qm_admin_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := testPool.Exec(ctx,
		fmt.Sprintf(`CREATE ROLE %q WITH LOGIN PASSWORD '%s' CREATEDB CREATEROLE`, admin, qmSQLAdminPassword)); err != nil {
		t.Fatalf("create the instance admin role: %v", err)
	}
	cfg, err := pgx.ParseConfig(testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		admin, qmSQLAdminPassword, cfg.Host, cfg.Port, cfg.Database)
	client := gcp.NewDatabases(func(context.Context) (string, error) { return dsn, nil })
	t.Cleanup(func() {
		client.Close()
		for _, slug := range slugs {
			_, _ = testPool.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, steps.DatabaseName(slug)))
			_, _ = testPool.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, steps.RoleName(slug)))
		}
		_, _ = testPool.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %q`, admin))
	})
	return client
}

func TestQMProvisionerDatabaseIsolation(t *testing.T) {
	ctx := context.Background()
	slug := "pilot-" + uuid.NewString()[:8]
	other := "other-" + uuid.NewString()[:8]
	client := qmSQLAdmin(t, slug, other)

	dbName, role := steps.DatabaseName(slug), steps.RoleName(slug)
	otherRole := steps.RoleName(other)

	if err := client.EnsureUser(ctx, role, "pw-one"); err != nil {
		t.Fatalf("create the tenant role: %v", err)
	}
	if err := client.EnsureUser(ctx, otherRole, "pw-two"); err != nil {
		t.Fatalf("create another tenant's role: %v", err)
	}
	if err := client.EnsureDatabase(ctx, dbName, role); err != nil {
		t.Fatalf("create the tenant database: %v", err)
	}

	// The tenant owns its database — which is what gives it rights on the
	// public schema from Postgres 15 on — and no other tenant can connect.
	var owner string
	var allowConn bool
	if err := testPool.QueryRow(ctx,
		`SELECT pg_get_userbyid(datdba), datallowconn FROM pg_database WHERE datname = $1`, dbName,
	).Scan(&owner, &allowConn); err != nil {
		t.Fatalf("read the database: %v", err)
	}
	if owner != role || !allowConn {
		t.Fatalf("database owner=%s allowconn=%v", owner, allowConn)
	}
	assertConnect(t, role, dbName, true)
	assertConnect(t, otherRole, dbName, false)

	// A re-run converges, and leaves the isolation exactly as it was.
	if err := client.EnsureUser(ctx, role, "pw-three"); err != nil {
		t.Fatalf("re-run the role: %v", err)
	}
	if err := client.EnsureDatabase(ctx, dbName, role); err != nil {
		t.Fatalf("re-run the database: %v", err)
	}
	assertConnect(t, role, dbName, true)
	assertConnect(t, otherRole, dbName, false)

	// Repair: a database left open to everyone by an interrupted run is
	// closed again by the next one.
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`GRANT CONNECT ON DATABASE %q TO PUBLIC`, dbName)); err != nil {
		t.Fatalf("open the database by hand: %v", err)
	}
	assertConnect(t, otherRole, dbName, true)
	if err := client.EnsureDatabase(ctx, dbName, role); err != nil {
		t.Fatalf("repair the database: %v", err)
	}
	assertConnect(t, otherRole, dbName, false)

	// Teardown removes both, in that order — Postgres refuses to drop a
	// role that still owns a database.
	if err := client.DropDatabase(ctx, dbName); err != nil {
		t.Fatalf("drop the database: %v", err)
	}
	if err := client.DropUser(ctx, role); err != nil {
		t.Fatalf("drop the role: %v", err)
	}
	// And both are safe to repeat: a teardown is retried.
	if err := client.DropDatabase(ctx, dbName); err != nil {
		t.Fatalf("re-drop the database: %v", err)
	}
	if err := client.DropUser(ctx, role); err != nil {
		t.Fatalf("re-drop the role: %v", err)
	}
	var exists bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("the database survived teardown")
	}
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("the role survived teardown")
	}
}

// The password EnsureUser sets is the one DATABASE_URL carries, so a re-run
// has to leave the role usable with the newest one.
func TestQMProvisionerDatabaseRolePasswordIsReset(t *testing.T) {
	ctx := context.Background()
	slug := "pilot-" + uuid.NewString()[:8]
	client := qmSQLAdmin(t, slug)
	role, dbName := steps.RoleName(slug), steps.DatabaseName(slug)

	if err := client.EnsureUser(ctx, role, "first-password"); err != nil {
		t.Fatal(err)
	}
	if err := client.EnsureDatabase(ctx, dbName, role); err != nil {
		t.Fatal(err)
	}
	assertLogin(t, role, "first-password", dbName, true)

	if err := client.EnsureUser(ctx, role, "second-password"); err != nil {
		t.Fatal(err)
	}
	assertLogin(t, role, "second-password", dbName, true)
	assertLogin(t, role, "first-password", dbName, false)
}

// Identifiers are interpolated into DDL, which cannot take parameters, so
// anything that is not a derived name is refused before it is built.
func TestQMProvisionerDatabaseRefusesOddIdentifiers(t *testing.T) {
	ctx := context.Background()
	client := qmSQLAdmin(t)
	for _, name := range []string{`qm_x"; DROP DATABASE postgres; --`, "QM_X", "qm-x", ""} {
		if err := client.EnsureDatabase(ctx, name, "qm_x"); err == nil {
			t.Errorf("EnsureDatabase accepted %q", name)
		}
		if err := client.EnsureUser(ctx, name, "pw"); err == nil {
			t.Errorf("EnsureUser accepted %q", name)
		}
		if err := client.DropDatabase(ctx, name); err == nil {
			t.Errorf("DropDatabase accepted %q", name)
		}
	}
}

func assertConnect(t *testing.T, role, dbName string, want bool) {
	t.Helper()
	var ok bool
	if err := testPool.QueryRow(context.Background(),
		`SELECT has_database_privilege($1, $2, 'CONNECT')`, role, dbName).Scan(&ok); err != nil {
		t.Fatalf("check connect privilege: %v", err)
	}
	if ok != want {
		t.Errorf("%s can connect to %s = %v, want %v", role, dbName, ok, want)
	}
}

func assertLogin(t *testing.T, role, password, dbName string, want bool) {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", role, password, cfg.Host, cfg.Port, dbName)
	conn, err := pgx.Connect(ctx, dsn)
	if err == nil {
		_ = conn.Close(ctx)
	}
	if (err == nil) != want {
		t.Errorf("%s login = %v, want ok=%v", role, err, want)
	}
}
