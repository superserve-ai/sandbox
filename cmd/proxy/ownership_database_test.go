package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/proxy"
)

func TestRoutingDatabaseCredentialContract(t *testing.T) {
	url := os.Getenv("PEER_ROUTING_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set PEER_ROUTING_TEST_DATABASE_URL for PostgreSQL role contract")
	}
	t.Run("administrator", func(t *testing.T) { testRoutingDatabaseCredentialContract(t, url, url) })
	t.Run("role_administrator", func(t *testing.T) {
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		name, password := "example_migrator_"+uuid.NewString()[:8], uuid.NewString()
		if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN NOINHERIT CREATEROLE CREATEDB PASSWORD '%s'", pgx.Identifier{name}.Sanitize(), password)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.Exec(cleanupCtx, "DROP ROLE "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error(err)
			}
		}()
		cfg := admin.Config()
		adminURL := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable", cfg.Host, cfg.Port, cfg.Database, name, password)
		testRoutingDatabaseCredentialContract(t, adminURL, url)
	})
}

func testRoutingDatabaseCredentialContract(t *testing.T, url, cleanupURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname='sandbox_proxy_router')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Skip("routing role already exists; use an isolated test database cluster")
	}
	name := "proxy_role_test_" + uuid.New().String()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// FORCE still requires permission to terminate other roles' backends.
		cleanupAdmin, err := pgx.Connect(cleanupCtx, cleanupURL)
		if err != nil {
			t.Error(err)
			return
		}
		defer cleanupAdmin.Close(cleanupCtx)
		if _, err := cleanupAdmin.Exec(cleanupCtx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		roleCtx, cancelRole := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelRole()
		if _, err := cleanupAdmin.Exec(roleCtx, "DROP ROLE IF EXISTS sandbox_proxy_router"); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	_, err = db.Exec(ctx, `CREATE TABLE public.sandbox(id uuid PRIMARY KEY,host_id text,destroyed_at timestamptz,secret_token text);
 CREATE TABLE public.host(id text PRIMARY KEY,vmd_addr text,proxy_addr text,incarnation_id uuid,peer_generation bigint,last_heartbeat_at timestamptz);
 ALTER TABLE public.sandbox ENABLE ROW LEVEL SECURITY;
 ALTER TABLE public.host ENABLE ROW LEVEL SECURITY;
 INSERT INTO public.host VALUES('owner','192.0.2.1:50051','192.0.2.1:5009','11111111-1111-4111-8111-111111111111',7,now());
 INSERT INTO public.sandbox VALUES('22222222-2222-4222-8222-222222222222','owner',NULL,'example-token');`)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile("../../supabase/migrations/20260923000010_sandbox_proxy_router.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	password := uuid.NewString()
	if _, err := db.Exec(ctx, fmt.Sprintf("ALTER ROLE sandbox_proxy_router PASSWORD '%s'", password)); err != nil {
		t.Fatal(err)
	}
	// Exercise attribute repair as both a superuser and an ordinary role admin.
	if _, err := db.Exec(ctx, `ALTER ROLE sandbox_proxy_router NOLOGIN INHERIT
        CREATEDB CREATEROLE CONNECTION LIMIT 64`); err != nil {
		t.Fatal(err)
	}
	// Reapplying must repair login/security flags without changing credentials
	// or an operator-adjusted connection limit.
	if _, err := db.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	var repaired bool
	if err := db.QueryRow(ctx, `SELECT rolcanlogin AND NOT rolinherit AND NOT rolsuper
        AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
        AND rolconnlimit = 64 FROM pg_roles WHERE rolname = 'sandbox_proxy_router'`).Scan(&repaired); err != nil || !repaired {
		t.Fatalf("role repair: %v, %v", repaired, err)
	}
	cfg.User = "sandbox_proxy_router"
	// Ensure the test server actually checks passwords before testing preservation.
	cfg.Password = uuid.NewString()
	wrong, err := pgx.ConnectConfig(ctx, cfg)
	if wrong != nil {
		wrong.Close(ctx)
	}
	var authErr *pgconn.PgError
	if !errors.As(err, &authErr) || authErr.Code != "28P01" {
		t.Fatalf("test database must require password authentication: %v", err)
	}
	cfg.Password = password
	// ConnString retains the original URL; build the test DSN from explicit fields.
	routingURL := fmt.Sprintf("host=%s port=%d dbname=%s user=sandbox_proxy_router password=%s sslmode=disable", cfg.Host, cfg.Port, name, password)
	pool, err := newOwnershipPool(ctx, true, routingURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	route, err := proxy.NewDBOwnershipResolver(pool, "edge").ResolveSandbox(ctx, "22222222-2222-4222-8222-222222222222")
	if err != nil || route.HostID != "owner" || route.Generation != 7 {
		t.Fatalf("restricted discovery: %+v %v", route, err)
	}
	if _, err := db.Exec(ctx, "UPDATE public.host SET incarnation_id=NULL, peer_generation=NULL, proxy_addr='192.0.2.1:5007'"); err != nil {
		t.Fatal(err)
	}
	route, err = proxy.NewDBOwnershipResolver(pool, "owner").ResolveSandbox(ctx, "22222222-2222-4222-8222-222222222222")
	if err != nil || route != (proxy.SandboxRoute{HostID: "owner"}) {
		t.Fatalf("restricted local discovery: %+v %v", route, err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// ACLs, rather than the user-resettable read-only default, must deny writes.
	if _, err := conn.Exec(ctx, "SET default_transaction_read_only=off"); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"SELECT secret_token FROM public.sandbox", "UPDATE public.sandbox SET host_id='other'", "UPDATE public.host SET proxy_addr='192.0.2.2:5009'", "DELETE FROM public.host", "INSERT INTO public.host(id) VALUES('other')"} {
		_, err := conn.Exec(ctx, query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("expected permission denial for %s: %v", query, err)
		}
	}
	conn.Release()
	if _, err := db.Exec(ctx, "GRANT UPDATE ON public.sandbox TO sandbox_proxy_router"); err != nil {
		t.Fatal(err)
	}
	invalid, err := newOwnershipPool(ctx, true, routingURL)
	if invalid != nil {
		invalid.Close()
	}
	if err == nil {
		t.Fatal("startup accepted a routing credential with write access")
	}
	invalid, err = newOwnershipPool(ctx, true, url)
	if invalid != nil {
		invalid.Close()
	}
	if err == nil {
		t.Fatal("startup accepted administrator credential")
	}
	// Keep a router backend alive through deferred fixture teardown to model a
	// server connection that has not exited yet after the client pool closes.
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	lingering, err := pgx.Connect(connectCtx, routingURL)
	cancelConnect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		lingering.Close(closeCtx)
	})
}
