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
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE IF EXISTS sandbox_proxy_router"); err != nil {
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
	sql, err := os.ReadFile("../../supabase/migrations/20260915155400_sandbox_proxy_router.sql")
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
	// Reapplying the migration must preserve the existing login credential.
	if _, err := db.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
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
	route, err := proxy.NewDBOwnershipResolver(pool).ResolveSandbox(ctx, "22222222-2222-4222-8222-222222222222")
	if err != nil || route.HostID != "owner" || route.Generation != 7 {
		t.Fatalf("restricted discovery: %+v %v", route, err)
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
}
