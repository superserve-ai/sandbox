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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
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
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		var present bool
		if err := db.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			if _, err := db.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
		}
	}
	migration, err := os.ReadFile("../../supabase/migrations/20261001202849_sandbox_routing_revocations.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	testRoutingRevocationTransitions(t, db)
	testRoutingRevocationTransactionVisibility(t, db)
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
	testRoutingRevocationListener(t, db, pool.Config(), cleanupURL)
	route, err := proxy.NewDBOwnershipResolver(pool, "edge").ResolveSandbox(ctx, "22222222-2222-4222-8222-222222222222")
	if err != nil || route.HostID != "owner" || route.Generation != 7 {
		t.Fatalf("restricted discovery: %+v %v", route, err)
	}
	var revocations int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation").Scan(&revocations); err != nil {
		t.Fatalf("restricted revocation reader: %v", err)
	}
	hosts, err := (proxy.DBHostDirectorySource{Pool: pool}).ListPeerHosts(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].HostID != "owner" {
		t.Fatalf("restricted host directory: %+v %v", hosts, err)
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
	for _, query := range []string{"SELECT secret_token FROM public.sandbox", "DELETE FROM public.sandbox_routing_revocation", "SELECT routing_private.prune_revocations(clock_timestamp())", "UPDATE public.sandbox SET host_id='other'", "UPDATE public.host SET proxy_addr='192.0.2.2:5009'", "DELETE FROM public.host", "INSERT INTO public.host(id) VALUES('other')"} {
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

func testRoutingRevocationTransitions(t *testing.T, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	id := uuid.NewString()
	exec("INSERT INTO sandbox(id,host_id) VALUES($1,'a')", id)
	assertVersion := func(want int64) {
		t.Helper()
		var got int64
		if err := db.QueryRow(ctx, "SELECT routing_version FROM sandbox WHERE id=$1", id).Scan(&got); err != nil || got != want {
			t.Fatalf("version=%d want=%d err=%v", got, want, err)
		}
	}
	assertVersion(1)
	exec("UPDATE sandbox SET host_id='b' WHERE id=$1", id)
	assertVersion(2)
	exec("UPDATE sandbox SET host_id='a' WHERE id=$1", id)
	assertVersion(3)
	// Changes from an older writer require no knowledge of the version field.
	exec("UPDATE sandbox SET destroyed_at=now() WHERE id=$1", id)
	exec("DELETE FROM sandbox WHERE id=$1", id)
	var n int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1 AND expires_at IS NULL", id).Scan(&n); err != nil || n != 3 {
		t.Fatalf("committed unaged revocations=%d: %v", n, err)
	}
	if _, err := db.Exec(ctx, "SELECT routing_private.prune_revocations($1)", time.Now().Add(-3*time.Hour)); err == nil {
		t.Fatal("retention accepted clock disagreement")
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1 AND expires_at IS NULL", id).Scan(&n); err != nil || n != 3 {
		t.Fatal("clock fault changed revocations", n, err)
	}
	exec("SELECT routing_private.prune_revocations(clock_timestamp())")
	if err := db.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1 AND expires_at > now()+interval '119 minutes'", id).Scan(&n); err != nil || n != 3 {
		t.Fatalf("post-commit retention=%d: %v", n, err)
	}
	rollbackID := uuid.NewString()
	exec("INSERT INTO sandbox(id,host_id) VALUES($1,'a')", rollbackID)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM sandbox WHERE id=$1", rollbackID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1", rollbackID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rollback left revocation: %d %v", n, err)
	}
}

func testRoutingRevocationTransactionVisibility(t *testing.T, writer *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	reader, err := pgx.ConnectConfig(ctx, writer.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close(ctx)
	id := uuid.NewString()
	if _, err := writer.Exec(ctx, "INSERT INTO sandbox(id,host_id) VALUES($1,'a')", id); err != nil {
		t.Fatal(err)
	}
	tx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "UPDATE sandbox SET host_id='b',destroyed_at=now() WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	var host string
	var version int64
	var revoked int
	if err := reader.QueryRow(ctx, "SELECT host_id,routing_version FROM sandbox WHERE id=$1", id).Scan(&host, &version); err != nil || host != "a" || version != 1 {
		t.Fatal("uncommitted owner leaked", host, version, err)
	}
	if _, err := reader.Exec(ctx, "SELECT routing_private.prune_revocations(clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1", id).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatal("uncommitted revocation visible", revoked, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT s.host_id,s.routing_version,count(r.sandbox_id) FROM sandbox s LEFT JOIN sandbox_routing_revocation r ON r.sandbox_id=s.id AND r.expires_at IS NULL WHERE s.id=$1 GROUP BY s.host_id,s.routing_version", id).Scan(&host, &version, &revoked); err != nil || host != "b" || version != 2 || revoked != 1 {
		t.Fatal("commit did not atomically expose owner and unaged revocation", host, version, revoked, err)
	}
	if _, err := reader.Exec(ctx, "SELECT routing_private.prune_revocations(clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	if err := reader.QueryRow(ctx, "SELECT count(*) FROM sandbox_routing_revocation WHERE sandbox_id=$1 AND expires_at>clock_timestamp()+interval '119 minutes'", id).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatal("retention consumed uncommitted time", revoked, err)
	}
}

func testRoutingRevocationListener(t *testing.T, writer *pgx.Conn, config *pgxpool.Config, adminURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config.MaxConns = 1
	app := "routing_listener_test_" + uuid.NewString()
	config.ConnConfig.RuntimeParams["application_name"] = app
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); pool.Close() }()
	state := &proxy.RoutingRevocations{}
	state.Start(ctx, pool, &proxy.HostDirectory{}, zerolog.Nop())
	wait := func(predicate func() bool) {
		t.Helper()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal("listener did not converge")
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	wait(state.Ready)
	// This notification has no table row: only the actual LISTEN path can deny it.
	id := uuid.NewString()
	if _, err := writer.Exec(ctx, "SELECT pg_notify('sandbox_routing_revoked',$1)", id+":1"); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return state.Ready() && !state.Allows(id, 1) })
	if !state.Allows(id, 2) {
		t.Fatal("push disabled unrelated version")
	}
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	var pid int32
	if err := admin.QueryRow(ctx, "SELECT pid FROM pg_stat_activity WHERE application_name=$1", app).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return !state.Ready() })
	wait(state.Ready)
	id = uuid.NewString()
	if _, err := writer.Exec(ctx, "INSERT INTO sandbox(id,host_id) VALUES($1,'a')", id); err != nil {
		t.Fatal(err)
	}
	if !state.Allows(id, 1) {
		t.Fatal("fresh sandbox unexpectedly fenced")
	}
	if _, err := writer.Exec(ctx, "UPDATE sandbox SET host_id='b' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return state.Ready() && !state.Allows(id, 1) })
	if !state.Allows(id, 2) {
		t.Fatal("new ownership version rejected")
	}
	// Prove re-LISTEN, not just periodic snapshots, after reconnect.
	notificationOnly := uuid.NewString()
	if _, err := writer.Exec(ctx, "SELECT pg_notify('sandbox_routing_revoked',$1)", notificationOnly+":1"); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return state.Ready() && !state.Allows(notificationOnly, 1) })
}
