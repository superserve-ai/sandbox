package proxy

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRouteFromRecordedHost(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"192.0.2.10:50051", "192.0.2.10:5009"},
		{"[2001:db8::10]:9090", "[2001:db8::10]:5009"},
		{"[::ffff:192.0.2.10]:50051", "192.0.2.10:5009"},
	} {
		route, err := routeFromRecordedHost("host-a", tc.addr)
		if err != nil || route.ProxyAddr != tc.want {
			t.Fatalf("%q: route=%+v err=%v", tc.addr, route, err)
		}
	}
	for _, addr := range []string{"", "example.test:9090", "http://192.0.2.1:9090", "192.0.2.1", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:abc", "0.0.0.0:9090", "127.0.0.1:9090", "[::]:9090", "[::1]:9090", "[fe80::1%eth0]:9090", "224.0.0.1:9090", "169.254.1.1:9090"} {
		if _, err := routeFromRecordedHost("host-a", addr); err == nil {
			t.Errorf("accepted %q", addr)
		}
	}
}

func TestDBOwnershipIgnoresAlteredProxyAddress(t *testing.T) {
	databaseURL := os.Getenv("PEER_ROUTING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set PEER_ROUTING_TEST_DATABASE_URL for PostgreSQL contract test")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	// Session-local tables shadow the real tables without modifying shared data.
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TEMP TABLE host (id text PRIMARY KEY, vmd_addr text, proxy_addr text);
 CREATE TEMP TABLE sandbox (id uuid PRIMARY KEY, host_id text, destroyed_at timestamptz);`)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO host VALUES ('host-a','192.0.2.10:50051','192.0.2.10:5009')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sandbox VALUES ($1,'host-a',NULL)`, id); err != nil {
		t.Fatal(err)
	}
	resolver := NewDBOwnershipResolver(pool)
	for _, advertised := range []string{"192.0.2.10:5009", "198.51.100.9:443", "malformed", ""} {
		if _, err := pool.Exec(ctx, `UPDATE host SET proxy_addr=$1`, advertised); err != nil {
			t.Fatal(err)
		}
		route, err := resolver.ResolveSandbox(ctx, id.String())
		if err != nil || route.ProxyAddr != "192.0.2.10:5009" {
			t.Fatalf("advertised=%q route=%+v err=%v", advertised, route, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE host SET vmd_addr='invalid', proxy_addr='192.0.2.10:5009'`); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSandbox(ctx, id.String()); err == nil {
		t.Fatal("invalid VMD address fell back to advertised proxy address")
	}
}
