package proxy

import (
	"context"
	"errors"
	"github.com/rs/zerolog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
		route, err := routeFromRecordedHost("host-a", tc.addr, 42)
		if err != nil || route.ProxyAddr != tc.want || route.Generation != 42 {
			t.Fatalf("%q: route=%+v err=%v", tc.addr, route, err)
		}
	}
	for _, addr := range []string{"", "example.test:9090", "http://192.0.2.1:9090", "192.0.2.1", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:abc", "0.0.0.0:9090", "127.0.0.1:9090", "[::]:9090", "[::1]:9090", "[fe80::1%eth0]:9090", "224.0.0.1:9090", "169.254.1.1:9090"} {
		if _, err := routeFromRecordedHost("host-a", addr, 42); err == nil {
			t.Errorf("accepted %q", addr)
		}
	}
}

func TestDBOwnershipRejectsAlteredProxyAddress(t *testing.T) {
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
	_, err = pool.Exec(ctx, `CREATE TEMP TABLE host (id text PRIMARY KEY, vmd_addr text, proxy_addr text, incarnation_id uuid, peer_generation bigint, last_heartbeat_at timestamptz);
 CREATE TEMP TABLE sandbox (id uuid PRIMARY KEY, host_id text, destroyed_at timestamptz);`)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO host VALUES ('host-a','192.0.2.10:50051','192.0.2.10:5009','11111111-1111-4111-8111-111111111111',42,now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sandbox VALUES ($1,'host-a',NULL)`, id); err != nil {
		t.Fatal(err)
	}
	resolver := NewDBOwnershipResolver(pool, "edge")
	if _, err := resolver.ResolveSandbox(ctx, uuid.NewString()); !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("missing sandbox error=%v", err)
	}
	deleted := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO sandbox VALUES ($1, 'host-a', now())", deleted); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSandbox(ctx, deleted.String()); !errors.Is(err, ErrInstanceNotFound) {
		t.Fatalf("deleted sandbox error=%v", err)
	}
	for _, advertised := range []string{"192.0.2.10:5009", "198.51.100.9:443", "malformed", ""} {
		if _, err := pool.Exec(ctx, `UPDATE host SET proxy_addr=$1`, advertised); err != nil {
			t.Fatal(err)
		}
		route, err := resolver.ResolveSandbox(ctx, id.String())
		if advertised == "192.0.2.10:5009" {
			if err != nil || route.ProxyAddr != "192.0.2.10:5009" || route.Generation != 42 {
				t.Fatalf("advertised=%q route=%+v err=%v", advertised, route, err)
			}
		} else if err == nil || route != (SandboxRoute{}) {
			t.Fatalf("mismatched advertisement produced route=%+v err=%v", route, err)
		}
	}
	for _, generation := range []int64{42, 43} {
		if _, err := pool.Exec(ctx, `UPDATE host SET peer_generation=$1, last_heartbeat_at=now(), proxy_addr='192.0.2.10:5009'`, generation); err != nil {
			t.Fatal(err)
		}
		var received PeerEndpoint
		router := NewRoutingHandler([]string{"sandbox.test"}, "edge", resolver, routePeerFunc(func(_ context.Context, host string, endpoint PeerEndpoint) (PeerStream, error) {
			if host != "host-a" {
				t.Errorf("host=%q", host)
			}
			received = endpoint
			return nil, errors.New("test peer unavailable")
		}), http.NotFoundHandler(), zerolog.Nop())
		request := httptest.NewRequest(http.MethodGet, "http://8080-"+id.String()+".sandbox.test/", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadGateway || received.Address != "192.0.2.10:5009" || received.Generation != uint64(generation) {
			t.Fatalf("status=%d endpoint=%+v", response.Code, received)
		}
	}
	for _, update := range []string{"peer_generation=NULL", "peer_generation=0", "peer_generation=-1", "incarnation_id=NULL", "last_heartbeat_at=NULL"} {
		if _, err := pool.Exec(ctx, `UPDATE host SET peer_generation=42, incarnation_id='11111111-1111-4111-8111-111111111111', last_heartbeat_at=now()`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "UPDATE host SET "+update); err != nil {
			t.Fatal(err)
		}
		if _, err := resolver.ResolveSandbox(ctx, id.String()); err == nil || errors.Is(err, ErrInstanceNotFound) {
			t.Fatalf("%s: expected unavailable owner, got %v", update, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE host SET peer_generation=42, incarnation_id='11111111-1111-4111-8111-111111111111', last_heartbeat_at=now()`); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `UPDATE host SET vmd_addr='invalid', proxy_addr='192.0.2.10:5009'`); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSandbox(ctx, id.String()); err == nil {
		t.Fatal("invalid VMD address fell back to advertised proxy address")
	}
}

func TestDBOwnershipLegacyLocalAndFencedRemote(t *testing.T) {
	for _, localHostID := range []string{"usw2", "use4", "default", "example-region-2-generated"} {
		t.Run(localHostID, func(t *testing.T) { testDBOwnershipLocalAndRemote(t, localHostID) })
	}
}

func testDBOwnershipLocalAndRemote(t *testing.T, localHostID string) {
	databaseURL := os.Getenv("PEER_ROUTING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set PEER_ROUTING_TEST_DATABASE_URL for PostgreSQL contract test")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TEMP TABLE host (id text PRIMARY KEY, vmd_addr text, proxy_addr text, incarnation_id uuid, peer_generation bigint, last_heartbeat_at timestamptz);
CREATE TEMP TABLE sandbox (id uuid PRIMARY KEY, host_id text, destroyed_at timestamptz);`)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewDBOwnershipResolver(pool, " "+localHostID+" ")
	for _, tc := range []struct {
		owner        string
		bound, local bool
	}{
		{localHostID, false, true},
		{localHostID + "-2-generated", true, false},
		{"some-other-host", false, false},
		{localHostID + "-2", false, false},
		{localHostID + "-2-random", false, false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			id := uuid.NewString()
			_, err := pool.Exec(ctx, `INSERT INTO host VALUES ($1,'192.0.2.2:50051','192.0.2.2:5007',NULL,NULL,now())`, tc.owner)
			if err != nil {
				t.Fatal(err)
			}
			if tc.bound {
				_, err = pool.Exec(ctx, `UPDATE host SET vmd_addr='192.0.2.3:50051',proxy_addr='192.0.2.3:5009',incarnation_id='11111111-1111-4111-8111-111111111111',peer_generation=1 WHERE id=$1`, tc.owner)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Exec(ctx, `INSERT INTO sandbox VALUES ($1,$2,NULL)`, id, tc.owner); err != nil {
				t.Fatal(err)
			}
			route, err := resolver.ResolveSandbox(ctx, id)
			switch {
			case tc.local:
				if err != nil || route != (SandboxRoute{HostID: localHostID}) {
					t.Fatalf("local route=%+v err=%v", route, err)
				}
			case tc.bound:
				if err != nil || route != (SandboxRoute{HostID: tc.owner, ProxyAddr: "192.0.2.3:5009", Generation: 1}) {
					t.Fatalf("remote route=%+v err=%v", route, err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), "authoritative peer endpoint unavailable") {
					t.Fatalf("unbound remote route=%+v err=%v", route, err)
				}
			}
			localCalls, peerCalls := 0, 0
			router := NewRoutingHandler([]string{"sandbox.test"}, localHostID, resolver, routePeerFunc(func(_ context.Context, host string, endpoint PeerEndpoint) (PeerStream, error) {
				peerCalls++
				if host != tc.owner || endpoint != (PeerEndpoint{Address: "192.0.2.3:5009", Generation: 1}) {
					t.Errorf("host=%s endpoint=%+v", host, endpoint)
				}
				return nil, errors.New("test peer unavailable")
			}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { localCalls++; w.WriteHeader(http.StatusNoContent) }), zerolog.Nop())
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://8080-"+id+".sandbox.test/", nil))
			wantLocal, wantPeer, wantStatus := 0, 0, http.StatusBadGateway
			if tc.local {
				wantLocal, wantStatus = 1, http.StatusNoContent
			}
			if tc.bound {
				wantPeer = 1
			}
			if localCalls != wantLocal || peerCalls != wantPeer || response.Code != wantStatus {
				t.Fatalf("local=%d peer=%d status=%d", localCalls, peerCalls, response.Code)
			}
		})
	}
}
