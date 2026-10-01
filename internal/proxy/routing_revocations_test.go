package proxy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type revocationQueryFunc func(context.Context, string, ...any) (pgx.Rows, error)

func (f revocationQueryFunc) Query(c context.Context, s string, a ...any) (pgx.Rows, error) {
	return f(c, s, a...)
}

func TestRevocationBootstrapExpiryAndFailure(t *testing.T) {
	r := &RoutingRevocations{}
	if r.Allows("a", 1) {
		t.Fatal("bootstrap permitted hint")
	}
	r.expires = time.Now().Add(time.Second)
	r.revoked = map[routeVersion]struct{}{{"a", 1}: {}}
	if r.Allows("a", 1) || !r.Allows("a", 2) {
		t.Fatal("version fence")
	}
	r.expires = time.Now().Add(-time.Second)
	if r.Allows("a", 2) {
		t.Fatal("expired state permitted hint")
	}
	r.expires = time.Now().Add(time.Second)
	err := r.refresh(context.Background(), revocationQueryFunc(func(context.Context, string, ...any) (pgx.Rows, error) { return nil, errors.New("offline") }))
	if err == nil || r.Allows("a", 2) {
		t.Fatal("failed refresh retained permission")
	}
}

func TestRoutingRevocationSnapshotDatabase(t *testing.T) {
	url := os.Getenv("PEER_ROUTING_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set PEER_ROUTING_TEST_DATABASE_URL for PostgreSQL contract test")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TEMP TABLE sandbox_routing_revocation(sandbox_id uuid,routing_version bigint,expires_at timestamptz)")
	r := &RoutingRevocations{}
	id := uuid.NewString()
	refresh := func() {
		t.Helper()
		if err := r.refresh(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	refresh()
	if !r.Allows(id, 1) {
		t.Fatal("empty complete snapshot rejected new sandbox")
	}
	exec("INSERT INTO sandbox_routing_revocation VALUES($1,1,NULL)", id)
	refresh()
	if r.Allows(id, 1) || !r.Allows(id, 2) {
		t.Fatal("old owner version not fenced")
	}
	// Pushes during an in-flight snapshot must not be overwritten by that read.
	other := uuid.NewString()
	err = r.refresh(ctx, revocationQueryFunc(func(c context.Context, q string, a ...any) (pgx.Rows, error) {
		rows, err := pool.Query(c, q, a...)
		r.applyNotification(other + ":7")
		return rows, err
	}))
	if err != nil || r.Allows(other, 7) || !r.Allows(other, 8) || !r.Allows(id, 2) {
		t.Fatal("push merge or unrelated request permission", err)
	}
	expires := r.expires
	r.applyNotification(other + ":8")
	if !r.expires.Equal(expires) || r.Allows(other, 8) || !r.Allows(id, 2) {
		t.Fatal("notification extended freshness or disabled unrelated routes")
	}
	// An unrelated stream failure must not be undone by a read already running.
	err = r.refresh(ctx, revocationQueryFunc(func(c context.Context, q string, a ...any) (pgx.Rows, error) {
		rows, err := pool.Query(c, q, a...)
		r.invalidate()
		return rows, err
	}))
	if err != nil || r.Allows(id, 2) {
		t.Fatal("notification lost to snapshot replacement", err)
	}
	// A slow snapshot cannot get a fresh full second after completion.
	before := time.Now()
	err = r.refresh(ctx, revocationQueryFunc(func(c context.Context, q string, a ...any) (pgx.Rows, error) {
		time.Sleep(40 * time.Millisecond)
		return pool.Query(c, q, a...)
	}))
	if err != nil || r.expires.After(before.Add(revocationTTL+10*time.Millisecond)) {
		t.Fatal("query latency extended freshness", err)
	}
	for _, replacement := range []string{"statement_timestamp() + interval '2 minutes'", "statement_timestamp() - interval '2 minutes'"} {
		err = r.refresh(ctx, revocationQueryFunc(func(c context.Context, q string, a ...any) (pgx.Rows, error) {
			q = strings.Replace(q, "statement_timestamp(), pg_is_in_recovery()", replacement+", pg_is_in_recovery()", 1)
			return pool.Query(c, q, a...)
		}))
		if err == nil || r.Allows(id, 2) {
			t.Fatal("clock skew permitted hint")
		}
	}
	err = r.refresh(ctx, revocationQueryFunc(func(c context.Context, q string, a ...any) (pgx.Rows, error) {
		return pool.Query(c, strings.Replace(q, "pg_is_in_recovery()", "true", 1), a...)
	}))
	if err == nil || r.Allows(id, 2) {
		t.Fatal("replica permitted hint")
	}
	exec("INSERT INTO sandbox_routing_revocation SELECT gen_random_uuid(),1,NULL FROM generate_series(1,65537)")
	if err := r.refresh(ctx, pool); err == nil || r.Allows(id, 2) {
		t.Fatal("partial snapshot permitted hint")
	}
}
