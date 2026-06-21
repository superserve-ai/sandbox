package pgstore

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/actor"
	"github.com/superserve-ai/sandbox/internal/db"
)

// These tests run against a real Postgres when ACTOR_TEST_DATABASE_URL is set
// (the schema from supabase/migrations applied). They prove the single-writer
// lease CAS holds under actual Postgres MVCC — not just the in-memory reference.
//
//	createdb actortest && psql actortest -f supabase/migrations/20260621000003_actor.sql
//	ACTOR_TEST_DATABASE_URL=postgres://... go test ./internal/actor/pgstore/

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func setup(t *testing.T) (*actor.Registry, *clock, string) {
	t.Helper()
	url := os.Getenv("ACTOR_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ACTOR_TEST_DATABASE_URL not set; skipping real-Postgres lease test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// A team row to satisfy the actor.team_id FK; unique per test run.
	var teamID string
	if err := pool.QueryRow(ctx, "INSERT INTO team DEFAULT VALUES RETURNING id").Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	reg := actor.NewRegistry(New(db.New(pool)), clk.now)
	return reg, clk, teamID
}

func uniqueName(t *testing.T) string { return "test/" + t.Name() }

func TestPgGetActorIdempotent(t *testing.T) {
	reg, _, team := setup(t)
	ctx := context.Background()
	a1, created1, err := reg.GetActor(ctx, team, uniqueName(t), actor.Actor{})
	if err != nil || !created1 {
		t.Fatalf("first: created=%v err=%v", created1, err)
	}
	a2, created2, err := reg.GetActor(ctx, team, uniqueName(t), actor.Actor{})
	if err != nil || created2 {
		t.Fatalf("second should resolve existing: created=%v err=%v", created2, err)
	}
	if a1.ID != a2.ID {
		t.Fatalf("idempotent getActor returned different ids: %s vs %s", a1.ID, a2.ID)
	}
}

func TestPgLeaseExpiryAndFencing(t *testing.T) {
	reg, clk, team := setup(t)
	ctx := context.Background()
	a, _, _ := reg.GetActor(ctx, team, uniqueName(t), actor.Actor{})

	l1, err := reg.Acquire(ctx, a.ID, "host-A", 10*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Foreign holder blocked while valid.
	if _, err := reg.Acquire(ctx, a.ID, "host-B", 10*time.Second); !errors.Is(err, actor.ErrLeaseHeld) {
		t.Fatalf("foreign acquire should be ErrLeaseHeld, got %v", err)
	}
	if err := l1.CheckFence(ctx); err != nil {
		t.Fatalf("holder fence should pass: %v", err)
	}

	// Expire it (deterministic via the injected clock).
	clk.add(11 * time.Second)
	if err := l1.CheckFence(ctx); !errors.Is(err, actor.ErrFenced) {
		t.Fatalf("expired holder must be fenced, got %v", err)
	}

	// Takeover gets a strictly higher fence token.
	l2, err := reg.Acquire(ctx, a.ID, "host-B", 10*time.Second)
	if err != nil {
		t.Fatalf("takeover acquire: %v", err)
	}
	if l2.Token() <= l1.Token() {
		t.Fatalf("fence token must increase on takeover: %d <= %d", l2.Token(), l1.Token())
	}
	if err := l1.CheckFence(ctx); !errors.Is(err, actor.ErrFenced) {
		t.Fatalf("old holder stays fenced after takeover, got %v", err)
	}
}

// TestPgConcurrentAcquire is the real-MVCC single-writer proof: many holders
// race TryAcquire on a free Actor; exactly one wins because the atomic UPDATE
// serializes on the row lock.
func TestPgConcurrentAcquire(t *testing.T) {
	reg, _, team := setup(t)
	ctx := context.Background()
	a, _, _ := reg.GetActor(ctx, team, uniqueName(t), actor.Actor{})

	const n = 32
	var winners int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			if _, err := reg.Acquire(ctx, a.ID, "host-"+itoa(id), time.Hour); err == nil {
				atomic.AddInt64(&winners, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if winners != 1 {
		t.Fatalf("exactly one acquirer must win under real Postgres, got %d", winners)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
