//go:build integration

package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Through a transaction pooler a session lock can stay on an idle pooled
// backend after the attempt; the lock must belong to an open transaction.
func TestProUpgradeInvoiceLockIsTransactionScoped(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	holders := func() (count int, inTransaction bool) {
		t.Helper()
		if err := h.Pool.QueryRow(t.Context(), `SELECT count(*), coalesce(bool_and(a.xact_start IS NOT NULL), false)
 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid,
  (SELECT hashtextextended($1, 0) AS key) k
 WHERE l.locktype = 'advisory' AND l.granted
  AND l.classid = ((k.key >> 32) & 4294967295)::bigint::oid
  AND l.objid = (k.key & 4294967295)::bigint::oid`, "invoice:"+team.String()).Scan(&count, &inTransaction); err != nil {
			t.Fatal(err)
		}
		return count, inTransaction
	}

	_, release, err := h.proUpgradeInvoiceLock(t.Context(), team)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			release()
		}
	})
	if count, inTransaction := holders(); count != 1 || !inTransaction {
		t.Fatalf("lock holders=%d in transaction=%t", count, inTransaction)
	}
	if _, _, err = h.proUpgradeInvoiceLock(t.Context(), team); !errors.Is(err, errProReconciliationBusy) {
		t.Fatalf("second attempt: %v", err)
	}
	release()
	released = true
	if count, _ := holders(); count != 0 {
		t.Fatalf("lock outlived release: %d holders", count)
	}
	_, release, err = h.proUpgradeInvoiceLock(t.Context(), team)
	if err != nil {
		t.Fatalf("lock not reusable after release: %v", err)
	}
	release()
}

// Each holder needs a lock transaction and a write connection. Concurrent
// holders for different teams must not fill the pool with lock transactions
// and then wait on each other for the second connection.
func TestProUpgradeInvoiceLocksDoNotExhaustThePool(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	cfg := h.Pool.Config()
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h = &Handlers{Pool: pool}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, release, err := h.proUpgradeInvoiceLock(ctx, uuid.New())
			if err != nil {
				errs <- err
				return
			}
			defer release()
			_, err = conn.Exec(ctx, `SELECT pg_sleep(0.01)`)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent lock holder: %v", err)
		}
	}
}
