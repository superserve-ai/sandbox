//go:build integration

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

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

// Concurrent checkouts for one team, as when a customer retries while the
// webhook and the recovery worker reconcile it, take the invoice lock in turn.
// Each must wait for its turn rather than fail busy, and waiting must not
// exhaust a two-connection pool.
func TestProUpgradeCheckoutsWaitForTheInvoiceLock(t *testing.T) {
	base, team := newPlanAssignmentFixture(t)
	withPool := func(maxConns int32) *Handlers {
		cfg := base.Pool.Config()
		cfg.MaxConns = maxConns
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return &Handlers{Pool: pool}
	}
	run := func(h *Handlers, wait time.Duration) (busy int, other error) {
		reconcile := func(ctx context.Context) (string, error) {
			conn, release, err := h.proUpgradeInvoiceLock(ctx, team)
			if err != nil {
				return "", err
			}
			defer release()
			_, err = conn.Exec(t.Context(), `SELECT pg_sleep(0.02)`)
			return "active", err
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := waitWhileReconciliationBusy(t.Context(), wait, reconcile)
				mu.Lock()
				defer mu.Unlock()
				if errors.Is(err, errProReconciliationBusy) {
					busy++
				} else if err != nil && other == nil {
					other = err
				}
			}()
		}
		wg.Wait()
		return busy, other
	}
	wide := withPool(16)
	// Without waiting, contention surfaces to the customer as busy.
	if busy, err := run(wide, 0); err != nil || busy == 0 {
		t.Fatalf("contention not reproduced: busy=%d err=%v", busy, err)
	}
	for _, h := range []*Handlers{wide, withPool(2)} {
		if busy, err := run(h, proReconciliationWait); err != nil || busy != 0 {
			t.Fatalf("checkouts failed while waiting their turn: busy=%d err=%v", busy, err)
		}
	}
}

// A checkout waiting its turn stays bound to the upgrade it accepted. If that
// upgrade ends meanwhile and another actor starts a successor, the waiting
// request must not reconcile or return the successor's checkout.
func TestProUpgradeCheckoutWaitKeepsTheAcceptedUpgrade(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	insert := func(state string) proUpgrade {
		t.Helper()
		id, actor := uuid.New(), uuid.New()
		conn, err := h.Pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		defer conn.Exec(context.WithoutCancel(t.Context()), `RESET session_replication_role`)
		if _, err = conn.Exec(t.Context(), `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,state)
 VALUES($1,$2,$3,'cus_example','pro_monthly','{}',clock_timestamp()-interval '1 minute',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day',clock_timestamp(),100,$4)`, id, team, actor, state); err != nil {
			t.Fatal(err)
		}
		u, err := scanProUpgrade(h.Pool.QueryRow(t.Context(), `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE id=$1`, id))
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	accepted := insert("expired")
	// The accepted upgrade was still open when its request read it.
	accepted.State = "prepared"
	successor := insert("prepared")
	// The successor's own checkout has completed.
	session := "cs_successor_" + strings.ReplaceAll(successor.ID.String(), "-", "")
	if _, err := h.Pool.Exec(t.Context(), `UPDATE billing_pro_upgrade SET session_id=$2 WHERE id=$1`, successor.ID, session); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/checkout/sessions/"+session {
			fmt.Fprintf(w, `{"id":%q,"status":"complete"}`, session)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(provider.Close)
	h.Stripe = &stripeHTTPClient{baseURL: provider.URL, httpClient: provider.Client(), apiVersion: "2026-07-29.dahlia"}

	// Another reconciler holds the team for the first attempt.
	holder, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = holder.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String()); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = holder.Rollback(context.Background())
	}()
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/stripe/pro-checkout", nil).WithContext(t.Context())
	h.resumeProUpgradeCheckout(c, accepted)
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("waiting checkout moved to the successor: %d %s (provider calls %d)", response.Code, response.Body.String(), calls.Load())
	}
}

// Waiting is bounded even when a retry cannot get a lock section or a
// connection: the checkout gives up as busy at the deadline instead of waiting
// out the reconciliation timeout.
func TestProUpgradeCheckoutWaitBoundsAcquisition(t *testing.T) {
	base, team := newPlanAssignmentFixture(t)
	cfg := base.Pool.Config()
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool}
	// Another section holds the pool's only lock-section slot throughout.
	leave, err := h.lockSection(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leave)
	started := time.Now()
	_, err = waitWhileReconciliationBusy(t.Context(), 300*time.Millisecond, func(ctx context.Context) (string, error) {
		_, release, err := h.proUpgradeInvoiceLock(ctx, team)
		if err == nil {
			release()
		}
		return "", err
	})
	if !errors.Is(err, errProReconciliationBusy) || time.Since(started) > 2*time.Second {
		t.Fatalf("acquisition outlived the wait: %v after %s", err, time.Since(started))
	}
}
