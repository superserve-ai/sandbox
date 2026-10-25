//go:build integration

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedPrepaidLastSlot(t *testing.T, f *prepaidFixture) {
	t.Helper()
	f.exec(`INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key,next_attempt_at)
 SELECT $1,$2,'checkout',500,gen_random_uuid(),'','','9999-01-01' FROM generate_series(1,$3)`, f.team, f.customer, prepaidLiveGrantLimit-1)
}

func TestPrepaidConcurrentCheckoutsReserveOnlyLastSlot(t *testing.T) {
	f := newPrepaidFixture(t)
	seedPrepaidLastSlot(t, f)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if _, err = tx.Exec(t.Context(), `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, f.team); err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	type outcome struct {
		session prepaidCheckoutSession
		err     error
	}
	done := make(chan outcome, 2)
	for range 2 {
		go func() {
			s, err := f.h.startPrepaidPaymentCheckout(t.Context(), f.client, f.team, actor, f.customer, 500, "https://example.com/success", "https://example.com/cancel")
			done <- outcome{s, err}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query='SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("checkout requests did not both wait for team lock", waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var accepted prepaidCheckoutSession
	var rejected int
	for range 2 {
		r := <-done
		if errors.Is(r.err, errPrepaidTooManyUnspent) {
			rejected++
			continue
		}
		if r.err != nil {
			t.Fatal(r.err)
		}
		accepted = r.session
	}
	if rejected != 1 || accepted.ID == "" || len(f.sessions) != 1 {
		t.Fatal("last slot created multiple provider sessions", rejected, accepted, len(f.sessions))
	}
	if n, err := prepaidUnspentPurchases(t.Context(), f.h.Pool, f.team); err != nil || n != prepaidLiveGrantLimit {
		t.Fatal("purchase cap exceeded", n, err)
	}
	id, err := uuid.Parse(accepted.Metadata["prepaid_purchase_id"])
	if err != nil {
		t.Fatal(err)
	}
	setPricingVersion(t, f.h, "legacy")
	if err = f.h.recordCheckoutPurchase(t.Context(), id, f.team, f.customer, actor, 500, accepted.ID); err != nil {
		t.Fatal("exact replay refused at capacity after rollback", err)
	}
	if len(f.sessions) != 1 {
		t.Fatal("replay created another session")
	}
}

func TestPrepaidAutoRechargeCannotRaceCheckoutForLastSlot(t *testing.T) {
	f := newPrepaidFixture(t)
	seedPrepaidLastSlot(t, f)
	f.enableAutoRecharge(2000, 500)
	f.observe(0, true)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	if err = f.h.preparePrepaidPurchase(t.Context(), tx, uuid.New(), f.team, f.customer, uuid.New(), 500); err != nil {
		t.Fatal(err)
	}
	if err = f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = f.h.recordAutoRecharges(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n, err := prepaidUnspentPurchases(t.Context(), f.h.Pool, f.team); err != nil || n != prepaidLiveGrantLimit {
		t.Fatal("checkout/recharge race exceeded cap", n, err)
	}
	var automatic int
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1 AND source='auto_recharge'`, f.team).Scan(&automatic); err != nil || automatic != 0 {
		t.Fatal("recharge consumed checkout reservation", automatic, err)
	}
}
