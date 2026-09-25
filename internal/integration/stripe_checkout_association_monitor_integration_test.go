//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_StripeAssociationCandidateGraceAndClaims(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	eventID := "evt_monitor_" + uuid.NewString()
	payload, err := json.Marshal(map[string]any{
		"id": eventID, "type": "customer.subscription.deleted", "created": now.Unix(),
		"data": map[string]any{"object": map[string]any{"id": "sub_example", "customer": "cus_example", "status": "canceled"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO stripe_webhook_event(event_id, event_type, payload, received_at, last_error)
VALUES ($1, 'customer.subscription.deleted', $2, $3, $4)`, eventID, payload, now.Add(-5*time.Minute), db.StripeCheckoutAssociationPendingError); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM stripe_webhook_event WHERE event_id = $1`, eventID)
	})

	list := func(at time.Time) []db.StripeCheckoutAssociationCandidate {
		t.Helper()
		candidates, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, at, 5*time.Minute, db.StripeCheckoutAssociationCursor{}, 100)
		if err != nil {
			t.Fatal(err)
		}
		var matches []db.StripeCheckoutAssociationCandidate
		for _, c := range candidates {
			if c.EventID == eventID {
				matches = append(matches, c)
			}
		}
		return matches
	}
	if got := list(now.Add(-time.Microsecond)); len(got) != 0 {
		t.Fatalf("candidate before grace = %v", got)
	}
	if got := list(now); len(got) != 1 {
		t.Fatalf("candidate at grace = %v", got)
	}
	if after, err := db.ListStripeCheckoutAssociationCandidates(ctx, testPool, now, 5*time.Minute,
		db.StripeCheckoutAssociationCursor{ReceivedAt: now.Add(-5 * time.Minute), EventID: eventID}, 100); err != nil {
		t.Fatal(err)
	} else {
		for _, candidate := range after {
			if candidate.EventID == eventID {
				t.Fatal("keyset scan revisited the cursor event")
			}
		}
	}

	claim := func(at time.Time) bool {
		t.Helper()
		tx, err := testPool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		claimed, err := db.ClaimStripeCheckoutAssociationAlert(ctx, tx, eventID, at, at.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return claimed
	}
	if !claim(now) || claim(now) {
		t.Fatal("claim must exclude a second worker")
	}
	if len(list(now)) != 0 {
		t.Fatal("leased event remained due")
	}
	if !claim(now.Add(2 * time.Minute)) {
		t.Fatal("abandoned claim was not reclaimed")
	}
	lease := now.Add(4 * time.Minute)
	if err := db.FinishStripeCheckoutAssociationAlert(ctx, testPool, eventID, lease, now.Add(32*time.Minute), true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if claim(now.Add(3 * time.Minute)) {
		t.Fatal("cooldown did not survive a new worker")
	}
	if !claim(now.Add(32 * time.Minute)) {
		t.Fatal("event did not become due after cooldown")
	}
	// Processing wins even if an old last_error remains.
	if _, err := testPool.Exec(ctx, `UPDATE stripe_webhook_event SET processed_at = $2 WHERE event_id = $1`, eventID, now); err != nil {
		t.Fatal(err)
	}
	if got := list(now.Add(40 * time.Minute)); len(got) != 0 {
		t.Fatalf("processed event remained alertable: %v", got)
	}
}
