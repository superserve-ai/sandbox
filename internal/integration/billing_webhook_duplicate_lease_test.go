//go:build integration

package integration

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// markProcessedAfterLeaseTracer simulates a concurrent delivery completing the
// event after the outer duplicate check but before promotion pre-reservation.
type markProcessedAfterLeaseTracer struct {
	mu      sync.Mutex
	eventID string
	marked  bool
}

func (tr *markProcessedAfterLeaseTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "-- name: ClaimStripeWebhookProcessingLease ") {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		if !tr.marked && tr.eventID != "" {
			tr.marked = true
			if _, err := testPool.Exec(context.Background(), `
				UPDATE stripe_webhook_event
				SET processed_at = now()
				WHERE event_id = $1`, tr.eventID); err != nil {
				panic(err)
			}
		}
	}
	return ctx
}

func (tr *markProcessedAfterLeaseTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestIntegration_ProcessedWebhookAfterLeaseClaimDoesNotReservePromotion(t *testing.T) {
	ctx := context.Background()
	teamID, _, userID := seedTeamAndKeyWithRole(t, "team_owner")
	eventID := "evt_processed_after_lease_" + uuid.NewString()
	customerID := "cus_" + teamID.String()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_billing_account (team_id, stripe_customer_id)
		VALUES ($1, $2)`, teamID, customerID); err != nil {
		t.Fatal(err)
	}

	tracer := &markProcessedAfterLeaseTracer{eventID: eventID}
	poolConfig := testPool.Config().Copy()
	poolConfig.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	router := newBillingRouterWithPool(t, &fakeStripeClient{}, pool)

	if w := sendStripeActivationWebhook(t, router, eventID, teamID, userID, time.Now().UTC()); w.Code != 200 {
		t.Fatalf("webhook: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var reserved bool
	if err := testPool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1
		FROM user_promotion_entitlement
		WHERE user_id = $1 AND stripe_redemption_reserved_team_id IS NOT NULL)`, userID).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved {
		t.Fatal("processed duplicate webhook created promotion reservation")
	}
}
