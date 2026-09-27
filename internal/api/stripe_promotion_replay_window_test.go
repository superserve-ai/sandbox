package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type replayWindowStripeClient struct {
	StripeBillingClient
	calls int
}

func (s *replayWindowStripeClient) CreateBillingCreditGrant(context.Context, StripeCreateBillingCreditGrantParams) (StripeBillingCreditGrant, error) {
	s.calls++
	return StripeBillingCreditGrant{ID: "credit_example"}, nil
}

func TestStripePromotionReplayWindow(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		attempted  time.Time
		settlement bool
	}{
		{name: "first attempt", attempted: now},
		{name: "fresh retry", attempted: now.Add(-time.Hour)},
		{name: "just within window", attempted: now.Add(-stripePromotionReplayWindow + time.Nanosecond)},
		{name: "window elapsed", attempted: now.Add(-stripePromotionReplayWindow), settlement: true},
		{name: "expired provider cache", attempted: now.Add(-25 * time.Hour), settlement: true},
		{name: "unknown attempt time", settlement: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stripe := &replayWindowStripeClient{}
			h := &Handlers{Stripe: stripe, Now: func() time.Time { return now }}
			pending := &stripePromotionPendingGrant{
				TeamID: uuid.New(), UserID: uuid.New(), CustomerID: "cus_example",
				FirstAttemptAt: tc.attempted, PreviouslyAttempted: tc.name != "first attempt",
			}
			_, err := h.createReservedStripePromotion(t.Context(), pending)
			if tc.settlement {
				var grantErr *stripePromotionGrantError
				if !errors.Is(err, errStripePromotionSettlementRequired) || !errors.As(err, &grantErr) || grantErr.ReleaseReservation {
					t.Fatalf("expired attempt did not preserve its fence: %v", err)
				}
				if grantErr.TeamID != pending.TeamID || grantErr.UserID != pending.UserID || stripe.calls != 0 {
					t.Fatalf("expired attempt changed reservation identity or called Stripe: %+v calls=%d", grantErr, stripe.calls)
				}
			} else if err != nil || stripe.calls != 1 {
				t.Fatalf("valid attempt: err=%v calls=%d", err, stripe.calls)
			}
		})
	}
}

func TestStripePromotionReplayWindowRecheckedAfterPreparationDelay(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	attemptedAt := now.Add(-stripePromotionReplayWindow + time.Second)
	if err := stripePromotionReplayWindowError(attemptedAt, now); err != nil {
		t.Fatalf("preparation unexpectedly failed: %v", err)
	}
	stripe := &replayWindowStripeClient{}
	h := &Handlers{Stripe: stripe, Now: func() time.Time { return now.Add(2 * time.Second) }}
	_, err := h.createReservedStripePromotion(t.Context(), &stripePromotionPendingGrant{
		TeamID: uuid.New(), UserID: uuid.New(), CustomerID: "cus_example",
		FirstAttemptAt: attemptedAt, PreviouslyAttempted: true,
	})
	var grantErr *stripePromotionGrantError
	if !errors.Is(err, errStripePromotionSettlementRequired) || !errors.As(err, &grantErr) || grantErr.ReleaseReservation || stripe.calls != 0 {
		t.Fatalf("delayed attempt escaped replay guard: err=%v calls=%d", err, stripe.calls)
	}
}
