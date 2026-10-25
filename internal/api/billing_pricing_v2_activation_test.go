package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

type activationCreditStripe struct {
	StripeBillingClient
	balances map[string]float64
}

func (s activationCreditStripe) GetCustomerCreditBalance(_ context.Context, customer string) (StripeCreditBalance, error) {
	usd, ok := s.balances[customer]
	if !ok {
		return StripeCreditBalance{}, errors.New("stripe unavailable")
	}
	return StripeCreditBalance{AvailableUSD: usd}, nil
}

func TestResolveActivationTeamsSettlesLapsedSubscriptionsByCredit(t *testing.T) {
	h := &Handlers{Stripe: activationCreditStripe{balances: map[string]float64{"cus_credit": 12.5, "cus_spent": 0}}}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	rows := []db.ListPricingV2ActivationBucketsRow{
		{TeamID: ids[0], Bucket: "lapsed", StripeCustomerID: "cus_credit"},
		{TeamID: ids[1], Bucket: "lapsed", StripeCustomerID: "cus_spent"},
		{TeamID: ids[2], Bucket: "lapsed", StripeCustomerID: "cus_unreadable"},
		{TeamID: ids[3], Bucket: "lapsed"},
		{TeamID: ids[4], Bucket: "free"},
		{TeamID: ids[5], Bucket: "skipped", Reason: "commercial_contract"},
	}
	teams, reads := h.resolveActivationTeams(context.Background(), rows)
	r := summarizeActivation("use", time.Unix(0, 0), teams)
	if reads != 3 {
		t.Fatalf("credit reads = %d, want one per lapsed team with a customer", reads)
	}
	if r.ToLegacyPAYG != 1 || r.ToFree != 3 || len(r.Skipped) != 2 || r.Pending != 5 {
		t.Fatalf("report = %+v, want 1 legacy PAYG, 3 Free, 2 skipped", r)
	}
	if len(r.LapsedWithCredit) != 1 || r.LapsedWithCredit[0].TeamID != ids[0] || *r.LapsedWithCredit[0].CreditCents != 1250 {
		t.Fatalf("lapsed with credit = %+v, want the team holding $12.50", r.LapsedWithCredit)
	}
	if len(r.LapsedNoCredit) != 2 || len(r.BlockedToFree) != 0 {
		t.Fatalf("lapsed without credit = %+v, want the spent and customerless teams", r.LapsedNoCredit)
	}
	if r.SkippedReasons["credit_unknown"] != 1 || r.SkippedReasons["commercial_contract"] != 1 {
		t.Fatalf("skipped reasons = %v, want an unreadable credit left for a later pass", r.SkippedReasons)
	}
}
