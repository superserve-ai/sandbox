package provisioning

import (
	"testing"
	"time"
)

func TestReadinessNeverFollowsHistoricalFinalizationAlone(t *testing.T) {
	now := time.Now()
	o := Operation{State: "grant_pending", FinalizedAt: &now}
	good := Readiness{AuthorityValid: true, PairVerified: true, AssignmentMaterialized: true, InvoiceEnrolled: true, InventoryKnown: true, DebtClear: true, CurrentGrantEligible: true, FundingFresh: true, PositiveFunds: true, BillingEligible: true, ValidUntil: now.Add(time.Minute)}
	if got := project(o, good, now); !got.Ready || got.State != "funding_ready" {
		t.Fatal(got)
	}
	cases := []struct {
		name   string
		change func(*Readiness)
		want   string
	}{
		{"revoked authority", func(r *Readiness) { r.AuthorityValid = false }, "review_required"},
		{"unverified pair", func(r *Readiness) { r.PairVerified = false }, "review_required"},
		{"unmaterialized", func(r *Readiness) { r.AssignmentMaterialized = false }, "review_required"},
		{"unenrolled", func(r *Readiness) { r.InvoiceEnrolled = false }, "review_required"},
		{"unknown inventory", func(r *Readiness) { r.InventoryKnown = false }, "review_required"},
		{"expired observation", func(r *Readiness) { r.ValidUntil = now }, "review_required"},
		{"debt", func(r *Readiness) { r.DebtClear = false }, "review_required"},
		{"grant not confirmed", func(r *Readiness) { r.CurrentGrantEligible = false }, "grant_pending"},
		{"stale funding", func(r *Readiness) { r.FundingFresh = false }, "funding_pending"},
		{"exhausted", func(r *Readiness) { r.PositiveFunds = false; r.Exhausted = true }, "exhausted"},
		{"paid authority needed", func(r *Readiness) { r.PaymentNeeded = true }, "payment_needed"},
		{"existing eligibility denies", func(r *Readiness) { r.BillingEligible = false }, "funding_pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.change(&r)
			got := project(o, r, now)
			if got.Ready || got.State != tc.want {
				t.Fatal(got)
			}
		})
	}
	o.Held = true
	if got := project(o, good, now); got.Ready || got.State != "held" {
		t.Fatal(got)
	}
	o.RevokedAt = &now
	if got := project(o, good, now); got.Ready || got.State != "revoked" {
		t.Fatal(got)
	}
}

func TestAbsentAdaptersAreClosed(t *testing.T) {
	s := &Service{}
	if _, err := s.Enqueue(t.Context(), [16]byte{}, [16]byte{}); err != ErrUnavailable {
		t.Fatal(err)
	}
	if got, err := s.Status(t.Context(), [16]byte{}, [16]byte{}); err != ErrUnavailable || got.Ready || got.State != "unavailable" {
		t.Fatal(got, err)
	}
}
