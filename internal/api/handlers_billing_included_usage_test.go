package api

import (
	"testing"
	"time"
)

func TestIncludedUsageMeasuresTheBillingPeriod(t *testing.T) {
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	u := &billingSummaryIncludedUsage{AmountCents: 25000, PeriodStart: start, PeriodEnd: end, Status: "issued"}
	u.measure(start, end, 123.455)
	if *u.UsedCents != 12346 || *u.RemainingCents != 12654 || *u.OverageCents != 0 {
		t.Fatalf("within allowance: %d %d %d", *u.UsedCents, *u.RemainingCents, *u.OverageCents)
	}
	u.measure(start, end, 300)
	if *u.UsedCents != 30000 || *u.RemainingCents != 0 || *u.OverageCents != 5000 {
		t.Fatalf("beyond allowance: %d %d %d", *u.UsedCents, *u.RemainingCents, *u.OverageCents)
	}
	other := &billingSummaryIncludedUsage{AmountCents: 25000, PeriodStart: start, PeriodEnd: end, Status: "issued"}
	other.measure(end, end.AddDate(0, 1, 0), 10)
	if other.UsedCents != nil {
		t.Fatal("measured usage from a different period")
	}
	pending := &billingSummaryIncludedUsage{AmountCents: 25000, PeriodStart: start, PeriodEnd: end, Status: "pending"}
	pending.measure(start, end, 10)
	if pending.RemainingCents != nil {
		t.Fatal("reported remaining allowance before it was issued")
	}
	var none *billingSummaryIncludedUsage
	none.measure(start, end, 10)
}
