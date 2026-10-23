package api

import (
	"testing"
	"time"
)

func TestProviderPairReceiptCalendarSelection(t *testing.T) {
	date := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	b := ContractProviderBinding{Anchor: date("2024-02-29"), FeeAnchor: date("2025-02-28")}
	b.Terms.FeeMonths = 1
	for _, tc := range []struct {
		start, end, feeStart, feeEnd string
		want                         bool
	}{
		{"2025-02-28", "2025-03-29", "2025-02-28", "2025-03-28", true},
		{"2025-02-28", "2025-03-29", "2025-03-28", "2025-04-28", false},
		{"2025-03-29", "2025-04-29", "2025-03-28", "2025-04-28", true},
		{"2025-03-29", "2025-04-29", "2025-02-28", "2025-03-28", false},
	} {
		if got := pairPaymentCoversAllowance(b, date(tc.start), date(tc.end), date(tc.feeStart).Unix(), date(tc.feeEnd).Unix()); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
	b.Terms.FeeMonths = 12
	if pairPaymentCoversAllowance(b, date("2028-01-29"), date("2028-02-29"), date("2027-02-28").Unix(), date("2028-02-28").Unix()) {
		t.Fatal("annual receipt fabricated coverage past its actual end")
	}
}
