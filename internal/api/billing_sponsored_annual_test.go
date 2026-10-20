package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSponsoredAnnualTimingAndFees(t *testing.T) {
	anchor := time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC)
	b := invoiceBase{Price: "price_annual", Item: "si_annual", Amount: 1200000, Months: 12, Anchor: anchor, WaiverEnd: annualBoundary(anchor, 12).Unix()}
	for _, months := range []int{0, 1, 3, 11, 12, 13, 24} {
		got, start, end, err := b.expectedFee(annualBoundary(anchor, months))
		want := int64(0)
		if months == 12 || months == 24 {
			want = 1200000
		}
		if err != nil || got != want {
			t.Fatalf("month %d: fee %d err %v", months, got, err)
		}
		if want > 0 && (start != annualBoundary(anchor, months).Unix() || end != annualBoundary(anchor, months+12).Unix()) {
			t.Fatal("annual fee drifted from leap-day anchor")
		}
	}
	for _, raw := range []string{`[{"applies_to":null,"bill_until":{"type":"timestamp","timestamp":1}}]`, `{}`, `[null]`} {
		if validateSponsoredAnnualTiming(invoiceSubscription{BillingSchedules: json.RawMessage(raw)}) == nil {
			t.Fatal("accepted unknown timing override", raw)
		}
	}
	o := sponsoredAnnualAuthority{Start: anchor, End: annualBoundary(anchor, 12)}
	for _, tc := range []struct {
		start, end int64
		valid      bool
	}{
		{o.End.Unix(), annualBoundary(anchor, 24).Unix(), true},
		{anchor.Unix(), o.End.Unix(), false},
		{o.End.Unix() + 86400, annualBoundary(anchor, 24).Unix() + 86400, false},
		{o.End.Unix(), annualBoundary(anchor, 24).Unix() - 1, false},
	} {
		if annualReceiptPeriod(o, proPaymentEvidence{Start: tc.start, End: tc.end}) != tc.valid {
			t.Fatal("incorrect paid period authority", tc)
		}
	}
}
