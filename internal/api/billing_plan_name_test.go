package api

import (
	"testing"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestBillingPlanFromContractNamesPlans(t *testing.T) {
	for _, tc := range []struct {
		offer, display string
		months         int32
		want           string
	}{
		{"pro_monthly", "Pro", 1, "Pro Monthly"},
		{"pro_annual", "Pro", 12, "Pro Annual"},
		{"yc_2026", "", 12, "YC Pro Annual"},
		{"gpu_monthly", "GPU", 1, "GPU Monthly"},
		{"unknown_offer", "", 1, "unknown_offer"},
	} {
		row := db.GetCurrentCommercialPlanRow{OfferKey: tc.offer, PlanDisplayName: tc.display, ChargeIntervalMonths: tc.months}
		if got := billingPlanFromContract(row).Name; got != tc.want {
			t.Errorf("%s: name = %q, want %q", tc.offer, got, tc.want)
		}
	}
}
