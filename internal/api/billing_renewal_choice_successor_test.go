package api

import (
	"testing"
	"time"
)

func TestRenewalChoiceReceiptFollowsOriginalGrantCalendar(t *testing.T) {
	for _, tc := range []struct {
		name, anchor, now, grant, fee string
		months                        int32
	}{
		{"monthly_before_credit_rollover", "2024-02-29", "2025-03-28", "2025-02-28", "2025-02-28", 1},
		{"monthly_at_credit_rollover", "2024-02-29", "2025-03-29", "2025-03-29", "2025-03-28", 1},
		{"annual_restores_leap_anniversary", "2024-02-29", "2028-02-29", "2028-02-29", "2028-02-29", 12},
		{"monthly_short_month", "2023-01-31", "2024-03-01", "2024-02-29", "2024-02-29", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor, _ := time.Parse("2006-01-02", tc.anchor)
			now, _ := time.Parse("2006-01-02", tc.now)
			b := ContractProviderBinding{Anchor: anchor, StartsAt: annualBoundary(anchor, 12), FeeAnchor: anchor, Terms: ProviderPairTerms{FeeMonths: tc.months}}
			if tc.months == 1 {
				b.FeeAnchor = b.StartsAt
			}
			grant, fee, err := renewalGrantFeeStart(b, now)
			if err != nil || grant.Format("2006-01-02") != tc.grant || fee.Format("2006-01-02") != tc.fee {
				t.Fatal("renewal selected a different grant's receipt", grant, fee, err)
			}
		})
	}
}
