package billing

import (
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestValidateSummaryPricingRatesRejectsUnsupportedResource(t *testing.T) {
	now := time.Now().UTC()
	rows := []db.ListActivePricingRatesForTeamCurrentRow{
		{
			PlanKey:       "payg",
			PlanName:      "Pay-as-you-go",
			Currency:      "USD",
			Resource:      "vcpu",
			Unit:          "second",
			PriceUsd:      numericFromFloat64(t, 0.000014),
			EffectiveFrom: now,
		},
		{
			PlanKey:       "payg",
			PlanName:      "Pay-as-you-go",
			Currency:      "USD",
			Resource:      "memory_gib",
			Unit:          "second",
			PriceUsd:      numericFromFloat64(t, 0.0000045),
			EffectiveFrom: now,
		},
		{
			PlanKey:       "payg",
			PlanName:      "Pay-as-you-go",
			Currency:      "USD",
			Resource:      "storage_gib",
			Unit:          "second",
			PriceUsd:      numericFromFloat64(t, 0.00000003),
			EffectiveFrom: now,
		},
		{
			PlanKey:       "payg",
			PlanName:      "Pay-as-you-go",
			Currency:      "USD",
			Resource:      "bandwidth",
			Unit:          "second",
			PriceUsd:      numericFromFloat64(t, 0.000001),
			EffectiveFrom: now,
		},
	}

	if _, err := ValidateSummaryPricingRates(rows); err == nil {
		t.Fatal("expected unsupported resource to be rejected")
	}
}

func numericFromFloat64(t *testing.T, v float64) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(strconv.FormatFloat(v, 'f', -1, 64)); err != nil {
		t.Fatalf("scan numeric: %v", err)
	}
	return n
}
