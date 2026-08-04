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

func TestCurrentBillingPeriodBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		now       time.Time
		wantStart time.Time
		wantEnd   time.Time
	}{
		{
			name:      "utc month start",
			now:       time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			wantStart: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "utc month end",
			now:       time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC),
			wantStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "one nanosecond before utc month rollover",
			now:       time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond),
			wantStart: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "exact utc month rollover",
			now:       time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			wantStart: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "one nanosecond after utc month rollover",
			now:       time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(time.Nanosecond),
			wantStart: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "utc year end",
			now:       time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			wantStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "leap year february end",
			now:       time.Date(2024, 2, 29, 23, 59, 59, 999999999, time.UTC),
			wantStart: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "utc year start",
			now:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "non-utc input normalizes to utc month end",
			now:       time.Date(2026, 1, 31, 23, 30, 0, 0, time.FixedZone("UTC-2", -2*3600)),
			wantStart: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "non-utc input crosses into previous year in utc",
			now:       time.Date(2026, 1, 1, 0, 30, 0, 0, time.FixedZone("UTC+2", 2*3600)),
			wantStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			wantEnd:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd := CurrentBillingPeriod(tc.now)
			if !gotStart.Equal(tc.wantStart) {
				t.Fatalf("period start = %s, want %s", gotStart, tc.wantStart)
			}
			if !gotEnd.Equal(tc.wantEnd) {
				t.Fatalf("period end = %s, want %s", gotEnd, tc.wantEnd)
			}
		})
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
