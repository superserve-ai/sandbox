package billing

import (
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

var requiredSummaryResources = map[string]struct{}{
	"memory_gib":  {},
	"storage_gib": {},
	"vcpu":        {},
}

type SummaryBreakdown struct {
	ComputeUSD float64
	MemoryUSD  float64
	StorageUSD float64
}

type SummaryCharges struct {
	CurrentChargesUSD        float64
	CreditsAppliedUSD        float64
	CreditsRemainingUSD      float64
	ExpectedInvoiceAmountUSD float64
	Breakdown                SummaryBreakdown
}

func CurrentBillingPeriod(now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

func CalculateSummaryCharges(
	vcpuSeconds float64,
	memoryGibSeconds float64,
	storageGibSeconds float64,
	vcpuRate float64,
	memoryRate float64,
	storageRate float64,
	creditsAvailable float64,
) SummaryCharges {
	breakdown := SummaryBreakdown{
		ComputeUSD: vcpuSeconds * vcpuRate,
		MemoryUSD:  memoryGibSeconds * memoryRate,
		StorageUSD: storageGibSeconds * storageRate,
	}
	currentCharges := breakdown.ComputeUSD + breakdown.MemoryUSD + breakdown.StorageUSD
	creditsApplied := math.Min(currentCharges, creditsAvailable)

	return SummaryCharges{
		CurrentChargesUSD:        currentCharges,
		CreditsAppliedUSD:        creditsApplied,
		CreditsRemainingUSD:      creditsAvailable - creditsApplied,
		ExpectedInvoiceAmountUSD: currentCharges - creditsApplied,
		Breakdown:                breakdown,
	}
}

func NumericFloat64(n pgtype.Numeric) (float64, error) {
	v, err := n.Float64Value()
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, fmt.Errorf("numeric value is null")
	}
	return v.Float64, nil
}
