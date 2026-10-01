package billing

import (
	"fmt"
	"math/big"
	"regexp"
)

var invoiceDecimal = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// InvoiceLineCents rounds the exact quantity-price product directly to cents.
// Rounding an intermediate dollar amount can cross a half-cent boundary.
func InvoiceLineCents(quantity, unitPriceUSD string) (int64, error) {
	values := make([]*big.Rat, 2)
	for i, text := range []string{quantity, unitPriceUSD} {
		if len(text) > 128 || !invoiceDecimal.MatchString(text) {
			return 0, fmt.Errorf("invalid invoice decimal")
		}
		value, ok := new(big.Rat).SetString(text)
		if !ok || value.Sign() < 0 {
			return 0, fmt.Errorf("invalid invoice decimal")
		}
		values[i] = value
	}
	cents := new(big.Rat).Mul(values[0], values[1])
	cents.Mul(cents, big.NewRat(100, 1))
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(cents.Num(), cents.Denom(), remainder)
	if remainder.Lsh(remainder, 1).Cmp(cents.Denom()) >= 0 {
		whole.Add(whole, big.NewInt(1))
	}
	if !whole.IsInt64() {
		return 0, fmt.Errorf("invoice amount exceeds supported range")
	}
	return whole.Int64(), nil
}

type InvoiceCreditAllocation struct {
	AppliedCents   int64
	RemainingCents int64
	PayableCents   int64
}

// AllocateInvoiceCredits uses the corrected, rounded charge. Each invoice is
// independent; only the genuine remaining credit balance carries forward.
func AllocateInvoiceCredits(chargeCents, availableCents int64) (InvoiceCreditAllocation, error) {
	if chargeCents < 0 || availableCents < 0 {
		return InvoiceCreditAllocation{}, fmt.Errorf("negative invoice charge or credit balance")
	}
	applied := min(chargeCents, availableCents)
	return InvoiceCreditAllocation{
		AppliedCents: applied, RemainingCents: availableCents - applied,
		PayableCents: chargeCents - applied,
	}, nil
}

// InvoiceSettlement contains the finalized provider amounts and credit ledger
// observations. Balance values use Stripe's convention: positive means owed.
type InvoiceSettlement struct {
	GrossCents             int64
	CreditAppliedCents     int64
	CreditRemainingCents   int64
	TotalCents             int64
	AmountDueCents         int64
	StartingInvoiceBalance int64
	EndingInvoiceBalance   int64
}

// VerifyInvoiceSettlement checks both the charge and the actual credit debit.
// A zero amount due alone cannot establish correctness: credits can cover an
// incorrect charge, and a below-minimum charge can move to invoice balance.
func VerifyInvoiceSettlement(expectedChargeCents, creditBeforeCents int64, observed InvoiceSettlement) error {
	allocation, err := AllocateInvoiceCredits(expectedChargeCents, creditBeforeCents)
	if err != nil {
		return err
	}
	if observed.GrossCents != expectedChargeCents {
		return fmt.Errorf("invoice gross charge differs: got %d cents, expected %d", observed.GrossCents, expectedChargeCents)
	}
	if observed.CreditAppliedCents != allocation.AppliedCents || observed.CreditRemainingCents != allocation.RemainingCents {
		return fmt.Errorf("invoice credit consumption differs: applied=%d remaining=%d, expected applied=%d remaining=%d",
			observed.CreditAppliedCents, observed.CreditRemainingCents, allocation.AppliedCents, allocation.RemainingCents)
	}
	if observed.TotalCents != allocation.PayableCents || observed.AmountDueCents < 0 {
		return fmt.Errorf("invoice net charge differs from corrected charge after credits")
	}
	// Avoid overflow when combining signed customer balances with invoice money.
	settled := new(big.Int).SetInt64(observed.AmountDueCents)
	settled.Add(settled, big.NewInt(observed.EndingInvoiceBalance))
	settled.Sub(settled, big.NewInt(observed.StartingInvoiceBalance))
	if settled.Cmp(big.NewInt(allocation.PayableCents)) != 0 {
		return fmt.Errorf("invoice payable amount and customer balance do not reconcile")
	}
	return nil
}
