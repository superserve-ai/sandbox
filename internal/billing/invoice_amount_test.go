package billing

import "testing"

func TestInvoiceLineCentsBoundary(t *testing.T) {
	for _, tc := range []struct {
		quantity, price string
		want            int64
	}{
		{"1.05500000001", "1", 106},
		{"1.05499999999", "1", 105},
		{"1.055", "1", 106},
		{"0.004999999999", "1", 0},
		{"0.005000000001", "1", 1},
		{"0.005", "1", 1},
		{"105.499999999", "0.01", 105},
		{"105.500000001", "0.01", 106},
		{"12345.678901234561", "0.000108", 133},
		{"12345.678901234565", "0.000108", 133},
		{"0", "0.000108", 0},
	} {
		t.Run(tc.quantity+"x"+tc.price, func(t *testing.T) {
			got, err := InvoiceLineCents(tc.quantity, tc.price)
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestInvoiceLineCentsRejectsInvalidAmounts(t *testing.T) {
	for _, value := range []string{"", "NaN", "Infinity", "-0.01", "1/2", "1e100", "92233720368547758.08"} {
		if _, err := InvoiceLineCents(value, "1"); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestInvoiceCreditConsumptionAtBoundary(t *testing.T) {
	for _, tc := range []struct {
		amount  string
		balance int64
		want    InvoiceCreditAllocation
	}{
		{"1.05500000001", 1000, InvoiceCreditAllocation{106, 894, 0}},
		{"1.05499999999", 1000, InvoiceCreditAllocation{105, 895, 0}},
		{"1.05500000001", 105, InvoiceCreditAllocation{105, 0, 1}},
		{"1.05499999999", 105, InvoiceCreditAllocation{105, 0, 0}},
		{"1.05500000001", 0, InvoiceCreditAllocation{0, 0, 106}},
	} {
		charge, err := InvoiceLineCents(tc.amount, "1")
		if err != nil {
			t.Fatal(err)
		}
		got, err := AllocateInvoiceCredits(charge, tc.balance)
		if err != nil || got != tc.want {
			t.Fatalf("%s balance=%d: got %+v, %v; want %+v", tc.amount, tc.balance, got, err, tc.want)
		}
	}
}

func TestInvoicePeriodCreditCarryForward(t *testing.T) {
	// A fractional usage residual is never added to next period's usage or charge.
	firstCents, _ := InvoiceLineCents("1.05499999999", "1")
	first, _ := AllocateInvoiceCredits(firstCents, 1000)
	secondCents, _ := InvoiceLineCents("1.05499999999", "1")
	second, _ := AllocateInvoiceCredits(secondCents, first.RemainingCents)
	if first.AppliedCents != 105 || second.AppliedCents != 105 || second.RemainingCents != 790 {
		t.Fatalf("unexpected period credit consumption: %+v then %+v", first, second)
	}
}

func TestVerifyInvoiceSettlement(t *testing.T) {
	for _, tc := range []struct {
		name           string
		charge, credit int64
		observed       InvoiceSettlement
		wantErr        bool
	}{
		{"full coverage", 106, 1000, InvoiceSettlement{GrossCents: 106, CreditAppliedCents: 106, CreditRemainingCents: 894}, false},
		{"wrong debit hidden by zero payable", 106, 1000, InvoiceSettlement{GrossCents: 106, CreditAppliedCents: 105, CreditRemainingCents: 895}, true},
		{"wrong ledger balance", 106, 1000, InvoiceSettlement{GrossCents: 106, CreditAppliedCents: 106, CreditRemainingCents: 895}, true},
		{"unapplied late adjustment", 106, 1000, InvoiceSettlement{GrossCents: 105, CreditAppliedCents: 105, CreditRemainingCents: 895}, true},
		{"partial credit", 106, 50, InvoiceSettlement{GrossCents: 106, CreditAppliedCents: 50, TotalCents: 56, AmountDueCents: 56}, false},
		{"minimum charge carried", 105, 100, InvoiceSettlement{GrossCents: 105, CreditAppliedCents: 100, TotalCents: 5, EndingInvoiceBalance: 5}, false},
		{"minimum charge lost", 105, 100, InvoiceSettlement{GrossCents: 105, CreditAppliedCents: 100, TotalCents: 5}, true},
		{"existing balance collected", 105, 0, InvoiceSettlement{GrossCents: 105, TotalCents: 105, AmountDueCents: 110, StartingInvoiceBalance: 5}, false},
		{"existing invoice credit", 105, 0, InvoiceSettlement{GrossCents: 105, TotalCents: 105, AmountDueCents: 95, StartingInvoiceBalance: -10}, false},
		{"invoice credit remains", 105, 0, InvoiceSettlement{GrossCents: 105, TotalCents: 105, StartingInvoiceBalance: -200, EndingInvoiceBalance: -95}, false},
		{"unexpected extra penny", 105, 0, InvoiceSettlement{GrossCents: 105, TotalCents: 105, AmountDueCents: 106}, true},
		{"negative expected credit", 105, -1, InvoiceSettlement{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyInvoiceSettlement(tc.charge, tc.credit, tc.observed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyInvoiceSettlementAtRoundingBoundary(t *testing.T) {
	for _, amount := range []string{"1.05499999999", "1.055", "1.05500000001", "0.004999999999", "0.005"} {
		charge, err := InvoiceLineCents(amount, "1")
		if err != nil {
			t.Fatal(err)
		}
		for _, credit := range []int64{0, 50, 1000} {
			allocation, err := AllocateInvoiceCredits(charge, credit)
			if err != nil {
				t.Fatal(err)
			}
			observed := InvoiceSettlement{GrossCents: charge, CreditAppliedCents: allocation.AppliedCents, CreditRemainingCents: allocation.RemainingCents, TotalCents: allocation.PayableCents, AmountDueCents: allocation.PayableCents}
			if err = VerifyInvoiceSettlement(charge, credit, observed); err != nil {
				t.Fatalf("%s credit=%d: %v", amount, credit, err)
			}
			observed.CreditRemainingCents++
			if err = VerifyInvoiceSettlement(charge, credit, observed); err == nil {
				t.Fatalf("accepted wrong remaining credit: %s credit=%d", amount, credit)
			}
		}
	}
}
