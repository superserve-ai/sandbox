package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func movePairFixture(f *pairFixture, anchor time.Time) {
	f.p.Anchor = anchor
	f.fee.StartDate, f.fee.BillingCycleAnchor = anchor.Unix(), anchor.Unix()
	f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = anchor.Unix(), annualBoundary(anchor, 12).Unix()
	f.usage.StartDate, f.usage.BillingCycleAnchor = anchor.Unix(), anchor.Unix()
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = anchor.Unix(), annualBoundary(anchor, 1).Unix()
	}
	f.invoice.Lines.Data[0].Period.Start, f.invoice.Lines.Data[0].Period.End = anchor.Unix(), annualBoundary(anchor, 12).Unix()
}

func successorPairFixture(f *pairFixture, previous ContractProviderBinding, monthly bool) ContractProviderBinding {
	next := previous
	next.ContractID, next.StartsAt, next.EndsAt, next.FeeItemID = uuid.New(), *previous.EndsAt, nil, "si_successor"
	next.Identity.OperationID = uuid.New()
	if monthly {
		next.FeeAnchor = next.StartsAt
		next.Terms.FeePriceID, next.Terms.FeeAmount, next.Terms.FeeMonths = "price_monthly", 120000, 1
	}
	next.Identity.ProviderTermsDigest, _ = next.Terms.Digest()
	i := &f.fee.Items.Data[0]
	i.ID, i.Price.ID, i.Price.UnitAmountDecimal = next.FeeItemID, next.Terms.FeePriceID, "1200000"
	feeMonth := (next.StartsAt.Year()-next.FeeAnchor.Year())*12 + int(next.StartsAt.Month()-next.FeeAnchor.Month())
	i.Start, i.End = next.StartsAt.Unix(), annualBoundary(next.FeeAnchor, feeMonth+int(next.Terms.FeeMonths)).Unix()
	if monthly {
		i.Price.Recurring.Interval, i.Price.UnitAmountDecimal = "month", "120000"
		f.fee.BillingCycleAnchor = next.StartsAt.Unix()
	}
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = next.StartsAt.Unix(), annualBoundary(next.Anchor, 13).Unix()
	}
	f.invoice.BillingReason = "subscription_cycle"
	f.p.WaiverInvoiceID = "in_successor_" + uuid.NewString()
	f.invoice.ID, f.fee.LatestInvoice = f.p.WaiverInvoiceID, f.p.WaiverInvoiceID
	f.invoice.Discounts, f.invoice.DiscountAmounts = nil, nil
	f.invoice.Total, f.invoice.Subtotal, f.invoice.AmountDue = next.Terms.FeeAmount, next.Terms.FeeAmount, next.Terms.FeeAmount
	f.invoice.AmountPaid, f.invoice.AmountRemaining, f.invoice.Status = 0, next.Terms.FeeAmount, "open"
	f.invoice.Lines.Data[0].Amount = next.Terms.FeeAmount
	f.invoice.Lines.Data[0].Pricing.PriceDetails.Price = next.Terms.FeePriceID
	f.invoice.Lines.Data[0].Parent.SubscriptionItemDetails.SubscriptionItem = next.FeeItemID
	f.invoice.Lines.Data[0].Period.Start, f.invoice.Lines.Data[0].Period.End = i.Start, i.End
	return next
}

func TestProviderPairSuccessorUsesActualBoundaryItem(t *testing.T) {
	for _, monthly := range []bool{false, true} {
		t.Run(map[bool]string{false: "annual", true: "monthly"}[monthly], func(t *testing.T) {
			f := newPairFixture(t)
			movePairFixture(f, time.Now().UTC().AddDate(-1, 0, 0).Add(-time.Hour).Truncate(time.Second))
			end := annualBoundary(f.p.Anchor, 12)
			previous := ContractProviderBinding{ContractID: uuid.New(), Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeSubscriptionID: f.p.FeeSubscriptionID, FeeItemID: f.p.FeeItemID, Anchor: f.p.Anchor, FeeAnchor: f.p.Anchor, StartsAt: f.p.Anchor, EndsAt: &end}
			next := successorPairFixture(f, previous, monthly)
			client := f.client(t)
			v, err := client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID)
			if err != nil || v.seal == ([32]byte{}) {
				t.Fatalf("valid successor: %v", err)
			}
			var restored VerifiedProviderPairSuccessor
			if err = json.Unmarshal(v.AuditEvidence(), &restored); err != nil || restored.seal != ([32]byte{}) {
				t.Fatal("audit serialization preserved verification authority")
			}
			f.fee.Items.Data[0].ID = previous.FeeItemID
			if _, err = client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID); err == nil {
				t.Fatal("stale fee item accepted at renewal")
			}
			f.fee.Items.Data[0].ID = next.FeeItemID
			f.usage.PauseCollection = nil
			if _, err = client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID); err == nil {
				t.Fatal("successor accepted without permanent usage hold")
			}
		})
	}
}

func TestProviderPairMonthlySuccessorRecoversAfterFirstUnpaidPeriod(t *testing.T) {
	f := newPairFixture(t)
	now := time.Now().UTC()
	movePairFixture(f, time.Date(now.Year()-1, now.Month()-1, 1, 0, 0, 0, 0, time.UTC))
	end := annualBoundary(f.p.Anchor, 12)
	previous := ContractProviderBinding{ContractID: uuid.New(), Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeSubscriptionID: f.p.FeeSubscriptionID, FeeItemID: f.p.FeeItemID, Anchor: f.p.Anchor, FeeAnchor: f.p.Anchor, StartsAt: f.p.Anchor, EndsAt: &end}
	next := successorPairFixture(f, previous, true)
	f.fee.Status = "past_due"
	f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = annualBoundary(next.Anchor, 13).Unix(), annualBoundary(next.Anchor, 14).Unix()
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End
	}
	client := f.client(t)
	if _, err := client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID); err != nil {
		t.Fatalf("unpaid historical boundary recovery: %v", err)
	}
	if _, err := client.verifyProviderPairPayment(t.Context(), next, f.invoice.ID); err == nil {
		t.Fatal("unpaid boundary invoice became cash coverage")
	}
	f.invoice.Lines.Data[0].Period.Start = f.fee.Items.Data[0].Start
	f.invoice.Lines.Data[0].Period.End = f.fee.Items.Data[0].End
	if _, err := client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID); err == nil {
		t.Fatal("later monthly invoice replaced original boundary evidence")
	}
}

func TestProviderPairLeapDayMonthlyFeeKeepsSeparateCalendar(t *testing.T) {
	for _, year := range []int{2024, 2028} {
		f := newPairFixture(t)
		movePairFixture(f, time.Date(year, 2, 29, 12, 0, 0, 0, time.UTC))
		end := annualBoundary(f.p.Anchor, 12)
		previous := ContractProviderBinding{ContractID: uuid.New(), Identity: f.p.Identity, Terms: f.p.Terms, CustomerID: f.p.CustomerID, UsageSubscriptionID: f.p.UsageSubscriptionID, FeeSubscriptionID: f.p.FeeSubscriptionID, FeeItemID: f.p.FeeItemID, Anchor: f.p.Anchor, FeeAnchor: f.p.Anchor, StartsAt: f.p.Anchor, EndsAt: &end}
		next := successorPairFixture(f, previous, true)
		if err := validatePairSuccessorInvoice(next, f.invoice.ID, f.invoice); err != nil {
			t.Fatalf("year %d: actual boundary invoice rejected: %v", year, err)
		}
		if next.Anchor.Day() != 29 || next.FeeAnchor.Day() != 28 || time.Unix(f.invoice.Lines.Data[0].Period.End, 0).UTC().Day() != 28 || annualBoundary(next.Anchor, 13).Day() != 29 {
			t.Fatal("fee transition changed the original usage calendar")
		}
		f.invoice.Status, f.invoice.AmountRemaining, f.invoice.AmountPaid = "paid", 0, next.Terms.FeeAmount
		f.invoice.StatusTransitions.PaidAt = next.StartsAt.Add(time.Minute).Unix()
		client := f.client(t)
		if _, err := client.verifyProviderPairPayment(t.Context(), next, f.invoice.ID); err != nil {
			t.Fatalf("year %d: exact actual fee cash rejected: %v", year, err)
		}
		wrong := next
		wrong.FeeAnchor = next.Anchor
		if _, err := client.verifyProviderPairPayment(t.Context(), wrong, f.invoice.ID); err == nil {
			t.Fatal("cash receipt silently extended to usage-calendar end")
		}
		if year == 2024 {
			// Delayed construction independently verifies current fee and usage
			// periods while retaining the original boundary invoice as evidence.
			start, finish, ok := billing.AnniversaryPeriod(next.FeeAnchor, time.Now())
			if !ok {
				t.Fatal("fee calendar unavailable")
			}
			f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = start.Unix(), finish.Unix()
			start, finish, ok = billing.AnniversaryPeriod(next.Anchor, time.Now())
			if !ok {
				t.Fatal("usage calendar unavailable")
			}
			for i := range f.usage.Items.Data {
				f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = start.Unix(), finish.Unix()
			}
			if _, err := client.verifySuccessorProviderPair(t.Context(), previous, next, f.invoice.ID); err != nil {
				t.Fatalf("separate current calendars rejected: %v", err)
			}
		}
	}
}
