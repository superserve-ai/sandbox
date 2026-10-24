package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// VerifiedProviderPairSuccessor proves the actual post-boundary provider pair.
// Confirmed customer choice and cash coverage are separate admission checks.
type VerifiedProviderPairSuccessor struct {
	Previous   ContractProviderBinding `json:"previous"`
	Binding    ContractProviderBinding `json:"binding"`
	VerifiedAt time.Time               `json:"verified_at"`
	Evidence   json.RawMessage         `json:"evidence"`
	seal       [32]byte
}

func (v VerifiedProviderPairSuccessor) AuditEvidence() json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (v VerifiedProviderPairSuccessor) digest() [32]byte {
	return sha256.Sum256(v.AuditEvidence())
}

// VerifySuccessorProviderPair reads the saved predecessor and actual provider
// state. Future schedules alone cannot establish an effective successor binding.
func (h *Handlers) VerifySuccessorProviderPair(ctx context.Context, previousContract uuid.UUID, next ContractProviderBinding, boundaryInvoice string) (VerifiedProviderPairSuccessor, error) {
	previous, err := h.ContractProviderBinding(ctx, next.Identity.TeamID, previousContract)
	if err != nil {
		return VerifiedProviderPairSuccessor{}, err
	}
	c, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return VerifiedProviderPairSuccessor{}, errors.New("paired successor verifier unavailable")
	}
	return c.verifySuccessorProviderPair(ctx, previous, next, boundaryInvoice)
}

func validatePairSuccessor(previous, next ContractProviderBinding) error {
	i, old := next.Identity, previous.Identity
	digest, err := next.Terms.Digest()
	if err != nil || digest != i.ProviderTermsDigest || !validPairDigest(i.TermsDigest) || i.OperationID == uuid.Nil || i.OperationID == old.OperationID ||
		i.TeamID != old.TeamID || i.AssignmentID != old.AssignmentID || i.AcceptanceID != old.AcceptanceID || i.ApprovalSemanticRevision != old.ApprovalSemanticRevision ||
		i.Merchant != old.Merchant || i.Live != old.Live || i.APIVersion != old.APIVersion ||
		next.ContractID == uuid.Nil || previous.ContractID == uuid.Nil || next.ContractID == previous.ContractID ||
		next.CustomerID != previous.CustomerID || next.FeeSubscriptionID != previous.FeeSubscriptionID || next.UsageSubscriptionID != previous.UsageSubscriptionID || next.FeeItemID == "" ||
		!next.Anchor.Equal(previous.Anchor) || next.FeeAnchor.IsZero() || next.FeeAnchor.Nanosecond() != 0 || (!next.FeeAnchor.Equal(previous.FeeAnchor) && !next.FeeAnchor.Equal(next.StartsAt)) || previous.EndsAt == nil || !next.StartsAt.Equal(*previous.EndsAt) || next.StartsAt.After(time.Now()) ||
		!reflect.DeepEqual(next.Terms.Resources, previous.Terms.Resources) || next.Terms.Rounding != previous.Terms.Rounding {
		return errors.New("successor differs from the saved provider pair or confirmed boundary")
	}
	months := (next.StartsAt.Year()-next.Anchor.Year())*12 + int(next.StartsAt.Month()-next.Anchor.Month())
	if months < 12 || !next.StartsAt.Equal(annualBoundary(next.Anchor, months)) {
		return errors.New("successor must retain the original anniversary")
	}
	if next.EndsAt != nil {
		endMonths := (next.EndsAt.Year()-next.Anchor.Year())*12 + int(next.EndsAt.Month()-next.Anchor.Month())
		if endMonths <= months || (endMonths-months)%int(next.Terms.FeeMonths) != 0 || !next.EndsAt.Equal(annualBoundary(next.Anchor, endMonths)) {
			return errors.New("successor end differs from its original-anchor cadence")
		}
	}
	return nil
}

func (c *stripeHTTPClient) verifySuccessorProviderPair(ctx context.Context, previous, next ContractProviderBinding, boundaryInvoice string) (VerifiedProviderPairSuccessor, error) {
	var result VerifiedProviderPairSuccessor
	if err := validatePairSuccessor(previous, next); err != nil {
		return result, err
	}
	if c.apiVersion != next.Identity.APIVersion {
		return result, errors.New("successor API version differs")
	}
	var account struct{ ID string }
	if err := c.doForm(ctx, http.MethodGet, "/v1/account", nil, &account, ""); err != nil {
		return result, err
	}
	if account.ID != next.Identity.Merchant {
		return result, errors.New("successor merchant differs")
	}
	fee, err := c.invoiceSubscription(ctx, next.FeeSubscriptionID)
	if err != nil {
		return result, err
	}
	usage, err := c.invoiceSubscription(ctx, next.UsageSubscriptionID)
	if err != nil {
		return result, err
	}
	for _, s := range []invoiceSubscription{fee, usage} {
		if s.Customer != next.CustomerID || s.LiveMode != next.Identity.Live || s.BillingMode.Type != "flexible" || s.CollectionMethod != "charge_automatically" || s.StartDate != next.Anchor.Unix() || s.Items.HasMore || s.AutomaticTax.Enabled || len(s.DefaultTaxRates) != 0 || len(s.Discounts) != 0 || s.BillingThresholds != nil || s.PendingUpdate != nil || s.TrialStart != 0 || s.TrialEnd != 0 || s.CancelAt != 0 || s.CancelAtPeriodEnd || !emptyPairSchedules(s.BillingSchedules) {
			return result, errors.New("successor subscription has unsupported calendar or modifiers")
		}
		for _, item := range s.Items.Data {
			if len(item.TaxRates) != 0 || len(item.Discounts) != 0 {
				return result, errors.New("successor item has unsupported modifiers")
			}
		}
	}
	if (fee.Status != "active" && fee.Status != "past_due" && fee.Status != "unpaid") || usage.Status != "active" || fee.ID != next.FeeSubscriptionID || fee.PauseCollection != nil || len(fee.Items.Data) != 1 || fee.BillingCycleAnchor != next.FeeAnchor.Unix() || usage.ID != next.UsageSubscriptionID || usage.Schedule != "" || usage.PauseCollection == nil || usage.PauseCollection.Behavior != "keep_as_draft" || usage.PauseCollection.ResumesAt != 0 {
		return result, errors.New("successor fee identity or usage hold differs")
	}
	item := fee.Items.Data[0]
	months := (next.StartsAt.Year()-next.FeeAnchor.Year())*12 + int(next.StartsAt.Month()-next.FeeAnchor.Month())
	if err = validatePairFeeItem(next.Terms, next.Identity.Live, item); err != nil {
		return result, err
	}
	currentStart := time.Unix(item.Start, 0).UTC()
	currentMonths := (currentStart.Year()-next.FeeAnchor.Year())*12 + int(currentStart.Month()-next.FeeAnchor.Month())
	if item.ID != next.FeeItemID || currentMonths < months || (currentMonths-months)%int(next.Terms.FeeMonths) != 0 || item.Start != annualBoundary(next.FeeAnchor, currentMonths).Unix() || item.End != annualBoundary(next.FeeAnchor, currentMonths+int(next.Terms.FeeMonths)).Unix() || item.Start > time.Now().Unix() || item.End <= time.Now().Unix() {
		return result, errors.New("successor fee item differs from the verified fee cadence")
	}
	a := invoiceAccount{Customer: next.CustomerID, Subscription: next.UsageSubscriptionID, Price: next.Terms.Rounding.PriceID, Meter: next.Terms.Rounding.MeterID, Event: next.Terms.Rounding.EventName}
	if err = validatePairUsageSubscription(next, a, usage); err != nil {
		return result, err
	}
	for _, r := range append(append([]StripeCheckoutResourceTerms{}, next.Terms.Resources...), next.Terms.Rounding) {
		meter, e := c.ActiveMeterID(ctx, r.EventName)
		if e != nil {
			return result, e
		}
		if meter != r.MeterID {
			return result, errors.New("successor usage event mapping changed")
		}
	}
	var inventory struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {next.CustomerID}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for _, s := range inventory.Data {
		if seen[s.ID] || s.Customer != next.CustomerID || (s.ID != fee.ID && s.ID != usage.ID && s.Status != "canceled" && s.Status != "incomplete_expired") {
			return result, errors.New("successor subscription inventory differs")
		}
		seen[s.ID] = true
	}
	if inventory.HasMore || !seen[fee.ID] || !seen[usage.ID] {
		return result, errors.New("successor subscription inventory is incomplete")
	}
	var boundary proPaidInvoice
	if boundaryInvoice == "" {
		return result, errors.New("successor requires its original boundary invoice")
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(boundaryInvoice), nil, &boundary, ""); err != nil {
		return result, err
	}
	if err = validatePairSuccessorInvoice(next, boundaryInvoice, boundary); err != nil {
		return result, err
	}
	result = VerifiedProviderPairSuccessor{Previous: previous, Binding: next, VerifiedAt: time.Now().UTC()}
	result.Evidence, err = json.Marshal(struct{ Account, Fee, Usage, Inventory, BoundaryInvoice any }{account, fee, usage, inventory, boundary})
	if err != nil {
		return VerifiedProviderPairSuccessor{}, err
	}
	result.seal = result.digest()
	return result, nil
}

func validatePairSuccessorInvoice(b ContractProviderBinding, id string, inv proPaidInvoice) error {
	if inv.ID != id || inv.Customer != b.CustomerID || inv.LiveMode != b.Identity.Live || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != b.FeeSubscriptionID || (inv.Status != "paid" && inv.Status != "open" && inv.Status != "uncollectible") || inv.BillingReason != "subscription_cycle" || inv.Currency != b.Terms.Currency || inv.Subtotal != b.Terms.FeeAmount || inv.Total != b.Terms.FeeAmount || len(inv.Taxes) != 0 || len(inv.Discounts) != 0 || len(inv.DiscountAmounts) != 0 || len(inv.PretaxCredits) != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 || inv.AmountShipping != 0 || inv.Lines.HasMore || len(inv.Lines.Data) != 1 {
		return errors.New("successor boundary invoice differs from its licensed fee")
	}
	l := inv.Lines.Data[0]
	months := (b.StartsAt.Year()-b.FeeAnchor.Year())*12 + int(b.StartsAt.Month()-b.FeeAnchor.Month())
	if l.Parent.SubscriptionItemDetails == nil || l.Parent.SubscriptionItemDetails.Subscription != b.FeeSubscriptionID || l.Parent.SubscriptionItemDetails.SubscriptionItem != b.FeeItemID || l.Parent.SubscriptionItemDetails.Proration || l.Pricing.PriceDetails == nil || l.Pricing.PriceDetails.Price != b.Terms.FeePriceID || l.Pricing.PriceDetails.Product != b.Terms.FeeProductID || l.Amount != b.Terms.FeeAmount || l.Currency != b.Terms.Currency || l.Quantity != 1 || baseLineHasCredits(l) || l.Period.Start != b.StartsAt.Unix() || l.Period.End != annualBoundary(b.FeeAnchor, months+int(b.Terms.FeeMonths)).Unix() {
		return errors.New("successor original boundary line differs from its bound item")
	}
	return nil
}

// ConfirmSuccessorProviderPair binds an already-created pending successor in
// the caller's guarded renewal transaction. It does not activate or record cash.
func ConfirmSuccessorProviderPair(ctx context.Context, tx pgx.Tx, verified VerifiedProviderPairSuccessor) (ContractProviderBinding, error) {
	var empty ContractProviderBinding
	now := time.Now()
	if tx == nil || verified.seal == ([32]byte{}) || verified.seal != verified.digest() || verified.VerifiedAt.After(now) || now.Sub(verified.VerifiedAt) > time.Minute {
		return empty, errors.New("fresh typed successor verification is required")
	}
	if err := validatePairSuccessor(verified.Previous, verified.Binding); err != nil {
		return empty, err
	}
	if err := lockCommercialOfferAccount(ctx, tx, verified.Binding.Identity.TeamID); err != nil {
		return empty, err
	}
	previous, err := loadContractProviderBinding(ctx, tx, verified.Previous.ContractID)
	if err != nil {
		return empty, err
	}
	a, _ := json.Marshal(previous)
	b, _ := json.Marshal(verified.Previous)
	if string(a) != string(b) {
		return empty, errors.New("successor predecessor differs from saved binding")
	}
	return confirmProviderBinding(ctx, tx, verified.Binding, verified.Evidence, verified.VerifiedAt)
}
