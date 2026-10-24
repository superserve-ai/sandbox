package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProviderPairTerms is frozen by server admission, separately from the customer's
// acceptance. Later configuration changes cannot replace any of these prices.
type ProviderPairTerms struct {
	FeePriceID   string                        `json:"fee_price_id"`
	FeeProductID string                        `json:"fee_product_id"`
	FeeAmount    int64                         `json:"fee_amount_cents"`
	Currency     string                        `json:"currency"`
	FeeMonths    int32                         `json:"fee_months"`
	Resources    []StripeCheckoutResourceTerms `json:"resources"`
	Rounding     StripeCheckoutResourceTerms   `json:"rounding"`
}

func (t ProviderPairTerms) Digest() (string, error) {
	if err := t.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

func (t ProviderPairTerms) validate() error {
	if !strings.HasPrefix(t.FeePriceID, "price_") || strings.TrimSpace(t.FeeProductID) == "" || t.FeeAmount <= 0 || t.Currency != "usd" || (t.FeeMonths != 1 && t.FeeMonths != 12) || len(t.Resources) != 3 || t.Rounding.UnitAmountDecimal != "1" {
		return errors.New("incomplete paired provider terms")
	}
	prices, meters, events, resources := map[string]bool{t.FeePriceID: true}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range append(append([]StripeCheckoutResourceTerms{}, t.Resources...), t.Rounding) {
		amount, err := meterDecimal(r.UnitAmountDecimal)
		if err != nil || amount.Sign() <= 0 || r.ResourceKey == "" || !strings.HasPrefix(r.PriceID, "price_") || r.MeterID == "" || r.EventName == "" || prices[r.PriceID] || meters[r.MeterID] || events[r.EventName] || resources[r.ResourceKey] {
			return errors.New("paired metered prices, resources, events and meters must be complete and distinct")
		}
		prices[r.PriceID], meters[r.MeterID], events[r.EventName], resources[r.ResourceKey] = true, true, true, true
	}
	return nil
}

type ProviderPairIdentity struct {
	OperationID              uuid.UUID `json:"operation_id"`
	TeamID                   uuid.UUID `json:"team_id"`
	AssignmentID             uuid.UUID `json:"assignment_id"`
	AcceptanceID             uuid.UUID `json:"acceptance_id"`
	ApprovalSemanticRevision int64     `json:"approval_semantic_revision"`
	TermsDigest              string    `json:"terms_digest"`
	ProviderTermsDigest      string    `json:"provider_terms_digest"`
	Merchant                 string    `json:"merchant"`
	Live                     bool      `json:"live"`
	APIVersion               string    `json:"api_version"`
}

type ProviderPairVerificationInput struct {
	Identity            ProviderPairIdentity `json:"identity"`
	Terms               ProviderPairTerms    `json:"terms"`
	CustomerID          string               `json:"customer_id"`
	FeeSubscriptionID   string               `json:"fee_subscription_id"`
	UsageSubscriptionID string               `json:"usage_subscription_id"`
	FeeItemID           string               `json:"fee_item_id"`
	WaiverCouponID      string               `json:"waiver_coupon_id"`
	WaiverInvoiceID     string               `json:"waiver_invoice_id"`
	Anchor              time.Time            `json:"anchor"`
}

// VerifiedProviderPair carries provider evidence, not a payment or funding-ready
// boolean. Only fresh read-only verification can construct the private seal.
type VerifiedProviderPair struct {
	Input      ProviderPairVerificationInput `json:"input"`
	VerifiedAt time.Time                     `json:"verified_at"`
	Evidence   json.RawMessage               `json:"evidence"`
	seal       [32]byte
}

func pairSeal(v VerifiedProviderPair) [32]byte {
	b, _ := json.Marshal(v)
	return sha256.Sum256(b)
}

func (v VerifiedProviderPair) validateFresh() error {
	now := time.Now()
	if v.seal == ([32]byte{}) || v.seal != pairSeal(v) || v.VerifiedAt.After(now) || now.Sub(v.VerifiedAt) > time.Minute {
		return errors.New("fresh verified provider pair is required")
	}
	return v.Input.validate()
}

func validPairDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

func (p ProviderPairVerificationInput) validate() error {
	i := p.Identity
	digest, err := p.Terms.Digest()
	if err != nil || digest != i.ProviderTermsDigest || !validPairDigest(i.TermsDigest) || i.OperationID == uuid.Nil || i.TeamID == uuid.Nil || i.AssignmentID == uuid.Nil || i.AcceptanceID == uuid.Nil || i.ApprovalSemanticRevision < 0 || !strings.HasPrefix(i.Merchant, "acct_") || i.APIVersion == "" || !strings.HasPrefix(p.CustomerID, "cus_") || !strings.HasPrefix(p.FeeSubscriptionID, "sub_") || !strings.HasPrefix(p.UsageSubscriptionID, "sub_") || p.FeeSubscriptionID == p.UsageSubscriptionID || !strings.HasPrefix(p.FeeItemID, "si_") || p.WaiverCouponID == "" || !strings.HasPrefix(p.WaiverInvoiceID, "in_") || p.Anchor.Unix() <= 0 || p.Anchor.Nanosecond() != 0 || p.Terms.FeeMonths != 12 || p.Terms.FeeAmount != 1200000 {
		return errors.New("initial provider pair identity or accepted terms are incomplete")
	}
	return nil
}

func pairMetadata(i ProviderPairIdentity, step string) map[string]string {
	return map[string]string{"operation_id": i.OperationID.String(), "assignment_id": i.AssignmentID.String(), "acceptance_id": i.AcceptanceID.String(), "step": step}
}

func requirePairMetadata(actual map[string]string, i ProviderPairIdentity, step string) error {
	for k, v := range pairMetadata(i, step) {
		if actual[k] != v {
			return errors.New("provider object correlation differs from its durable operation")
		}
	}
	return nil
}

// VerifyInitialProviderPair performs GETs only. Creation and the usage hold must
// already have their own confirmed, durable provisioning requests.
func (h *Handlers) VerifyInitialProviderPair(ctx context.Context, p ProviderPairVerificationInput) (VerifiedProviderPair, error) {
	c, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return VerifiedProviderPair{}, errors.New("paired provider verifier unavailable")
	}
	return c.verifyInitialProviderPair(ctx, p)
}

func (c *stripeHTTPClient) verifyInitialProviderPair(ctx context.Context, p ProviderPairVerificationInput) (VerifiedProviderPair, error) {
	var result VerifiedProviderPair
	if err := p.validate(); err != nil {
		return result, err
	}
	if c.apiVersion != p.Identity.APIVersion {
		return result, errors.New("provider API version differs from frozen request")
	}
	var account struct{ ID string }
	if err := c.doForm(ctx, http.MethodGet, "/v1/account", nil, &account, ""); err != nil {
		return result, err
	}
	if account.ID != p.Identity.Merchant {
		return result, errors.New("provider merchant differs from frozen request")
	}
	var customer struct {
		ID       string            `json:"id"`
		Live     bool              `json:"livemode"`
		Deleted  bool              `json:"deleted"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(p.CustomerID), nil, &customer, ""); err != nil {
		return result, err
	}
	if customer.ID != p.CustomerID || customer.Live != p.Identity.Live || customer.Deleted {
		return result, errors.New("paired customer identity differs")
	}
	if err := requirePairMetadata(customer.Metadata, p.Identity, "customer"); err != nil {
		return result, err
	}
	fee, err := c.invoiceSubscription(ctx, p.FeeSubscriptionID)
	if err != nil {
		return result, err
	}
	usage, err := c.invoiceSubscription(ctx, p.UsageSubscriptionID)
	if err != nil {
		return result, err
	}
	if err = validateInitialPairSubscriptions(p, fee, usage); err != nil {
		return result, err
	}
	for _, r := range append(append([]StripeCheckoutResourceTerms{}, p.Terms.Resources...), p.Terms.Rounding) {
		meter, e := c.ActiveMeterID(ctx, r.EventName)
		if e != nil {
			return result, e
		}
		if meter != r.MeterID {
			return result, errors.New("paired event meter mapping changed")
		}
	}
	var inventory struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {p.CustomerID}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
		return result, err
	}
	if inventory.HasMore || len(inventory.Data) != 2 {
		return result, errors.New("initial provider pair requires complete two-subscription inventory")
	}
	seen := map[string]bool{}
	for _, s := range inventory.Data {
		if seen[s.ID] || (s.ID != fee.ID && s.ID != usage.ID) || s.Customer != p.CustomerID {
			return result, errors.New("initial provider pair inventory differs")
		}
		seen[s.ID] = true
	}
	var coupon struct {
		ID         string            `json:"id"`
		Duration   string            `json:"duration"`
		PercentOff float64           `json:"percent_off"`
		AmountOff  *int64            `json:"amount_off"`
		Live       bool              `json:"livemode"`
		Metadata   map[string]string `json:"metadata"`
		AppliesTo  struct {
			Products []string `json:"products"`
		} `json:"applies_to"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/coupons/"+url.PathEscape(p.WaiverCouponID), nil, &coupon, ""); err != nil {
		return result, err
	}
	if coupon.ID != p.WaiverCouponID || coupon.Duration != "once" || coupon.PercentOff != 100 || coupon.AmountOff != nil || coupon.Live != p.Identity.Live || !reflect.DeepEqual(coupon.AppliesTo.Products, []string{p.Terms.FeeProductID}) {
		return result, errors.New("initial fee coupon differs from one-time product waiver")
	}
	if err = requirePairMetadata(coupon.Metadata, p.Identity, "waiver"); err != nil {
		return result, err
	}
	var invoice proPaidInvoice
	if err = c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(p.WaiverInvoiceID)+"?expand[]=discounts", nil, &invoice, ""); err != nil {
		return result, err
	}
	if err = validatePairWaiverInvoice(p, invoice); err != nil {
		return result, err
	}
	if len(fee.Discounts) == 1 && (invoice.Discounts[0].ID == "" || fee.Discounts[0] != invoice.Discounts[0].ID) {
		return result, errors.New("current fee discount is not the verified once waiver")
	}
	obligations, err := c.verifyInitialPairObligations(ctx, p, usage.LatestInvoice)
	if err != nil {
		return result, err
	}
	if err = c.verifyProCreditNotes(ctx, invoice, p.Terms.FeePriceID); err != nil {
		return result, err
	}
	result.Input, result.VerifiedAt = p, time.Now().UTC()
	result.Evidence, err = json.Marshal(struct{ Account, Customer, Fee, Usage, Inventory, Coupon, Invoice, Obligations any }{account, customer, fee, usage, inventory, coupon, invoice, obligations})
	if err != nil {
		return VerifiedProviderPair{}, err
	}
	result.seal = pairSeal(result)
	return result, nil
}

func validateInitialPairSubscriptions(p ProviderPairVerificationInput, fee, usage invoiceSubscription) error {
	for step, sub := range map[string]invoiceSubscription{"fee": fee, "usage": usage} {
		if sub.Customer != p.CustomerID || sub.LiveMode != p.Identity.Live || sub.Status != "active" || sub.BillingMode.Type != "flexible" || sub.CollectionMethod != "charge_automatically" || sub.StartDate != p.Anchor.Unix() || sub.BillingCycleAnchor != p.Anchor.Unix() || sub.Items.HasMore || sub.AutomaticTax.Enabled || sub.BillingThresholds != nil || sub.TrialStart != 0 || sub.TrialEnd != 0 || sub.PendingUpdate != nil || sub.CancelAt != 0 || sub.CancelAtPeriodEnd || sub.Schedule != "" || !emptyPairSchedules(sub.BillingSchedules) {
			return fmt.Errorf("initial %s subscription calendar or collection terms differ", step)
		}
		if err := requirePairMetadata(sub.Metadata, p.Identity, step); err != nil {
			return err
		}
		if len(sub.DefaultTaxRates) != 0 {
			return errors.New("paired subscription has unsupported manual taxes")
		}
		for _, item := range sub.Items.Data {
			if len(item.TaxRates) != 0 || len(item.Discounts) != 0 {
				return errors.New("paired item has unsupported tax or discount modifiers")
			}
		}
	}
	if fee.ID != p.FeeSubscriptionID || usage.ID != p.UsageSubscriptionID || fee.PauseCollection != nil || fee.LatestInvoice != p.WaiverInvoiceID || len(fee.Items.Data) != 1 || len(fee.Discounts) > 1 || usage.PauseCollection == nil || usage.PauseCollection.Behavior != "keep_as_draft" || usage.PauseCollection.ResumesAt != 0 || len(usage.Discounts) != 0 {
		return errors.New("initial pair fee or usage hold differs")
	}
	i := fee.Items.Data[0]
	if !i.Price.Active {
		return errors.New("initial fee price is inactive")
	}
	if err := validatePairFeeItem(p.Terms, p.Identity.Live, i); err != nil {
		return err
	}
	if i.ID != p.FeeItemID || i.Start != p.Anchor.Unix() || i.End != annualBoundary(p.Anchor, 12).Unix() {
		return errors.New("initial licensed item identity or annual window differs")
	}
	all := append(append([]StripeCheckoutResourceTerms{}, p.Terms.Resources...), p.Terms.Rounding)
	if err := validateFrozenProResources(usage, all, ""); err != nil {
		return err
	}
	for _, item := range usage.Items.Data {
		if item.ID == "" || item.Price.LiveMode != p.Identity.Live || !item.Price.Active || item.Start != p.Anchor.Unix() || item.End != annualBoundary(p.Anchor, 1).Unix() {
			return errors.New("initial usage item calendar or mode differs")
		}
	}
	return nil
}

func (c *stripeHTTPClient) verifyInitialPairObligations(ctx context.Context, p ProviderPairVerificationInput, usageInvoice string) (json.RawMessage, error) {
	var pending struct {
		Data    []json.RawMessage `json:"data"`
		HasMore bool              `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoiceitems?"+url.Values{"customer": {p.CustomerID}, "pending": {"true"}, "limit": {"100"}}.Encode(), nil, &pending, ""); err != nil {
		return nil, err
	}
	if pending.HasMore || len(pending.Data) != 0 {
		return nil, errors.New("initial pair has pending invoice items")
	}
	var invoices struct {
		Data    []proPaidInvoice `json:"data"`
		HasMore bool             `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {p.CustomerID}, "limit": {"100"}}.Encode(), nil, &invoices, ""); err != nil {
		return nil, err
	}
	if invoices.HasMore {
		return nil, errors.New("initial pair invoice inventory is incomplete")
	}
	seen := map[string]bool{}
	for _, inv := range invoices.Data {
		if seen[inv.ID] || inv.Customer != p.CustomerID || inv.LiveMode != p.Identity.Live || inv.Total != 0 || inv.AmountDue != 0 || inv.AmountPaid != 0 || inv.AmountRemaining != 0 || inv.Parent.SubscriptionDetails == nil {
			return nil, errors.New("initial pair has an unexpected invoice obligation")
		}
		seen[inv.ID] = true
		if inv.ID == p.WaiverInvoiceID && inv.Parent.SubscriptionDetails.Subscription == p.FeeSubscriptionID && inv.Status == "paid" {
			continue
		}
		if inv.ID == "" || inv.ID != usageInvoice || inv.Parent.SubscriptionDetails.Subscription != p.UsageSubscriptionID || inv.Status != "paid" && (inv.Status != "draft" || inv.AutoAdvance) {
			return nil, errors.New("initial pair has an unrelated invoice")
		}
	}
	if !seen[p.WaiverInvoiceID] || usageInvoice != "" && !seen[usageInvoice] {
		return nil, errors.New("initial pair invoice inventory is missing its original invoice")
	}
	return json.Marshal(struct{ Pending, Invoices any }{pending, invoices})
}

func emptyPairSchedules(b json.RawMessage) bool {
	s := strings.TrimSpace(string(b))
	return s == "" || s == "null" || s == "[]"
}

func validatePairFeeItem(t ProviderPairTerms, live bool, i invoiceSubscriptionItem) error {
	p := i.Price
	interval := "month"
	if t.FeeMonths == 12 {
		interval = "year"
	}
	if i.ID == "" || i.Quantity != 1 || p.ID != t.FeePriceID || p.Product != t.FeeProductID || p.LiveMode != live || p.Currency != t.Currency || p.BillingScheme != "per_unit" || p.TransformQuantity != nil || p.UnitAmountDecimal != fmt.Sprint(t.FeeAmount) || p.Recurring.UsageType != "licensed" || p.Recurring.Meter != "" || p.Recurring.Interval != interval || p.Recurring.IntervalCount != 1 {
		return errors.New("paired licensed item differs from frozen provider terms")
	}
	return nil
}

func validatePairWaiverInvoice(p ProviderPairVerificationInput, inv proPaidInvoice) error {
	if inv.ID != p.WaiverInvoiceID || inv.Customer != p.CustomerID || inv.LiveMode != p.Identity.Live || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != p.FeeSubscriptionID || inv.Status != "paid" || inv.BillingReason != "subscription_create" || inv.Currency != "usd" || inv.Subtotal != p.Terms.FeeAmount || inv.Total != 0 || inv.AmountDue != 0 || inv.AmountPaid != 0 || inv.AmountRemaining != 0 || inv.PaidOutOfBand || inv.StartingBalance != 0 || inv.EndingBalance == nil || *inv.EndingBalance != 0 || len(inv.Taxes) != 0 || inv.AmountShipping != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 || inv.Lines.HasMore || len(inv.Lines.Data) != 1 || len(inv.Discounts) != 1 || inv.Discounts[0].Coupon != p.WaiverCouponID || len(inv.DiscountAmounts) != 1 || inv.DiscountAmounts[0].Amount != p.Terms.FeeAmount {
		return errors.New("initial invoice does not prove exact zero-cash annual waiver")
	}
	l := inv.Lines.Data[0]
	if l.Parent.SubscriptionItemDetails == nil || l.Parent.SubscriptionItemDetails.Subscription != p.FeeSubscriptionID || l.Parent.SubscriptionItemDetails.SubscriptionItem != p.FeeItemID || l.Parent.SubscriptionItemDetails.Proration || l.Pricing.PriceDetails == nil || l.Pricing.PriceDetails.Price != p.Terms.FeePriceID || l.Pricing.PriceDetails.Product != p.Terms.FeeProductID || l.Amount != p.Terms.FeeAmount || l.Currency != "usd" || l.Quantity != 1 || l.Period.Start != p.Anchor.Unix() || l.Period.End != annualBoundary(p.Anchor, 12).Unix() {
		return errors.New("initial waiver invoice line differs from pinned annual fee")
	}
	for _, credit := range append(append([]StripeInvoicePretaxCredit{}, inv.PretaxCredits...), l.PretaxCredits...) {
		if credit.Type != "discount" || credit.CreditBalanceTransaction != "" || credit.Amount != p.Terms.FeeAmount {
			return errors.New("initial fee waiver consumed unsupported credits")
		}
	}
	return nil
}
