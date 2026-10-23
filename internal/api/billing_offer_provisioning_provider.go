package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

// The client is captured once, so preflight and dispatch cannot use different
// credentials after a configuration rotation. Runtime registration is separate.
type offerProvisioningProvider struct{ client *stripeHTTPClient }

var _ provisioning.Provider = (*offerProvisioningProvider)(nil)

type offerProviderReceipt struct {
	ID      string `json:"id"`
	Item    string `json:"item,omitempty"`
	Invoice string `json:"invoice,omitempty"`
	Anchor  int64  `json:"anchor,omitempty"`
}

func offerPairInput(o provisioning.Operation) (ProviderPairVerificationInput, error) {
	p := ProviderPairVerificationInput{}
	var snapshot struct {
		Team       uuid.UUID `json:"team_id"`
		Assignment uuid.UUID `json:"assignment_id"`
		Acceptance uuid.UUID `json:"acceptance_id"`
		Revision   *int64    `json:"approval_revision"`
	}
	if json.Unmarshal(o.Offer.Snapshot, &snapshot) != nil || snapshot.Revision == nil || *snapshot.Revision < 0 || snapshot.Team != o.TeamID || snapshot.Assignment != o.AssignmentID || snapshot.Acceptance != o.Offer.AcceptanceID || o.ID == uuid.Nil || o.TeamID == uuid.Nil || o.AssignmentID == uuid.Nil || o.Offer.AcceptanceID == uuid.Nil || !validPairDigest(o.Offer.TermsDigest) || o.Offer.Merchant == "" || o.Offer.APIVersion == "" || json.Unmarshal(o.Offer.ProviderTerms, &p.Terms) != nil {
		return p, provisioning.ErrConflict
	}
	digest, err := p.Terms.Digest()
	if err != nil || p.Terms.FeeAmount != 1200000 || p.Terms.FeeMonths != 12 {
		return p, provisioning.ErrConflict
	}
	p.Identity = ProviderPairIdentity{OperationID: o.ID, TeamID: o.TeamID, AssignmentID: o.AssignmentID, AcceptanceID: o.Offer.AcceptanceID, ApprovalSemanticRevision: *snapshot.Revision, TermsDigest: o.Offer.TermsDigest, ProviderTermsDigest: digest, Merchant: o.Offer.Merchant, Live: o.Offer.Live, APIVersion: o.Offer.APIVersion}
	for step, r := range o.Requests {
		if r.State != "confirmed" {
			continue
		}
		var receipt offerProviderReceipt
		if json.Unmarshal(r.Receipt, &receipt) != nil || receipt.ID == "" {
			return p, provisioning.ErrConflict
		}
		switch step {
		case provisioning.Customer:
			p.CustomerID = receipt.ID
		case provisioning.Waiver:
			p.WaiverCouponID = receipt.ID
		case provisioning.Fee:
			p.FeeSubscriptionID, p.FeeItemID, p.WaiverInvoiceID, p.Anchor = receipt.ID, receipt.Item, receipt.Invoice, time.Unix(receipt.Anchor, 0).UTC()
		case provisioning.Usage:
			p.UsageSubscriptionID = receipt.ID
		}
	}
	return p, nil
}

func (p *offerProvisioningProvider) Prepare(_ context.Context, o provisioning.Operation, step provisioning.Step) (provisioning.Request, error) {
	input, err := offerPairInput(o)
	if err != nil {
		return provisioning.Request{}, err
	}
	form := url.Values{}
	path := "/v1/subscriptions"
	for k, v := range pairMetadata(input.Identity, string(step)) {
		form.Set("metadata["+k+"]", v)
	}
	switch step {
	case provisioning.Customer:
		path = "/v1/customers"
	case provisioning.Waiver:
		path = "/v1/coupons"
		form.Set("id", "offer_"+o.ID.String())
		form.Set("duration", "once")
		form.Set("percent_off", "100")
		form.Set("applies_to[products][0]", input.Terms.FeeProductID)
		form.Set("expand[]", "applies_to")
	case provisioning.Fee, provisioning.Usage:
		if input.CustomerID == "" {
			return provisioning.Request{}, provisioning.ErrConflict
		}
		form.Set("customer", input.CustomerID)
		form.Set("billing_mode[type]", "flexible")
		form.Set("collection_method", "charge_automatically")
		form.Set("payment_behavior", "error_if_incomplete")
		form.Set("proration_behavior", "none")
		form.Set("automatic_tax[enabled]", "false")
		if step == provisioning.Fee {
			if input.WaiverCouponID == "" {
				return provisioning.Request{}, provisioning.ErrConflict
			}
			form.Set("items[0][price]", input.Terms.FeePriceID)
			form.Set("items[0][quantity]", "1")
			form.Set("discounts[0][coupon]", input.WaiverCouponID)
		} else {
			if input.FeeSubscriptionID == "" || input.Anchor.Unix() <= 0 {
				return provisioning.Request{}, provisioning.ErrConflict
			}
			form.Set("backdate_start_date", strconv.FormatInt(input.Anchor.Unix(), 10))
			for i, r := range append(append([]StripeCheckoutResourceTerms{}, input.Terms.Resources...), input.Terms.Rounding) {
				form.Set(fmt.Sprintf("items[%d][price]", i), r.PriceID)
			}
		}
	case provisioning.UsageHold:
		if !offerUsageHoldPath.MatchString("/v1/subscriptions/" + input.UsageSubscriptionID) {
			return provisioning.Request{}, provisioning.ErrConflict
		}
		path += "/" + input.UsageSubscriptionID
		// Preserve the usage creation correlation; the hold is its own journal step.
		form = url.Values{"pause_collection[behavior]": {"keep_as_draft"}, "proration_behavior": {"none"}}
	default:
		return provisioning.Request{}, provisioning.ErrConflict
	}
	return provisioning.NewRequest(path, form.Encode()), nil
}

func (p *offerProvisioningProvider) Preflight(ctx context.Context, r provisioning.SavedRequest) error {
	if err := p.client.preflightOfferProviderRequest(ctx, r); err != nil {
		return err
	}
	// Price checks are reads and remain retryable before dispatch commitment.
	input, err := offerRequestInput(r)
	if err != nil {
		return err
	}
	h := Handlers{Stripe: p.client}
	if err = h.VerifyProviderPairTerms(ctx, input.Identity, input.Terms); err != nil {
		return provisioning.ErrConflict
	}
	return nil
}

func offerRequestInput(r provisioning.SavedRequest) (ProviderPairVerificationInput, error) {
	var snapshot struct {
		Team       uuid.UUID `json:"team_id"`
		Assignment uuid.UUID `json:"assignment_id"`
	}
	if json.Unmarshal(r.Offer.Snapshot, &snapshot) != nil {
		return ProviderPairVerificationInput{}, provisioning.ErrConflict
	}
	return offerPairInput(provisioning.Operation{ID: r.OperationID, TeamID: snapshot.Team, AssignmentID: snapshot.Assignment, Offer: r.Offer})
}

func (p *offerProvisioningProvider) Create(ctx context.Context, r provisioning.SavedRequest) (json.RawMessage, error) {
	raw, err := p.client.sendOfferProviderRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	return projectOfferProviderReceipt(r, raw)
}

// Only minimal identity/calendar evidence is persisted. Full provider inventory
// and economics are verified afresh before any local activation transaction.
func projectOfferProviderReceipt(r provisioning.SavedRequest, raw json.RawMessage) (json.RawMessage, error) {
	input, err := offerRequestInput(r)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(r.Request.Payload)
	if err != nil {
		return nil, provisioning.ErrConflict
	}
	var obj struct {
		ID       string            `json:"id"`
		Live     *bool             `json:"livemode"`
		Deleted  bool              `json:"deleted"`
		Metadata map[string]string `json:"metadata"`
	}
	if json.Unmarshal(raw, &obj) != nil || obj.ID == "" || obj.Live == nil || *obj.Live != r.Offer.Live || obj.Deleted {
		return nil, provisioning.ErrUnknown
	}
	step := string(r.Step)
	if r.Step == provisioning.UsageHold {
		step = string(provisioning.Usage)
	}
	if requirePairMetadata(obj.Metadata, input.Identity, step) != nil {
		return nil, provisioning.ErrUnknown
	}
	receipt := offerProviderReceipt{ID: obj.ID}
	switch r.Step {
	case provisioning.Customer:
		if !strings.HasPrefix(obj.ID, "cus_") {
			return nil, provisioning.ErrUnknown
		}
	case provisioning.Waiver:
		var coupon struct {
			Duration string          `json:"duration"`
			Percent  json.RawMessage `json:"percent_off"`
			Amount   *int64          `json:"amount_off"`
			Applies  struct {
				Products []string `json:"products"`
			} `json:"applies_to"`
		}
		if json.Unmarshal(raw, &coupon) != nil {
			return nil, provisioning.ErrUnknown
		}
		percent, err := meterDecimal(string(coupon.Percent))
		if err != nil || percent.Cmp(big.NewRat(100, 1)) != 0 || obj.ID != form.Get("id") || coupon.Duration != "once" || coupon.Amount != nil || len(coupon.Applies.Products) != 1 || coupon.Applies.Products[0] != input.Terms.FeeProductID {
			return nil, provisioning.ErrUnknown
		}
	case provisioning.Fee, provisioning.Usage, provisioning.UsageHold:
		var sub invoiceSubscription
		if json.Unmarshal(raw, &sub) != nil || !strings.HasPrefix(sub.ID, "sub_") || sub.Status != "active" || sub.Items.HasMore || sub.StartDate <= 0 || sub.StartDate != sub.BillingCycleAnchor {
			return nil, provisioning.ErrUnknown
		}
		if r.Step == provisioning.UsageHold {
			if r.Request.Path != "/v1/subscriptions/"+sub.ID || sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 {
				return nil, provisioning.ErrUnknown
			}
		} else if sub.Customer != form.Get("customer") {
			return nil, provisioning.ErrUnknown
		}
		if r.Step == provisioning.Fee {
			if len(sub.Items.Data) != 1 || validatePairFeeItem(input.Terms, r.Offer.Live, sub.Items.Data[0]) != nil || sub.Items.Data[0].Start != sub.StartDate || sub.Items.Data[0].End != annualBoundary(time.Unix(sub.StartDate, 0).UTC(), 12).Unix() || !strings.HasPrefix(sub.LatestInvoice, "in_") {
				return nil, provisioning.ErrUnknown
			}
			receipt.Item, receipt.Invoice, receipt.Anchor = sub.Items.Data[0].ID, sub.LatestInvoice, sub.StartDate
		} else {
			if validateFrozenProResources(sub, append(append([]StripeCheckoutResourceTerms{}, input.Terms.Resources...), input.Terms.Rounding), "") != nil {
				return nil, provisioning.ErrUnknown
			}
			if r.Step == provisioning.Usage && strconv.FormatInt(sub.StartDate, 10) != form.Get("backdate_start_date") {
				return nil, provisioning.ErrUnknown
			}
		}
	default:
		return nil, provisioning.ErrConflict
	}
	return json.Marshal(receipt)
}

func (p *offerProvisioningProvider) Recover(ctx context.Context, r provisioning.SavedRequest) (json.RawMessage, error) {
	if r.State != "dispatched" || r.DispatchedAt == nil {
		return nil, provisioning.ErrConflict
	}
	// Reuse identity preflight with a copy; never alter the durable dispatch state.
	check := r
	check.State = "prepared"
	check.DispatchedAt = nil
	if err := p.client.preflightOfferProviderRequest(ctx, check); err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(r.Request.Payload)
	if err != nil {
		return nil, provisioning.ErrConflict
	}
	path := ""
	switch r.Step {
	case provisioning.Waiver:
		// Scope is omitted by default. Read it without changing the saved POST.
		path = "/v1/coupons/" + url.PathEscape(form.Get("id")) + "?" + url.Values{"expand[]": {"applies_to"}}.Encode()
	case provisioning.UsageHold:
		path = r.Request.Path
	}
	if path != "" {
		raw, e := p.client.offerProviderHTTP(ctx, http.MethodGet, path, "", "", r.Offer.APIVersion)
		if e != nil {
			return nil, e
		}
		return projectOfferProviderReceipt(r, raw)
	}
	path = "/v1/subscriptions"
	query := url.Values{"limit": {"100"}, "customer": {form.Get("customer")}, "status": {"all"}}
	if r.Step == provisioning.Customer {
		path = "/v1/customers"
		query = url.Values{"limit": {"100"}}
	}
	var found json.RawMessage
	seen := map[string]bool{}
	// Search is eventually consistent. Use complete bounded list pagination;
	// inability to establish completeness leaves the original dispatch unknown.
	for page := 0; page < 20; page++ {
		raw, e := p.client.offerProviderHTTP(ctx, http.MethodGet, path+"?"+query.Encode(), "", "", r.Offer.APIVersion)
		if e != nil {
			return nil, e
		}
		var list struct {
			Data []json.RawMessage `json:"data"`
			More *bool             `json:"has_more"`
		}
		if json.Unmarshal(raw, &list) != nil || list.More == nil || list.Data == nil {
			return nil, provisioning.ErrUnknown
		}
		last := ""
		for _, obj := range list.Data {
			var id struct {
				ID       string            `json:"id"`
				Metadata map[string]string `json:"metadata"`
			}
			if json.Unmarshal(obj, &id) != nil || id.ID == "" || seen[id.ID] {
				return nil, provisioning.ErrUnknown
			}
			seen[id.ID] = true
			last = id.ID
			if id.Metadata["operation_id"] == r.OperationID.String() && id.Metadata["step"] == string(r.Step) {
				if found != nil {
					return nil, provisioning.ErrUnknown
				}
				found = obj
			}
		}
		if !*list.More {
			if found == nil {
				return nil, provisioning.ErrUnknown
			}
			return projectOfferProviderReceipt(r, found)
		}
		if last == "" {
			return nil, provisioning.ErrUnknown
		}
		query.Set("starting_after", last)
	}
	return nil, provisioning.ErrUnknown
}

func (p *offerProvisioningProvider) Verify(ctx context.Context, o provisioning.Operation) (provisioning.Verification, error) {
	input, err := offerPairInput(o)
	if err != nil {
		return provisioning.Verification{}, err
	}
	for _, step := range []provisioning.Step{provisioning.Customer, provisioning.Waiver, provisioning.Fee, provisioning.Usage, provisioning.UsageHold} {
		if o.Requests[step].State != "confirmed" {
			return provisioning.Verification{}, provisioning.ErrUnknown
		}
	}
	var held offerProviderReceipt
	if json.Unmarshal(o.Requests[provisioning.UsageHold].Receipt, &held) != nil || held.ID != input.UsageSubscriptionID {
		return provisioning.Verification{}, provisioning.ErrConflict
	}
	v, err := p.client.verifyInitialProviderPair(ctx, input)
	if err != nil {
		return provisioning.Verification{}, provisioning.ErrUnknown
	}
	return provisioning.Verification{Evidence: v.Evidence, Proof: v}, nil
}
