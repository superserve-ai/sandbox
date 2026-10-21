package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func renewalSuccessorID(k renewalChoiceKey) uuid.UUID {
	return uuid.NewSHA1(k.Assignment, []byte(k.Team.String()+"/"+k.Boundary.UTC().Format(time.RFC3339)))
}
func renewalTargetDigest(k renewalChoiceKey, op renewalChoiceOperation) string {
	k.Boundary = k.Boundary.UTC()
	return renewalHash(struct {
		Key       renewalChoiceKey
		Successor uuid.UUID
		Choice    string
		Binding   renewalChoiceBinding
		Terms     *renewalChoiceTerms
	}{k, renewalSuccessorID(k), op.Request.Choice, op.Binding, op.Terms})
}
func renewalSuccessorBinding(k renewalChoiceKey, op renewalChoiceOperation, previous ContractProviderBinding, feeItem string) (ContractProviderBinding, error) {
	if op.Request.Choice == "free" || validateRenewalTerms(op.Request.Choice, op.Terms) != nil || previous.EndsAt == nil || !previous.EndsAt.Equal(k.Boundary) || renewalHash(renewalChoiceBindingFromPair(previous)) != renewalHash(op.Binding) || feeItem == "" {
		return ContractProviderBinding{}, errRenewalConflict
	}
	next := previous
	next.ContractID = renewalSuccessorID(k)
	next.Identity.OperationID = next.ContractID
	next.Identity.TermsDigest = renewalTargetDigest(k, op)
	next.StartsAt, next.EndsAt, next.FeeItemID = k.Boundary, nil, feeItem
	next.Terms.FeePriceID, next.Terms.FeeProductID, next.Terms.FeeAmount, next.Terms.FeeMonths = op.Terms.Price, op.Terms.Product, op.Terms.Amount, int32(op.Terms.Months)
	if op.Request.Choice == "monthly" {
		next.FeeAnchor = k.Boundary
	}
	var err error
	next.Identity.ProviderTermsDigest, err = next.Terms.Digest()
	if err != nil {
		return next, err
	}
	return next, validatePairSuccessor(previous, next)
}

type renewalFeeInventory struct {
	Data    []proPaidInvoice `json:"data"`
	HasMore bool             `json:"has_more"`
}

func (c *stripeHTTPClient) renewalFeeInvoices(ctx context.Context, b ContractProviderBinding) (renewalFeeInventory, error) {
	var list renewalFeeInventory
	err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {b.CustomerID}, "subscription": {b.FeeSubscriptionID}, "limit": {"100"}}.Encode(), nil, &list, "")
	if err != nil {
		return list, err
	}
	if list.HasMore {
		return list, errRenewalPending
	}
	seen := map[string]bool{}
	for _, inv := range list.Data {
		if inv.ID == "" || seen[inv.ID] || inv.Customer != b.CustomerID || inv.LiveMode != b.Identity.Live || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != b.FeeSubscriptionID || inv.Lines.HasMore {
			return list, errRenewalConflict
		}
		seen[inv.ID] = true
	}
	return list, nil
}

func (v *stripeRenewalScheduleVerifier) observeBoundary(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if time.Now().UTC().Before(k.Boundary) {
		return renewalChoiceProof{}, errRenewalPending
	}
	previous, owned, err := v.binding(ctx, k, op)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	if op.Request.Choice == "free" {
		return v.observeFreeBoundary(ctx, k, op, previous, owned)
	}
	fee, err := v.Client.invoiceSubscription(ctx, previous.FeeSubscriptionID)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	if err = validatePairFeeSibling(previous, fee); err != nil {
		return renewalChoiceProof{}, err
	}
	next, err := renewalSuccessorBinding(k, op, previous, fee.Items.Data[0].ID)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	inventory, err := v.Client.renewalFeeInvoices(ctx, next)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	invoice := ""
	for _, inv := range inventory.Data {
		boundaryLine := false
		for _, line := range inv.Lines.Data {
			if line.Period.Start == k.Boundary.Unix() {
				boundaryLine = true
			}
		}
		if !boundaryLine {
			continue
		}
		if invoice != "" || validatePairSuccessorInvoice(next, inv.ID, inv) != nil {
			return renewalChoiceProof{}, errRenewalConflict
		}
		invoice = inv.ID
	}
	if invoice == "" {
		return renewalChoiceProof{}, errRenewalPending
	}
	verified, err := v.Client.verifySuccessorProviderPair(ctx, previous, next, invoice)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	evidence, _ := json.Marshal(map[string]any{"source": "verified_boundary_pair", "pair": verified.AuditEvidence(), "fee_inventory": inventory})
	proof := renewalChoiceProof{Operation: op.ID, Boundary: k.Boundary, BindingHash: renewalHash(op.Binding), TermsHash: renewalHash(op.Terms), Outcome: "confirmed", Timing: "boundary_history", VerifiedAt: verified.VerifiedAt, Evidence: evidence}
	proof.successor = &verified
	return proof, nil
}

func (v *stripeRenewalScheduleVerifier) observeFreeBoundary(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, b ContractProviderBinding, owned *renewalChoiceOwnedSchedule) (renewalChoiceProof, error) {
	if owned == nil || len(op.Steps) == 0 {
		return renewalChoiceProof{}, errRenewalPending
	}
	step := op.Steps[len(op.Steps)-1]
	if step.Request.Kind != "update_schedule" || step.Request.Schedule != owned.Proof.Schedule || step.Proof == nil || step.Proof.RequestHash != renewalHash(step.Request) {
		return renewalChoiceProof{}, errRenewalPending
	}
	// Recovery retains the original request receipt separately from the later
	// boundary observation, so a restart can still prove cancellation was timely.
	original := step.Proof.OriginalChoice
	if original == nil {
		original = step.Proof.Choice
	}
	if original == nil || original.Outcome != "confirmed" || original.Timing != "future_configuration" || !original.VerifiedAt.Before(k.Boundary) || validateRenewalProof(k, op, *original, original.VerifiedAt) != nil {
		return renewalChoiceProof{}, errRenewalPending
	}
	if err := (&Handlers{Stripe: v.Client}).VerifyProviderPairTerms(ctx, b.Identity, b.Terms); err != nil {
		return renewalChoiceProof{}, err
	}
	fee, err := v.Client.invoiceSubscription(ctx, b.FeeSubscriptionID)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	usage, err := v.Client.invoiceSubscription(ctx, b.UsageSubscriptionID)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	if validatePairFeeSibling(b, fee) != nil || fee.Status != "canceled" || fee.EndedAt != k.Boundary.Unix() || fee.BillingCycleAnchor != b.Anchor.Unix() || fee.StartDate != b.Anchor.Unix() || fee.Items.Data[0].ID != b.FeeItemID || validatePairFeeItem(b.Terms, b.Identity.Live, fee.Items.Data[0]) != nil || fee.Items.Data[0].End != k.Boundary.Unix() || fee.Schedule != "" || fee.PendingUpdate != nil {
		return renewalChoiceProof{}, errRenewalConflict
	}
	account := invoiceAccount{Customer: b.CustomerID, Subscription: b.UsageSubscriptionID, Price: b.Terms.Rounding.PriceID, Meter: b.Terms.Rounding.MeterID, Event: b.Terms.Rounding.EventName}
	if validatePairUsageSubscription(b, account, usage) != nil || usage.Status != "active" || usage.PauseCollection == nil || usage.PauseCollection.Behavior != "keep_as_draft" || usage.PauseCollection.ResumesAt != 0 || usage.Schedule != "" || !emptyPairSchedules(usage.BillingSchedules) {
		return renewalChoiceProof{}, errRenewalConflict
	}
	var subs struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = v.Client.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {b.CustomerID}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &subs, ""); err != nil {
		return renewalChoiceProof{}, err
	}
	if subs.HasMore || len(subs.Data) != 2 {
		return renewalChoiceProof{}, errRenewalConflict
	}
	seen := map[string]bool{}
	for _, sub := range subs.Data {
		if seen[sub.ID] || sub.Customer != b.CustomerID || sub.LiveMode != b.Identity.Live || (sub.ID != b.FeeSubscriptionID && sub.ID != b.UsageSubscriptionID) {
			return renewalChoiceProof{}, errRenewalConflict
		}
		seen[sub.ID] = true
	}
	invoices, err := v.Client.renewalFeeInvoices(ctx, b)
	if err != nil {
		return renewalChoiceProof{}, err
	}
	var raw []byte
	if err = v.Pool.QueryRow(ctx, `SELECT evidence FROM billing_contract_provider_binding WHERE contract_id=$1 AND team_id=$2`, b.ContractID, k.Team).Scan(&raw); err != nil {
		return renewalChoiceProof{}, err
	}
	var saved struct{ Invoice proPaidInvoice }
	if json.Unmarshal(raw, &saved) != nil || len(invoices.Data) != 1 || invoices.Data[0].ID != saved.Invoice.ID {
		return renewalChoiceProof{}, errRenewalConflict
	}
	if _, err = renewalVerifiedWaiver(b, raw, fee.Discounts); err != nil {
		return renewalChoiceProof{}, err
	}
	evidence, _ := json.Marshal(map[string]any{"source": "verified_boundary_cancellation", "fee": fee, "usage": usage, "invoices": invoices, "original_update": step.Proof.Evidence})
	return renewalChoiceProof{Operation: op.ID, Boundary: k.Boundary, BindingHash: renewalHash(op.Binding), TermsHash: renewalHash(op.Terms), Outcome: "confirmed", Timing: "boundary_history", VerifiedAt: time.Now().UTC(), Evidence: evidence}, nil
}
