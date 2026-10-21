package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type stripeRenewalScheduleVerifier struct {
	Pool   *pgxpool.Pool
	Client *stripeHTTPClient
}

func (v *stripeRenewalScheduleVerifier) binding(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (ContractProviderBinding, *renewalChoiceOwnedSchedule, error) {
	if v == nil || v.Pool == nil || v.Client == nil || v.Client.apiVersion != renewalStripeVersion {
		return ContractProviderBinding{}, nil, errRenewalDisabled
	}
	key, binding, err := loadRenewalChoicePair(ctx, v.Pool, k.Team, k.Assignment)
	if err != nil {
		return binding, nil, err
	}
	if !key.Boundary.Equal(k.Boundary) || renewalHash(renewalChoiceBindingFromPair(binding)) != renewalHash(op.Binding) {
		return binding, nil, errRenewalConflict
	}
	var raw []byte
	if err = v.Pool.QueryRow(ctx, `SELECT COALESCE(snapshot->'owned_schedule','null'::jsonb) FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3`, k.Team, k.Assignment, k.Boundary).Scan(&raw); err != nil {
		return binding, nil, err
	}
	var owned *renewalChoiceOwnedSchedule
	if json.Unmarshal(raw, &owned) != nil {
		return binding, nil, errRenewalConflict
	}
	if owned != nil {
		original := renewalChoiceOperation{ID: owned.Operation, Binding: op.Binding}
		form, parseErr := url.ParseQuery(owned.Request.Form)
		if parseErr != nil || !validRenewalStep(original, owned.Request) || owned.Request.Kind != "create_schedule" || len(form) != 1 || form.Get("from_subscription") != binding.FeeSubscriptionID || owned.Proof.Outcome != "confirmed" || owned.Proof.RequestHash != renewalHash(owned.Request) || owned.Proof.BindingHash != renewalHash(op.Binding) || owned.Proof.Schedule == "" {
			return binding, nil, errRenewalConflict
		}
	}
	return binding, owned, nil
}

// All reads happen outside journal transactions and the dispatch-only guard.
// The inherited pair verifier owns merchant, price and usage-item validation.
func (v *stripeRenewalScheduleVerifier) Inspect(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalScheduleSnapshot, error) {
	var snapshot renewalScheduleSnapshot
	if !time.Now().UTC().Before(k.Boundary) {
		return snapshot, errRenewalPending
	}
	b, owned, err := v.binding(ctx, k, op)
	if err != nil {
		return snapshot, err
	}
	if err = (&Handlers{Stripe: v.Client}).VerifyProviderPairTerms(ctx, b.Identity, b.Terms); err != nil {
		return snapshot, err
	}
	if err = validateRenewalTerms(op.Request.Choice, op.Terms); err != nil {
		return snapshot, err
	}
	if op.Request.Choice == "monthly" {
		target, identity := b.Terms, b.Identity
		target.FeePriceID, target.FeeProductID, target.FeeAmount, target.FeeMonths = op.Terms.Price, op.Terms.Product, op.Terms.Amount, int32(op.Terms.Months)
		identity.ProviderTermsDigest, err = target.Digest()
		if err != nil {
			return snapshot, err
		}
		if err = (&Handlers{Stripe: v.Client}).VerifyProviderPairTerms(ctx, identity, target); err != nil {
			return snapshot, err
		}
	}
	fee, err := v.Client.invoiceSubscription(ctx, b.FeeSubscriptionID)
	if err != nil {
		return snapshot, err
	}
	usage, err := v.Client.invoiceSubscription(ctx, b.UsageSubscriptionID)
	if err != nil {
		return snapshot, err
	}
	if err = validatePairFeeSibling(b, fee); err != nil {
		return snapshot, err
	}
	if err = validatePairFeeItem(b.Terms, b.Identity.Live, fee.Items.Data[0]); err != nil {
		return snapshot, err
	}
	if len(fee.Items.Data[0].Discounts) != 0 || len(fee.Items.Data[0].TaxRates) != 0 {
		return snapshot, errRenewalConflict
	}
	var originalEvidence []byte
	if err = v.Pool.QueryRow(ctx, `SELECT evidence FROM billing_contract_provider_binding WHERE contract_id=$1 AND team_id=$2`, b.ContractID, k.Team).Scan(&originalEvidence); err != nil {
		return snapshot, err
	}
	waiver, err := renewalVerifiedWaiver(b, originalEvidence, fee.Discounts)
	if err != nil {
		return snapshot, errRenewalConflict
	}
	a := invoiceAccount{Customer: b.CustomerID, Subscription: b.UsageSubscriptionID, Price: b.Terms.Rounding.PriceID, Meter: b.Terms.Rounding.MeterID, Event: b.Terms.Rounding.EventName}
	if err = validatePairUsageSubscription(b, a, usage); err != nil {
		return snapshot, err
	}
	if fee.Status != "active" || fee.BillingMode.Type != "flexible" || fee.CollectionMethod != "charge_automatically" || fee.StartDate != b.Anchor.Unix() || fee.BillingCycleAnchor != b.Anchor.Unix() || fee.Items.Data[0].ID != b.FeeItemID || fee.Items.Data[0].Start != b.Anchor.Unix() || fee.Items.Data[0].End != k.Boundary.Unix() || fee.PauseCollection != nil || fee.PendingUpdate != nil || fee.TrialEnd != 0 || fee.AutomaticTax.Enabled || len(fee.DefaultTaxRates) != 0 || fee.BillingThresholds != nil || !emptyPairSchedules(fee.BillingSchedules) || usage.Status != "active" || usage.BillingMode.Type != "flexible" || usage.PauseCollection == nil || usage.PauseCollection.Behavior != "keep_as_draft" || usage.PauseCollection.ResumesAt != 0 || usage.Schedule != "" || !emptyPairSchedules(usage.BillingSchedules) {
		return snapshot, errRenewalConflict
	}
	if requirePairMetadata(fee.Metadata, b.Identity, "fee") != nil || requirePairMetadata(usage.Metadata, b.Identity, "usage") != nil {
		return snapshot, errRenewalConflict
	}
	var inventory struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	if err = v.Client.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {b.CustomerID}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
		return snapshot, err
	}
	if inventory.HasMore || len(inventory.Data) != 2 {
		return snapshot, errRenewalConflict
	}
	seen := map[string]bool{}
	for _, sub := range inventory.Data {
		if seen[sub.ID] || (sub.ID != fee.ID && sub.ID != usage.ID) || sub.Customer != b.CustomerID || sub.LiveMode != b.Identity.Live {
			return snapshot, errRenewalConflict
		}
		seen[sub.ID] = true
	}
	snapshot = renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: b.Anchor, Boundary: k.Boundary}
	if fee.Schedule == "" {
		if owned != nil || fee.CancelAt != 0 || fee.CancelAtPeriodEnd {
			return renewalScheduleSnapshot{}, errRenewalPending
		}
		return snapshot, nil
	}
	if owned == nil || owned.Proof.Schedule != fee.Schedule {
		return renewalScheduleSnapshot{}, errRenewalPending
	}
	schedule, err := v.schedule(ctx, fee.Schedule)
	if err != nil {
		return renewalScheduleSnapshot{}, err
	}
	if schedule.Customer != b.CustomerID || schedule.Subscription != b.FeeSubscriptionID || schedule.Live != b.Identity.Live || schedule.Status != "active" || schedule.BillingMode.Type != "flexible" || schedule.Current.Start != b.Anchor.Unix() || schedule.Current.End != k.Boundary.Unix() || len(schedule.Phases) < 1 || len(schedule.Phases) > 2 || len(schedule.Pauses) != 0 || (len(schedule.RenewalInterval) != 0 && !renewalEmptySetting(schedule.RenewalInterval)) || validateRenewalScheduleDefaults(schedule.Defaults) != nil || (fee.CancelAt != 0 && fee.CancelAt != k.Boundary.Unix()) {
		return renewalScheduleSnapshot{}, errRenewalConflict
	}
	current, err := renewalSchedulePhaseForm(schedule.Phases[0], "phases[0]", "charge_automatically")
	if err != nil {
		return renewalScheduleSnapshot{}, err
	}
	if current.Get("phases[0][start_date]") != strconv.FormatInt(b.Anchor.Unix(), 10) || current.Get("phases[0][end_date]") != strconv.FormatInt(k.Boundary.Unix(), 10) || current.Get("phases[0][items][0][price]") != b.Terms.FeePriceID {
		return renewalScheduleSnapshot{}, errRenewalConflict
	}
	for name, values := range current {
		if strings.Contains(name, "[discounts]") && (len(values) != 1 || !((name == "phases[0][discounts][0][coupon]" && values[0] == waiver.Coupon) || (name == "phases[0][discounts][0][discount]" && values[0] == waiver.Discount))) {
			return renewalScheduleSnapshot{}, errRenewalConflict
		}
	}
	snapshot.Schedule, snapshot.Owned, snapshot.CurrentPhase = schedule.ID, true, current
	return snapshot, nil
}

type renewalWaiverIdentity struct{ Coupon, Discount string }

func renewalVerifiedWaiver(b ContractProviderBinding, raw []byte, discounts []string) (renewalWaiverIdentity, error) {
	var saved struct {
		Coupon  struct{ ID, Duration string }
		Invoice proPaidInvoice
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Coupon.ID == "" || saved.Coupon.Duration != "once" || len(saved.Invoice.Discounts) != 1 || saved.Invoice.Discounts[0].ID == "" {
		return renewalWaiverIdentity{}, errRenewalConflict
	}
	p := ProviderPairVerificationInput{Identity: b.Identity, Terms: b.Terms, CustomerID: b.CustomerID, FeeSubscriptionID: b.FeeSubscriptionID, UsageSubscriptionID: b.UsageSubscriptionID, FeeItemID: b.FeeItemID, Anchor: b.Anchor, WaiverCouponID: saved.Coupon.ID, WaiverInvoiceID: saved.Invoice.ID}
	if err := validatePairWaiverInvoice(p, saved.Invoice); err != nil {
		return renewalWaiverIdentity{}, err
	}
	if len(discounts) > 1 || (len(discounts) == 1 && discounts[0] != saved.Invoice.Discounts[0].ID) {
		return renewalWaiverIdentity{}, errRenewalConflict
	}
	return renewalWaiverIdentity{Coupon: saved.Coupon.ID, Discount: saved.Invoice.Discounts[0].ID}, nil
}

func (v *stripeRenewalScheduleVerifier) schedule(ctx context.Context, id string) (renewalScheduleObject, error) {
	var schedule renewalScheduleObject
	err := v.Client.doForm(ctx, http.MethodGet, "/v1/subscription_schedules/"+url.PathEscape(id), nil, &schedule, "")
	if err == nil && (schedule.ID != id || schedule.Object != "subscription_schedule") {
		err = errRenewalConflict
	}
	return schedule, err
}

func (v *stripeRenewalScheduleVerifier) ObserveStep(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, request renewalChoiceStepRequest) (renewalChoiceStepProof, error) {
	if request.Kind == "create_schedule" {
		if _, _, err := v.binding(ctx, k, op); err != nil {
			return renewalChoiceStepProof{}, err
		}
		return v.recoverEvent(ctx, k, op, request, time.Now().UTC())
	}
	if request.Kind != "update_schedule" {
		return renewalChoiceStepProof{}, errRenewalPending
	}
	if _, _, err := v.binding(ctx, k, op); err != nil {
		return renewalChoiceStepProof{}, err
	}
	original, err := v.recoverEvent(ctx, k, op, request, time.Now().UTC())
	if err != nil || original.Choice == nil {
		return renewalChoiceStepProof{}, errRenewalPending
	}
	if !time.Now().UTC().Before(k.Boundary) {
		// Only the exact original request event can settle a previously unknown
		// update. The historical pair then proves what actually began at B.
		observed := op
		observed.Steps = append([]renewalChoiceStep(nil), op.Steps...)
		if len(observed.Steps) > 0 {
			observed.Steps[len(observed.Steps)-1].Proof = &original
		}
		choice, err := v.observeBoundary(ctx, k, observed)
		if err != nil {
			return renewalChoiceStepProof{}, err
		}
		original.OriginalChoice = original.Choice
		original.Choice, original.VerifiedAt = &choice, choice.VerifiedAt
		return original, nil
	}
	snapshot, err := v.Inspect(ctx, k, op)
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	if !snapshot.Owned || snapshot.Schedule != request.Schedule {
		return renewalChoiceStepProof{}, errRenewalConflict
	}
	schedule, err := v.schedule(ctx, snapshot.Schedule)
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	raw, err := json.Marshal(schedule)
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	proof, err := verifyRenewalScheduleReceipt(k, op, request, raw, time.Now().UTC())
	if err == nil {
		proof.Evidence, _ = json.Marshal(map[string]any{"source": "original_update_and_current_schedule", "original_event": original.Evidence, "schedule": schedule.ID, "response_hash": renewalHash(json.RawMessage(raw)), "request_hash": renewalHash(request)})
		if proof.Choice != nil {
			proof.Choice.Evidence = proof.Evidence
		}
	}
	return proof, err
}

type renewalScheduleEvent struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Type    string `json:"type"`
	Version string `json:"api_version"`
	Account string `json:"account"`
	Live    bool   `json:"livemode"`
	Created int64  `json:"created"`
	Request struct {
		ID          string `json:"id"`
		Idempotency string `json:"idempotency_key"`
	} `json:"request"`
	Data struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// Event retention is bounded. Missing/truncated history stays unknown; it can
// never authorize another create or prove that an in-flight write had no effect.
func (v *stripeRenewalScheduleVerifier) recoverEvent(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, request renewalChoiceStepRequest, now time.Time) (renewalChoiceStepProof, error) {
	if op.DispatchedAt == nil || (request.Kind != "create_schedule" && request.Kind != "update_schedule") || request.Version != v.Client.apiVersion || now.Before(*op.DispatchedAt) || now.Sub(*op.DispatchedAt) >= 30*24*time.Hour {
		return renewalChoiceStepProof{}, errRenewalPending
	}
	var merchant struct{ ID string }
	if err := v.Client.doForm(ctx, http.MethodGet, "/v1/account", nil, &merchant, ""); err != nil {
		return renewalChoiceStepProof{}, err
	}
	if merchant.ID != op.Binding.Merchant {
		return renewalChoiceStepProof{}, errRenewalConflict
	}
	eventType := "subscription_schedule.created"
	if request.Kind == "update_schedule" {
		eventType = "subscription_schedule.updated"
	}
	var events struct {
		Data    []renewalScheduleEvent `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	query := url.Values{"type": {eventType}, "limit": {"100"}, "created[gte]": {strconv.FormatInt(op.DispatchedAt.Unix(), 10)}, "created[lte]": {strconv.FormatInt(now.Unix(), 10)}}
	if err := v.Client.doForm(ctx, http.MethodGet, "/v1/events?"+query.Encode(), nil, &events, ""); err != nil {
		return renewalChoiceStepProof{}, err
	}
	if events.HasMore {
		return renewalChoiceStepProof{}, errRenewalPending
	}
	var matched *renewalChoiceStepProof
	for _, event := range events.Data {
		if event.Request.Idempotency != request.Idempotency {
			continue
		}
		if matched != nil || event.ID == "" || event.Object != "event" || event.Type != eventType || event.Version != renewalStripeVersion || event.Request.ID == "" || event.Live != op.Binding.Live || (event.Account != "" && event.Account != op.Binding.Merchant) || event.Created < op.DispatchedAt.Unix() || event.Created > now.Unix() {
			return renewalChoiceStepProof{}, errRenewalConflict
		}
		proof, err := verifyRenewalScheduleReceipt(k, op, request, event.Data.Object, time.Unix(event.Created, 0).UTC())
		if err != nil {
			return renewalChoiceStepProof{}, err
		}
		proof.VerifiedAt = now.UTC()
		proof.Evidence, _ = json.Marshal(map[string]any{"source": "original_schedule_request_event", "event": event.ID, "request": event.Request.ID, "created": event.Created, "schedule": proof.Schedule, "request_hash": renewalHash(request), "object_hash": renewalHash(event.Data.Object)})
		matched = &proof
	}
	if matched == nil {
		return renewalChoiceStepProof{}, errRenewalPending
	}
	return *matched, nil
}

func (v *stripeRenewalScheduleVerifier) ObserveChoice(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if !time.Now().UTC().Before(k.Boundary) {
		return v.observeBoundary(ctx, k, op)
	}
	if len(op.Steps) != 0 {
		proof, err := v.ObserveStep(ctx, k, op, op.Steps[len(op.Steps)-1].Request)
		if err != nil || proof.Choice == nil {
			return renewalChoiceProof{}, errRenewalPending
		}
		return *proof.Choice, nil
	}
	snapshot, err := v.Inspect(ctx, k, op)
	if err != nil || snapshot.Schedule != "" || op.Request.Choice != "annual" || validateRenewalTerms("annual", op.Terms) != nil {
		return renewalChoiceProof{}, errRenewalPending
	}
	b, _, err := v.binding(ctx, k, op)
	if err != nil || op.Terms.Price != b.Terms.FeePriceID || op.Terms.Product != b.Terms.FeeProductID || op.Terms.Amount != b.Terms.FeeAmount {
		return renewalChoiceProof{}, errRenewalConflict
	}
	evidence, _ := json.Marshal(map[string]string{"source": "unmodified_annual_pair", "binding_hash": renewalHash(op.Binding)})
	return renewalChoiceProof{Operation: op.ID, Boundary: k.Boundary, BindingHash: renewalHash(op.Binding), TermsHash: renewalHash(op.Terms), Outcome: "confirmed", Timing: "future_configuration", VerifiedAt: time.Now().UTC(), Evidence: evidence}, nil
}
