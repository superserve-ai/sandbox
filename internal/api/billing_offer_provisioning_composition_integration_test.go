//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

func offerCompositionFixture(t *testing.T, confirmed ...int) (*offerProvisioningAuthority, *provisioning.Service, YCAcceptanceRecord, provisioning.Operation) {
	t.Helper()
	a, service, r, o, _ := offerCompositionBoundaryFixture(t, time.Now().UTC().Add(-time.Minute).Truncate(time.Second), confirmed...)
	return a, service, r, o
}

func offerCompositionBoundaryFixture(t *testing.T, anchor time.Time, confirmed ...int) (*offerProvisioningAuthority, *provisioning.Service, YCAcceptanceRecord, provisioning.Operation, *pairFixture) {
	t.Helper()
	s, r := acceptedCatalogFixture(t)
	h := s.Catalog.(ycAcceptedCatalog).h
	h.YCOfferAcceptance = s
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_funding_account SET observe=false,enforce=false WHERE team_id=$1`, r.TeamID)
	})
	s.Provisioning = &acceptanceProvisioningFixture{}
	if _, err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := loadYCAcceptance(t.Context(), s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.Pool.Exec(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO profile(id,email) VALUES($1,$2)`, r.UserID, r.UserID.String()+"@example.test")
	exec(`INSERT INTO team_memberships(team_id,user_id) VALUES($1,$2)`, r.TeamID, r.UserID)
	exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, r.UserID, r.TeamID)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, r.TeamID)
	f := newPairFixture(t)
	f.p.UsageSubscriptionID = "sub_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.usage.ID = f.p.UsageSubscriptionID
	movePairFixture(f, anchor)
	f.p.Identity.OperationID, f.p.Identity.TeamID, f.p.Identity.AssignmentID, f.p.Identity.AcceptanceID = *r.OperationID, r.TeamID, *r.AssignmentID, r.ID
	f.p.Identity.ApprovalSemanticRevision, f.p.Identity.TermsDigest = r.ApprovalRevision, r.TermsDigest
	for i := range f.p.Terms.Resources {
		for _, rate := range r.Terms.ResourceRates {
			if rate.Resource == f.p.Terms.Resources[i].ResourceKey {
				amount, ok := new(big.Rat).SetString(rate.PriceUSD)
				if !ok {
					t.Fatal("invalid fixture rate")
				}
				f.p.Terms.Resources[i].UnitAmountDecimal = new(big.Rat).Mul(amount, big.NewRat(360000, 1)).FloatString(12)
				f.usage.Items.Data[i].Price.UnitAmountDecimal = f.p.Terms.Resources[i].UnitAmountDecimal
			}
		}
	}
	f.p.Identity.ProviderTermsDigest, err = f.p.Terms.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.fee.Metadata, f.usage.Metadata = pairMetadata(f.p.Identity, "fee"), pairMetadata(f.p.Identity, "usage")
	offer, err := acceptedProvisioningSnapshot(r)
	if err != nil {
		t.Fatal(err)
	}
	offer.Merchant, offer.APIVersion, offer.Live = f.p.Identity.Merchant, f.p.Identity.APIVersion, f.p.Identity.Live
	offer.ProviderTerms, _ = json.Marshal(f.p.Terms)
	raw, _ := json.Marshal(offer)
	exec(`INSERT INTO billing_offer_provisioning_operation(id,team_id,assignment_id,accepted_offer) VALUES($1,$2,$3,$4)`, *r.OperationID, r.TeamID, *r.AssignmentID, raw)
	o := provisioning.Operation{ID: *r.OperationID, TeamID: r.TeamID, AssignmentID: *r.AssignmentID, Offer: offer, Requests: map[provisioning.Step]provisioning.SavedRequest{}}
	receipts := map[provisioning.Step]offerProviderReceipt{
		provisioning.Customer: {ID: f.p.CustomerID}, provisioning.Waiver: {ID: f.p.WaiverCouponID},
		provisioning.Fee:   {ID: f.p.FeeSubscriptionID, Item: f.p.FeeItemID, Invoice: f.p.WaiverInvoiceID, Anchor: f.p.Anchor.Unix()},
		provisioning.Usage: {ID: f.p.UsageSubscriptionID}, provisioning.UsageHold: {ID: f.p.UsageSubscriptionID},
	}
	client := f.client(t)
	provider := &offerProvisioningProvider{client: client}
	steps := []provisioning.Step{provisioning.Customer, provisioning.Waiver, provisioning.Fee, provisioning.Usage, provisioning.UsageHold}
	if len(confirmed) > 0 {
		steps = steps[:confirmed[0]]
	}
	for _, step := range steps {
		payload, err := provider.Prepare(t.Context(), o, step)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := json.Marshal(payload)
		receipt, _ := json.Marshal(receipts[step])
		exec(`INSERT INTO billing_offer_provisioning_request(operation_id,step,idempotency_key,request,state,dispatched_at,receipt) VALUES($1,$2,$3,$4,'confirmed',clock_timestamp(),$5)`, o.ID, string(step), fmt.Sprintf("offer-provisioning/%s/%s/v1", o.ID, step), request, receipt)
		o.Requests[step] = provisioning.SavedRequest{State: "confirmed", Receipt: receipt}
	}
	a := &offerProvisioningAuthority{h: h, admission: &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}, client: client, dispatchesResolved: CheckProviderPairDispatchesResolved}
	service := &provisioning.Service{Pool: h.Pool, Authority: a, Provider: provider}
	h.OfferProvisioning, s.Provisioning = service, ycAcceptanceProvisioner{service: service}
	return a, service, r, o, f
}

type offerExportFaultProvider struct {
	provisioning.Provider
	a                   *offerProvisioningAuthority
	team                uuid.UUID
	creates, recoveries int
	unknown             bool
}

func (*offerExportFaultProvider) Preflight(context.Context, provisioning.SavedRequest) error {
	return nil
}
func (p *offerExportFaultProvider) Create(ctx context.Context, _ provisioning.SavedRequest) (json.RawMessage, error) {
	p.creates++
	if _, err := p.a.h.Pool.Exec(ctx, `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.team); err != nil {
		return nil, err
	}
	if p.unknown {
		return nil, provisioning.ErrUnknown
	}
	return json.RawMessage(`{"id":"cus_recovered"}`), nil
}
func (p *offerExportFaultProvider) Recover(context.Context, provisioning.SavedRequest) (json.RawMessage, error) {
	p.recoveries++
	return json.RawMessage(`{"id":"cus_recovered"}`), nil
}

func TestOfferCompositionExportGatePreventsNewWritesAndPermitsRecovery(t *testing.T) {
	for _, phase := range []string{"before_first", "between_steps", "unknown_recovery"} {
		t.Run(phase, func(t *testing.T) {
			a, service, _, o := offerCompositionFixture(t, 0)
			provider := &offerExportFaultProvider{Provider: service.Provider, a: a, team: o.TeamID, unknown: phase == "unknown_recovery"}
			service.Provider = provider
			if phase == "before_first" {
				if _, err := a.h.Pool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, o.TeamID); err != nil {
					t.Fatal(err)
				}
			}
			if err := service.Reconcile(t.Context(), o.TeamID, o.AssignmentID); err == nil {
				t.Fatal("disabled export allowed progress")
			}
			wantCreates := 1
			if phase == "before_first" {
				wantCreates = 0
			}
			if provider.creates != wantCreates {
				t.Fatalf("writes=%d want=%d", provider.creates, wantCreates)
			}
			if phase == "unknown_recovery" {
				if err := service.Reconcile(t.Context(), o.TeamID, o.AssignmentID); err == nil {
					t.Fatal("recovery authorized next disabled step")
				}
				if provider.creates != 1 || provider.recoveries != 1 {
					t.Fatal("disabled export blocked recovery or replayed write", provider.creates, provider.recoveries)
				}
			}
		})
	}
}

func TestOfferCompositionFinalizationAndRevocation(t *testing.T) {
	a, service, r, o := offerCompositionFixture(t)
	ctx := t.Context()
	for range 2 {
		if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
			t.Fatal(err)
		}
	}
	var periods, contracts, enrollment int
	if err := a.h.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM billing_commercial_offer_period WHERE assignment_id=$1),(SELECT count(*) FROM billing_commercial_contract WHERE id=$2),(SELECT count(*) FROM billing_invoice_enrollment WHERE team_id=$3 AND completed_at IS NOT NULL)`, o.AssignmentID, o.ID, o.TeamID).Scan(&periods, &contracts, &enrollment); err != nil || periods != 12 || contracts != 1 || enrollment != 1 {
		t.Fatal("finalization was not exact or atomic", periods, contracts, enrollment, err)
	}
	status, err := service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || status.Ready {
		t.Fatal("materialization alone became ready", status, err)
	}
	binding, err := loadContractProviderBinding(ctx, a.h.Pool, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.WithProviderPairAuthority(ctx, binding, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp() WHERE contract_id=$1`, o.ID)
		return err
	}); err != nil {
		t.Fatal("current paired worker authority denied", err)
	}
	if _, err = a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range deliveries {
		if d.AcceptanceID != r.ID {
			continue
		}
		found = true
		for range 2 {
			if err = a.revokeFinancialDelivery(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("missing shared invalidation delivery")
	}
	state, err := a.admission.Service.FinancialState(ctx, r.ClaimID)
	if err != nil || state.State != "revoked" || state.PendingInvalidations != 0 {
		t.Fatal("revocation acknowledged before completion", state, err)
	}
	status, err = service.Status(ctx, o.TeamID, o.AssignmentID)
	if err != nil || status.Ready || !status.Revoked {
		t.Fatal("regional status lost permanent revocation", status, err)
	}
	called := false
	if err = a.WithFinalization(ctx, o, func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error { called = true; return nil }); err == nil || called {
		t.Fatal("late finalizer crossed revocation", err)
	}
	if err = a.WithProviderPairAuthority(ctx, binding, func(context.Context, pgx.Tx) error { called = true; return nil }); err == nil || called {
		t.Fatal("late entitlement dispatch crossed acknowledged revocation", err)
	}
}

func TestOfferCompositionMaterializationRollback(t *testing.T) {
	a, _, r, o := offerCompositionFixture(t)
	failure := errors.New("synthetic SQL materialization failure")
	err := a.WithFinalization(t.Context(), o, func(ctx context.Context, tx pgx.Tx, _ provisioning.AcceptedOffer) error {
		if _, e := tx.Exec(ctx, `UPDATE billing_offer_provisioning_operation SET last_error='synthetic' WHERE id=$1`, o.ID); e != nil {
			return e
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	var saved, finalized bool
	if err = a.h.Pool.QueryRow(t.Context(), `SELECT last_error IS NOT NULL,EXISTS(SELECT 1 FROM billing_offer_financial_fence WHERE team_id=$1 AND finalized_at IS NOT NULL) FROM billing_offer_provisioning_operation WHERE id=$2`, o.TeamID, o.ID).Scan(&saved, &finalized); err != nil || saved || finalized {
		t.Fatal("partial regional effect committed", saved, finalized, err)
	}
	shared, err := a.admission.Service.ReadFinancialAuthorization(t.Context(), r.ID, "initial", o.ID)
	if err != nil || shared.AuthorizationID == uuid.Nil {
		t.Fatal("durable shared authorization was not committed first", err)
	}
}

func TestOfferCompositionMissingSuccessorAndLostAcknowledgement(t *testing.T) {
	a, _, r, o := offerCompositionFixture(t)
	ctx := t.Context()
	successor := uuid.New()
	if _, err := a.admission.Service.IssueFinancialAuthorization(ctx, r, "successor", successor, r.RenewalTermsDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	deliveries, err := a.admission.Service.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
	if err != nil {
		t.Fatal(err)
	}
	var delivery YCFinancialInvalidation
	for _, d := range deliveries {
		if d.OperationID == successor {
			delivery = d
		}
	}
	if delivery.InvalidationID == uuid.Nil {
		t.Fatal("missing successor invalidation")
	}
	stale := delivery
	stale.LeaseID = uuid.New()
	if err = a.revokeFinancialDelivery(ctx, stale); err == nil {
		t.Fatal("stale shared lease acknowledged")
	}
	target := provisioning.FinancialTarget{TeamID: o.TeamID, AssignmentID: o.AssignmentID, Phase: "successor", TargetID: successor}
	first, err := provisioning.LoadFinancialRevocationReceipt(ctx, a.h.Pool, target, delivery.InvalidationID)
	if err != nil {
		t.Fatal("regional fence did not survive failed shared acknowledgement", err)
	}
	if err = a.revokeFinancialDelivery(ctx, delivery); err != nil {
		t.Fatal(err)
	}
	replayed, err := provisioning.LoadFinancialRevocationReceipt(ctx, a.h.Pool, target, delivery.InvalidationID)
	if err != nil || first != replayed {
		t.Fatal("lost-ack recovery changed immutable receipt", err)
	}
	tx, err := a.h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = provisioning.CheckFinancialTarget(ctx, tx, target); !errors.Is(err, provisioning.ErrRevoked) {
		t.Fatal("late missing successor escaped tombstone", err)
	}
	if err = provisioning.CheckFinancialTarget(ctx, tx, provisioning.InitialFinancialTarget(o.TeamID, o.AssignmentID)); err != nil {
		t.Fatal("successor fence changed initial target", err)
	}
}
