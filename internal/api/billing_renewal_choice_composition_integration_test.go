//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// This composition-only test uses the actual shared receipt, regional financial
// fence and entitlement worker from the separate integration checkout.
func TestRenewalChoiceFinancialComposition(t *testing.T) {
	for _, choice := range []string{"annual", "monthly"} {
		t.Run(choice, func(t *testing.T) {
			authority, h, r, f, client, actor := newRenewalAcceptedPairFixture(t, time.Now().UTC().Add(4*time.Second).Truncate(time.Second).AddDate(-1, 0, 0))
			h.YCOfferAcceptance = authority.Admission.Service
			h.Config = &config.Config{BillingUsageEntitlementsEnabled: true}
			k, previous, err := loadRenewalChoicePair(t.Context(), h.Pool, r.TeamID, *r.AssignmentID)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Until(k.Boundary.Add(50 * time.Millisecond)))
			target := successorPairFixture(f, previous, choice == "monthly")
			terms, err := loadRenewalChoiceTerms(t.Context(), h.Pool, choice, 1, target.Terms)
			if err != nil {
				t.Fatal(err)
			}
			op := renewalChoiceOperation{ID: uuid.New(), Actor: actor, Binding: renewalChoiceBindingFromPair(previous), Terms: terms, State: "confirmed", Request: renewalChoiceRequest{Acceptance: r.ID, ApprovalRevision: r.ApprovalRevision, Choice: choice}}
			store := postgresRenewalChoiceStore{Pool: h.Pool}
			if err = store.Transact(t.Context(), k, func(tx renewalChoiceTransaction) error {
				tx.Journal().Confirmed = &op
				return tx.Save("confirmed_choice_fixture")
			}); err != nil {
				t.Fatal(err)
			}
			common := &offerProvisioningAuthority{h: h, admission: authority.Admission, client: client, successorRequester: RenewalSuccessorRequester, dispatchesResolved: CheckProviderPairDispatchesResolved}
			h.ProviderPairEntitlementAuthority = common
			service := configureRenewalRuntimeFixture(t, h, authority.Admission, f, client)
			successor := service.Successors.(*acceptedRenewalSuccessors)
			wf := &pairWorkerFixture{h: h, b: target}
			configurePairWorkerProvider(t, wf, f)
			serve := f.serve
			debt := false
			f.serve = func(w http.ResponseWriter, req *http.Request) bool {
				if req.URL.Path == "/v1/invoices" && req.URL.Query().Get("subscription") == target.FeeSubscriptionID {
					json.NewEncoder(w).Encode(map[string]any{"data": []proPaidInvoice{f.invoice}})
					return true
				}
				if req.URL.Path == "/v1/invoices" && req.URL.Query().Get("status") == "open" && debt {
					json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "in_debt", "customer": target.CustomerID, "status": "open"}}})
					return true
				}
				if req.URL.Path == "/v1/invoices/in_prior_"+r.TeamID.String() {
					json.NewEncoder(w).Encode(map[string]any{"id": "in_prior_" + r.TeamID.String(), "customer": target.CustomerID, "status": "paid", "amount_remaining": 0, "parent": map[string]any{"subscription_details": map[string]any{"subscription": target.UsageSubscriptionID}}})
					return true
				}
				return serve(w, req)
			}
			assertState := func(want string, materialized bool) {
				t.Helper()
				var state string
				var contracts, fences, payments int
				err := h.Pool.QueryRow(t.Context(), `SELECT snapshot->>'successor_state',(SELECT count(*) FROM billing_commercial_contract WHERE id=$4),(SELECT count(*) FROM billing_offer_financial_fence WHERE target_id=$4 AND finalized_at IS NOT NULL),(SELECT count(*) FROM billing_contract_payment WHERE contract_id=$4) FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3`, k.Team, k.Assignment, k.Boundary, renewalSuccessorID(k)).Scan(&state, &contracts, &fences, &payments)
				n := 0
				if materialized {
					n = 1
				}
				if err != nil || state != want || contracts != n || fences != n || payments != n {
					t.Fatal("non-atomic successor", state, contracts, fences, payments, err)
				}
			}
			if err = service.reconcileSuccessor(t.Context(), k); err != nil {
				t.Fatal(err)
			}
			assertState("payment_pending", false)
			f.invoice.Status, f.invoice.AmountPaid, f.invoice.AmountRemaining = "paid", target.Terms.FeeAmount, 0
			f.invoice.StatusTransitions.PaidAt = k.Boundary.Unix()
			debt = true
			if err = service.reconcileSuccessor(t.Context(), k); err != nil {
				t.Fatal(err)
			}
			assertState("review_required", false)
			debt = false
			if err = service.reconcileSuccessor(t.Context(), k); err != nil {
				t.Fatal(err)
			}
			assertState("review_required", false)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := h.Pool.Exec(t.Context(), q, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, k.Team, target.CustomerID, target.UsageSubscriptionID, target.Terms.Rounding.PriceID, target.Terms.Rounding.EventName, target.Terms.Rounding.MeterID, previous.Anchor)
			prior := annualBoundary(previous.Anchor, 11)
			exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),0,0,0)`, k.Team, prior, k.Boundary)
			exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,state,verified_at,plan,finalized_evidence) VALUES($1,$2,$3,$4,'released',clock_timestamp(),jsonb_build_object('customer',$5::text,'subscription',$6::text,'expected_cents',0,'credit_before_cents',0,'resources',jsonb_build_array(jsonb_build_object('resource','cpu','expected_cents',0,'snapshot',billing_meter_accounting_snapshot($1,$2,$3,'cpu')))), '{"credit_applied_cents":0,"credit_remaining_cents":0,"net_cents":0}')`, k.Team, prior, k.Boundary, "in_prior_"+r.TeamID.String(), target.CustomerID, target.UsageSubscriptionID)
			if _, e := client.verifyProviderPairPayment(t.Context(), target, f.invoice.ID); e != nil {
				t.Fatal("cash", e)
			}
			if d, e := client.entitlementDebt(t.Context(), target.CustomerID); e != nil || d != "" {
				t.Fatal("debt", d, e)
			}
			if e := h.entitlementClosingInvoice(t.Context(), db.BillingCommercialContract{ID: renewalSuccessorID(k), TeamID: k.Team, CustomerID: target.CustomerID, SubscriptionID: target.UsageSubscriptionID, EntitlementAnchor: previous.Anchor}, k.Boundary, client); e != nil {
				t.Fatal("closing", e)
			}
			// Authority and the journal may change after network observation but before
			// the shared receipt reaches the regional commit.
			for _, change := range []string{"revision", "requester"} {
				successor.Finalize = func(ctx context.Context, accepted YCAcceptanceRecord, phase string, id uuid.UUID, digest string, boundary time.Time, apply func(context.Context, pgx.Tx, YCFinancialAuthorization) error) error {
					if change == "revision" {
						if err := store.Transact(ctx, k, func(tx renewalChoiceTransaction) error { return tx.Save("concurrent_fixture") }); err != nil {
							return err
						}
					} else {
						exec(`DELETE FROM user_role_assignments WHERE user_id=$1 AND team_id=$2`, actor, k.Team)
					}
					return h.FinalizeAcceptedOfferFinancial(ctx, accepted, phase, id, digest, boundary, apply)
				}
				if err = service.reconcileSuccessor(t.Context(), k); err == nil {
					t.Fatal("stale observation crossed commit", change)
				}
				assertState("review_required", false)
				if change == "requester" {
					exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, actor, k.Team)
				}
			}
			failure := errors.New("lost regional materialization")
			successor.Finalize = func(ctx context.Context, r YCAcceptanceRecord, phase string, id uuid.UUID, digest string, b time.Time, apply func(context.Context, pgx.Tx, YCFinancialAuthorization) error) error {
				return h.FinalizeAcceptedOfferFinancial(ctx, r, phase, id, digest, b, func(ctx context.Context, tx pgx.Tx, a YCFinancialAuthorization) error {
					if err := apply(ctx, tx, a); err != nil {
						return err
					}
					return failure
				})
			}
			if err = service.reconcileSuccessor(t.Context(), k); !errors.Is(err, failure) {
				t.Fatal("rollback injection did not reach full activation", err)
			}
			assertState("review_required", false)
			successor.Finalize = h.FinalizeAcceptedOfferFinancial
			for range 2 {
				if err = service.reconcileSuccessor(t.Context(), k); err != nil {
					t.Fatal(err)
				}
			}
			assertState("active", true)
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, k.Team)
			time.Sleep(time.Until(k.Boundary.Add(time.Second)))
			for range 2 {
				if _, err = h.reconcileUsageEntitlement(t.Context(), renewalSuccessorID(k)); err != nil {
					t.Fatal(err)
				}
			}
			entitlement, err := h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: k.Team, Kind: "metered_usage"})
			if err != nil || entitlement.State != "issued" || entitlement.AmountCents != 100000 || !entitlement.PeriodStart.Equal(k.Boundary) || !entitlement.PeriodEnd.Equal(annualBoundary(previous.Anchor, 13)) || wf.posts.Load() != 1 {
				t.Fatal("actual worker did not issue one original-calendar grant", entitlement, err, wf.posts.Load())
			}
		})
	}
}

func TestRenewalChoiceFreeRemovalComposition(t *testing.T) {
	a, initial, r, operation, f := offerCompositionBoundaryFixture(t, time.Now().UTC().Add(5*time.Second).Truncate(time.Second).AddDate(-1, 0, 0))
	if err := initial.Reconcile(t.Context(), operation.TeamID, operation.AssignmentID); err != nil {
		t.Fatal(err)
	}
	k, previous, err := loadRenewalChoicePair(t.Context(), a.h.Pool, r.TeamID, *r.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	op := renewalChoiceOperation{ID: uuid.New(), Actor: r.UserID, Binding: renewalChoiceBindingFromPair(previous), State: "confirmed", Request: renewalChoiceRequest{Acceptance: r.ID, ApprovalRevision: r.ApprovalRevision, Choice: "free"}}
	create, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: op.Binding.Anchor, Boundary: k.Boundary})
	if err != nil {
		t.Fatal(err)
	}
	created := renewalChoiceStepProof{RequestHash: renewalHash(create), Outcome: "confirmed", Schedule: "sub_sched_fixture", BindingHash: renewalHash(op.Binding), VerifiedAt: time.Now().UTC()}
	_, _, _, response, _ := renewalReceiptFixture(t, "free")
	response["customer"], response["subscription"], response["livemode"] = op.Binding.Customer, op.Binding.Fee, op.Binding.Live
	response["current_phase"] = map[string]any{"start_date": op.Binding.Anchor.Unix(), "end_date": k.Boundary.Unix()}
	phase := response["phases"].([]any)[0].(map[string]any)
	phase["start_date"], phase["end_date"] = op.Binding.Anchor.Unix(), k.Boundary.Unix()
	phase["items"].([]any)[0].(map[string]any)["price"] = f.p.Terms.FeePriceID
	phase["items"].([]any)[0].(map[string]any)["plan"] = f.p.Terms.FeePriceID
	phase["discounts"] = []any{map[string]any{"coupon": f.p.WaiverCouponID}}
	phaseRaw, _ := json.Marshal(phase)
	current, err := renewalSchedulePhaseForm(phaseRaw, "phases[0]", "charge_automatically")
	if err != nil {
		t.Fatal(err)
	}
	update, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Schedule: created.Schedule, Owned: true, Anchor: op.Binding.Anchor, Boundary: k.Boundary, CurrentPhase: current})
	if err != nil {
		t.Fatal(err)
	}
	op.Steps = []renewalChoiceStep{{Request: update, State: "dispatched"}}
	raw, _ := json.Marshal(response)
	receipt, err := verifyRenewalScheduleReceipt(k, op, update, raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	op.Steps = []renewalChoiceStep{{Request: update, State: "confirmed", Proof: &receipt}}
	op.Proof = receipt.Choice
	store := postgresRenewalChoiceStore{Pool: a.h.Pool}
	if err = store.Transact(t.Context(), k, func(tx renewalChoiceTransaction) error {
		tx.Journal().OwnedSchedule = &renewalChoiceOwnedSchedule{Operation: op.ID, Request: create, Proof: created}
		tx.Journal().Confirmed = &op
		return tx.Save("confirmed_free_fixture")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,'in_existing_debt')`, previous.ContractID, annualBoundary(previous.Anchor, 11)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(k.Boundary.Add(50 * time.Millisecond)))
	f.fee.Status, f.fee.EndedAt = "canceled", k.Boundary.Unix()
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = k.Boundary.Unix(), annualBoundary(previous.Anchor, 13).Unix()
	}
	service := configureRenewalRuntimeFixture(t, a.h, a.admission, f, a.client)
	adapter := service.Successors.(*acceptedRenewalSuccessors)
	failure := errors.New("synthetic removal rollback")
	adapter.Remove = func(ctx context.Context, r YCAcceptanceRecord, actor, id uuid.UUID, apply func(context.Context, pgx.Tx) error) error {
		return a.h.WithAcceptedOfferRemoval(ctx, r, actor, id, func(ctx context.Context, tx pgx.Tx) error {
			if err := apply(ctx, tx); err != nil {
				return err
			}
			return failure
		})
	}
	if err = service.reconcileSuccessor(t.Context(), k); !errors.Is(err, failure) {
		t.Fatal("removal did not reach guarded callback", err)
	}
	var status string
	if err = a.h.Pool.QueryRow(t.Context(), `SELECT status FROM billing_commercial_contract WHERE id=$1`, previous.ContractID).Scan(&status); err != nil || status != "active" {
		t.Fatal("partial Free removal committed", status, err)
	}
	adapter.Remove = func(ctx context.Context, r YCAcceptanceRecord, actor, id uuid.UUID, apply func(context.Context, pgx.Tx) error) error {
		if err := a.h.WithAcceptedOfferRemoval(ctx, r, actor, id, apply); err != nil {
			return err
		}
		return failure
	}
	if err = service.reconcileSuccessor(t.Context(), k); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	adapter.Remove = a.h.WithAcceptedOfferRemoval
	if err = service.reconcileSuccessor(t.Context(), k); err != nil {
		t.Fatal("lost response recovery", err)
	}
	var state string
	var paidTargets, paidContracts, debts int
	if err = a.h.Pool.QueryRow(t.Context(), `SELECT snapshot->>'successor_state',(SELECT count(*) FROM billing_offer_financial_fence WHERE target_id=$4 AND finalized_at IS NOT NULL),(SELECT count(*) FROM billing_commercial_contract WHERE id=$4),(SELECT count(*) FROM billing_entitlement_debt WHERE contract_id=$5 AND invoice_id='in_existing_debt') FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3`, k.Team, k.Assignment, k.Boundary, renewalSuccessorID(k), previous.ContractID).Scan(&state, &paidTargets, &paidContracts, &debts); err != nil || state != "free" || paidTargets != 0 || paidContracts != 0 || debts != 1 {
		t.Fatal("Free changed financial obligations", state, paidTargets, paidContracts, debts, err)
	}
}
