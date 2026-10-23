//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestRenewalChoiceBoundaryUsesOriginalInvoiceAndActualPair(t *testing.T) {
	for _, choice := range []string{"annual", "monthly"} {
		t.Run(choice, func(t *testing.T) {
			pool, f, client, k, op := newRenewalActivatedPairFixture(t, time.Now().UTC().Add(3*time.Second).Truncate(time.Second).AddDate(-1, 0, 0))
			time.Sleep(time.Until(k.Boundary.Add(50 * time.Millisecond)))
			_, previous, err := loadRenewalChoicePair(t.Context(), pool, k.Team, k.Assignment)
			if err != nil {
				t.Fatal(err)
			}
			actual := successorPairFixture(f, previous, choice == "monthly")
			op.Request.Choice = choice
			op.Terms, err = loadRenewalChoiceTerms(t.Context(), pool, choice, 1, actual.Terms)
			if err != nil {
				t.Fatal(err)
			}
			v := &stripeRenewalScheduleVerifier{Pool: pool, Client: client}
			proof, err := v.ObserveChoice(t.Context(), k, op)
			if err != nil || proof.Timing != "boundary_history" || proof.successor == nil || proof.successor.Binding.FeeItemID != actual.FeeItemID || proof.successor.Binding.ContractID != renewalSuccessorID(k) || proof.successor.Binding.Identity.TermsDigest != renewalTargetDigest(k, op) {
				t.Fatal("actual boundary pair not established", proof, err)
			}
			// Open invoices establish plan history, never paid eligibility.
			if f.invoice.Status != "open" {
				t.Fatal("fixture unexpectedly paid")
			}
			raw, _ := json.Marshal(proof)
			var restored renewalChoiceProof
			if err = json.Unmarshal(raw, &restored); err != nil || restored.successor != nil {
				t.Fatal("JSON restored typed financial evidence", err)
			}
			original := f.invoice.Lines.Data[0].Period.Start
			f.invoice.Lines.Data[0].Period.Start = original + 86400
			if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
				t.Fatal("later invoice replaced original boundary")
			}
			f.invoice.Lines.Data[0].Period.Start = original
			f.extraInvoice = true
			if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
				t.Fatal("duplicate boundary obligation accepted")
			}
			f.extraInvoice = false
			f.usage.PauseCollection = nil
			if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
				t.Fatal("unheld usage pair confirmed")
			}
		})
	}
}

func TestRenewalChoiceFreeBoundaryRequiresExactCancellation(t *testing.T) {
	pool, f, client, k, op := newRenewalActivatedPairFixture(t, time.Now().UTC().Add(3*time.Second).Truncate(time.Second).AddDate(-1, 0, 0))
	time.Sleep(time.Until(k.Boundary.Add(50 * time.Millisecond)))
	op.Request.Choice, op.Terms = "free", nil
	create, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Anchor: op.Binding.Anchor, Boundary: k.Boundary})
	if err != nil {
		t.Fatal(err)
	}
	created := renewalChoiceStepProof{RequestHash: renewalHash(create), Outcome: "confirmed", Schedule: "sub_sched_fixture", BindingHash: renewalHash(op.Binding), VerifiedAt: k.Boundary.Add(-time.Hour)}
	if err = (postgresRenewalChoiceStore{Pool: pool}).Transact(t.Context(), k, func(tx renewalChoiceTransaction) error {
		tx.Journal().OwnedSchedule = &renewalChoiceOwnedSchedule{Operation: op.ID, Request: create, Proof: created}
		return tx.Save("owned_schedule_fixture")
	}); err != nil {
		t.Fatal(err)
	}
	current := url.Values{"phases[0][start_date]": {strconv.FormatInt(op.Binding.Anchor.Unix(), 10)}, "phases[0][end_date]": {strconv.FormatInt(k.Boundary.Unix(), 10)}, "phases[0][items][0][price]": {f.p.Terms.FeePriceID}, "phases[0][items][0][quantity]": {"1"}, "phases[0][discounts][0][coupon]": {f.p.WaiverCouponID}, "phases[0][proration_behavior]": {"none"}, "phases[0][collection_method]": {"charge_automatically"}}
	update, err := buildRenewalScheduleStep(k, op, renewalScheduleSnapshot{BindingHash: renewalHash(op.Binding), Schedule: created.Schedule, Owned: true, Anchor: op.Binding.Anchor, Boundary: k.Boundary, CurrentPhase: current})
	if err != nil {
		t.Fatal(err)
	}
	choice := fixtureRenewalProof(k, op, k.Boundary.Add(-time.Minute))
	op.Steps = []renewalChoiceStep{{Request: update, State: "confirmed", Proof: &renewalChoiceStepProof{RequestHash: renewalHash(update), Outcome: "confirmed", Schedule: created.Schedule, Choice: &choice}}}
	f.fee.Status, f.fee.EndedAt = "canceled", k.Boundary.Unix()
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = k.Boundary.Unix(), annualBoundary(op.Binding.Anchor, 13).Unix()
	}
	v := &stripeRenewalScheduleVerifier{Pool: pool, Client: client}
	proof, err := v.ObserveChoice(t.Context(), k, op)
	if err != nil || proof.Timing != "boundary_history" || proof.Outcome != "confirmed" || proof.successor != nil {
		t.Fatal(proof, err)
	}
	// The original update succeeded before B, but its response was lost. Recovery
	// must survive persistence before the separate successor reconciliation runs.
	_, _, _, response, _ := renewalReceiptFixture(t, "free")
	response["customer"], response["subscription"], response["livemode"] = op.Binding.Customer, op.Binding.Fee, op.Binding.Live
	response["current_phase"] = map[string]any{"start_date": op.Binding.Anchor.Unix(), "end_date": k.Boundary.Unix()}
	phase := response["phases"].([]any)[0].(map[string]any)
	phase["start_date"], phase["end_date"] = op.Binding.Anchor.Unix(), k.Boundary.Unix()
	phase["items"].([]any)[0].(map[string]any)["price"] = f.p.Terms.FeePriceID
	phase["items"].([]any)[0].(map[string]any)["plan"] = f.p.Terms.FeePriceID
	phase["discounts"] = []any{map[string]any{"coupon": f.p.WaiverCouponID}}
	dispatched := k.Boundary.Add(-2 * time.Minute)
	op.DispatchedAt, op.State = &dispatched, "outcome_unknown"
	op.Steps[0].State, op.Steps[0].Proof = "outcome_unknown", nil
	event := renewalScheduleEvent{ID: "evt_update", Object: "event", Type: "subscription_schedule.updated", Version: renewalStripeVersion, Created: dispatched.Unix() + 1, Live: op.Binding.Live}
	event.Request.ID, event.Request.Idempotency = "req_update", update.Idempotency
	event.Data.Object, _ = json.Marshal(response)
	transport := client.httpClient.Transport
	client.httpClient.Transport = stripeCheckoutRecoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/events" {
			return transport.RoundTrip(r)
		}
		raw, _ := json.Marshal(map[string]any{"data": []renewalScheduleEvent{event}, "has_more": false})
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
	})
	store := postgresRenewalChoiceStore{Pool: pool}
	if err = store.Transact(t.Context(), k, func(tx renewalChoiceTransaction) error {
		tx.Journal().Requested = &op
		return tx.Save("unknown_free_fixture")
	}); err != nil {
		t.Fatal(err)
	}
	s := &renewalChoiceService{Store: store}
	if err = s.reconcileSteps(t.Context(), k, &renewalScheduleProvider{Client: client, Verifier: v}); err != nil {
		t.Fatal(err)
	}
	if err = store.Transact(t.Context(), k, func(tx renewalChoiceTransaction) error {
		confirmed := tx.Journal().Confirmed
		if confirmed == nil || confirmed.Proof.Timing != "boundary_history" || confirmed.Steps[0].Proof.OriginalChoice == nil {
			t.Fatal("recovered Free did not retain its original request proof", confirmed)
		}
		op = *confirmed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if proof, err = v.ObserveChoice(t.Context(), k, op); err != nil || proof.Timing != "boundary_history" {
		t.Fatal("persisted Free recovery could not reconcile successor", proof, err)
	}
	f.fee.EndedAt++
	if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
		t.Fatal("late cancellation became exact boundary Free")
	}
	f.fee.EndedAt--
	f.extraInvoice = true
	if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
		t.Fatal("new fee invoice ignored by Free history")
	}
	f.extraInvoice = false
	f.extra = true
	if _, err = v.ObserveChoice(t.Context(), k, op); err == nil {
		t.Fatal("another subscription ignored by Free history")
	}
}
