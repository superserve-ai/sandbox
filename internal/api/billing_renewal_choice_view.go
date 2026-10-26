package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Customer projections omit provider identities, actor IDs and verification data.
type renewalChoiceTermsView struct {
	Offer      string  `json:"offer_key"`
	Version    int     `json:"offer_version"`
	RateCard   string  `json:"rate_card_key"`
	Currency   string  `json:"currency"`
	Amount     int64   `json:"charge_amount_cents"`
	Months     int     `json:"charge_interval_months"`
	Allowances []int64 `json:"monthly_allowance_cents"`
	Payment    string  `json:"payment_requirement"`
	Rollover   bool    `json:"rollover"`
	Proration  bool    `json:"proration"`
}
type renewalChoiceInstructionView struct {
	Request uuid.UUID               `json:"request_id"`
	Choice  string                  `json:"choice"`
	State   string                  `json:"state"`
	Terms   *renewalChoiceTermsView `json:"terms"`
}
type renewalChoiceOptionView struct {
	Choice            string                  `json:"choice"`
	Available         bool                    `json:"available"`
	UnavailableReason string                  `json:"unavailable_reason,omitempty"`
	Terms             *renewalChoiceTermsView `json:"terms"`
}
type renewalChoiceView struct {
	Assignment       uuid.UUID                     `json:"assignment_id"`
	Acceptance       uuid.UUID                     `json:"acceptance_id"`
	ApprovalRevision int64                         `json:"approval_revision"`
	Revision         int64                         `json:"choice_revision"`
	Boundary         time.Time                     `json:"intended_boundary"`
	Requested        *renewalChoiceInstructionView `json:"requested"`
	Confirmed        *renewalChoiceInstructionView `json:"last_confirmed"`
	SuccessorState   string                        `json:"successor_state"`
	Options          []renewalChoiceOptionView     `json:"available_options"`
}

func renewalTermsView(t *renewalChoiceTerms) *renewalChoiceTermsView {
	if t == nil {
		return nil
	}
	return &renewalChoiceTermsView{Offer: t.Offer, Version: t.Version, RateCard: t.RateCard, Currency: t.Currency, Amount: t.Amount, Months: t.Months, Allowances: append([]int64(nil), t.Allowances...), Payment: "verified_payment"}
}
func renewalInstructionView(op *renewalChoiceOperation) *renewalChoiceInstructionView {
	if op == nil {
		return nil
	}
	return &renewalChoiceInstructionView{Request: op.Request.ID, Choice: op.Request.Choice, State: op.State, Terms: renewalTermsView(op.Terms)}
}
func (s *renewalChoiceService) view(ctx context.Context, k renewalChoiceKey, actor uuid.UUID) (renewalChoiceView, error) {
	var view renewalChoiceView
	if err := s.available(); err != nil {
		return view, err
	}
	if !validRenewalKey(k) || actor == uuid.Nil {
		return view, errRenewalConflict
	}
	err := s.admittedTransaction(ctx, k, actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		a, err := s.Authority.Authorize(ctx, tx.SQL(), k, actor)
		if err != nil {
			return err
		}
		j := tx.Journal()
		view = renewalChoiceView{Assignment: k.Assignment, Acceptance: a.Acceptance, ApprovalRevision: a.Revision, Revision: j.Revision, Boundary: k.Boundary, Requested: renewalInstructionView(j.Requested), Confirmed: renewalInstructionView(j.Confirmed), SuccessorState: j.SuccessorState}
		for _, choice := range []string{"annual", "monthly", "free"} {
			terms, err := s.Authority.Resolve(ctx, tx.SQL(), k, choice)
			option := renewalChoiceOptionView{Choice: choice}
			switch {
			case s.Provider == nil || j.Confirmed == nil:
				option.UnavailableReason = "integration_unavailable"
			case !tx.Now().Before(k.Boundary):
				option.UnavailableReason = "boundary_passed"
			case j.Requested != nil && (j.Requested.State == "dispatched" || j.Requested.State == "outcome_unknown"):
				option.UnavailableReason = "change_pending"
			case !renewalCalendarSupported(choice, a.Binding.Anchor, k.Boundary):
				option.UnavailableReason = "integration_unavailable"
			case err != nil || validateRenewalTerms(choice, terms) != nil:
				option.UnavailableReason = "catalog_unavailable"
			default:
				option.Available = true
				option.Terms = renewalTermsView(terms)
			}
			view.Options = append(view.Options, option)
		}
		return nil
	})
	return view, err
}

// First status reads locate the provider-confirmed original term server-side.
func (s *renewalChoiceService) currentView(ctx context.Context, team, assignment, actor uuid.UUID) (renewalChoiceView, error) {
	if err := s.available(); err != nil {
		return renewalChoiceView{}, err
	}
	if team == uuid.Nil || assignment == uuid.Nil || actor == uuid.Nil {
		return renewalChoiceView{}, errRenewalConflict
	}
	key, err := s.Authority.Locate(ctx, team, assignment, actor)
	if err != nil {
		return renewalChoiceView{}, err
	}
	if key.Team != team || key.Assignment != assignment || !validRenewalKey(key) {
		return renewalChoiceView{}, errRenewalConflict
	}
	if err := s.initialize(ctx, key, actor); err != nil {
		return renewalChoiceView{}, err
	}
	return s.view(ctx, key, actor)
}
