package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	errRenewalDisabled = errors.New("renewal choice integration is unavailable")
	errRenewalConflict = errors.New("renewal choice revision or identity conflict")
	errRenewalPending  = errors.New("renewal provider outcome must be reconciled first")
)

type renewalChoiceKey struct {
	Team       uuid.UUID `json:"team_id"`
	Assignment uuid.UUID `json:"assignment_id"`
	Boundary   time.Time `json:"intended_boundary"`
}

type renewalChoiceBinding struct {
	Contract        uuid.UUID `json:"contract_id"`
	ProviderBinding uuid.UUID `json:"provider_binding_id"`
	Merchant        string    `json:"merchant_account"`
	Live            bool      `json:"live_mode"`
	Customer        string    `json:"customer_id"`
	Fee             string    `json:"fee_subscription_id"`
	Usage           string    `json:"usage_subscription_id"`
	Anchor          time.Time `json:"original_anchor"`
}

type renewalChoiceTerms struct {
	Offer      string  `json:"offer_key"`
	Version    int     `json:"offer_version"`
	RateCard   string  `json:"rate_card_key"`
	Price      string  `json:"price_id"`
	Product    string  `json:"product_id"`
	Currency   string  `json:"currency"`
	Amount     int64   `json:"amount_cents"`
	Months     int     `json:"interval_months"`
	Allowances []int64 `json:"monthly_allowance_cents"`
}

type renewalChoiceRequest struct {
	Acceptance       uuid.UUID `json:"acceptance_id"`
	ID               uuid.UUID `json:"request_id"`
	Choice           string    `json:"choice"`
	ApprovalRevision int64     `json:"expected_approval_revision"`
	ChoiceRevision   int64     `json:"expected_choice_revision"`
}

type renewalChoiceOperation struct {
	Steps        []renewalChoiceStep  `json:"steps,omitempty"`
	ID           uuid.UUID            `json:"operation_id"`
	Request      renewalChoiceRequest `json:"request"`
	Actor        uuid.UUID            `json:"actor_id"`
	Binding      renewalChoiceBinding `json:"binding"`
	Terms        *renewalChoiceTerms  `json:"terms,omitempty"`
	State        string               `json:"state"`
	CreatedAt    time.Time            `json:"created_at"`
	DispatchedAt *time.Time           `json:"dispatched_at,omitempty"`
	Proof        *renewalChoiceProof  `json:"proof,omitempty"`
}

// Proofs come only from the registered provider verifier, never a request body.
// Boundary history includes original write timing and complete invoice inventory.
type renewalChoiceProof struct {
	// Fresh typed provider verification is never restored from persisted JSON.
	successor   *VerifiedProviderPairSuccessor
	Operation   uuid.UUID       `json:"operation_id"`
	Boundary    time.Time       `json:"intended_boundary"`
	BindingHash string          `json:"binding_hash"`
	TermsHash   string          `json:"terms_hash"`
	Outcome     string          `json:"outcome"` // confirmed, no_effect, unknown
	Timing      string          `json:"timing"`  // future_configuration, boundary_history
	VerifiedAt  time.Time       `json:"verified_at"`
	Evidence    json.RawMessage `json:"evidence"`
}

type renewalChoiceJournal struct {
	OwnedSchedule  *renewalChoiceOwnedSchedule `json:"owned_schedule,omitempty"`
	Key            renewalChoiceKey            `json:"key"`
	Revision       int64                       `json:"revision"`
	Requested      *renewalChoiceOperation     `json:"requested,omitempty"`
	Confirmed      *renewalChoiceOperation     `json:"last_confirmed,omitempty"`
	Successor      uuid.UUID                   `json:"successor_id"`
	SuccessorState string                      `json:"successor_state"`
}

type renewalChoiceOwnedSchedule struct {
	Operation uuid.UUID                `json:"operation_id"`
	Request   renewalChoiceStepRequest `json:"request"`
	Proof     renewalChoiceStepProof   `json:"proof"`
}

type renewalChoiceAuthority struct {
	Acceptance uuid.UUID
	Revision   int64
	Binding    renewalChoiceBinding
}

// Regional admission checks current team, assignment, acceptance and actor
// authority. It does not promise atomicity across databases. Resolve returns
// published terms; neither Authorize nor Resolve performs provider I/O.
type renewalChoiceAuthoritySource interface {
	// Locate reads the original activated term; callers never calculate it from
	// acceptance time. Authorize must revalidate the located key during admission.
	Locate(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (renewalChoiceKey, error)
	// Admit checks point-in-time authority and permits bounded regional-only work.
	// It is separate from DispatchGuard and must not reuse its shared lock lease.
	// Pending metadata grants no dispatch or benefit authority; successor adoption
	// still requires its own fresh payment/debt/authority checks.
	Admit(context.Context, renewalChoiceKey, uuid.UUID, func(context.Context) error) error
	// DispatchGuard rechecks this exact accepted operation and holds shared Auth
	// authority for one provider call only. Its callback must perform no SQL.
	DispatchGuard(context.Context, renewalChoiceKey, renewalChoiceOperation, func(context.Context) error) error
	Authorize(context.Context, pgx.Tx, renewalChoiceKey, uuid.UUID) (renewalChoiceAuthority, error)
	Resolve(context.Context, pgx.Tx, renewalChoiceKey, string) (*renewalChoiceTerms, error)
	DefaultProof(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
}

// Register only after exact-boundary late-write rejection has been established.
// Dispatch preserves the current term. Observe is read-only and must recover the
// original operation; an unknown write is never blindly submitted a second time.
type renewalChoiceProvider interface {
	Dispatch(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
	Observe(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
}

// Reconcile uses the existing guarded contract/payment path inside tx. It must
// verify exact cash coverage, debt and closing eligibility before returning active,
// and preserve all existing debt on free. The stable successor ID fences retries.
// This interface cannot authorize provider charges or direct grant issuance.
type renewalChoiceSuccessors interface {
	Reconcile(context.Context, pgx.Tx, renewalChoiceKey, renewalChoiceOperation, uuid.UUID) (string, error)
}

type renewalChoiceFinancialSuccessors interface {
	ReconcileFinancial(context.Context, renewalChoiceKey, renewalChoiceOperation, func(context.Context, pgx.Tx, func() (string, error)) error) error
}

type renewalChoiceTransaction interface {
	SQL() pgx.Tx
	Now() time.Time
	Journal() *renewalChoiceJournal
	Find(uuid.UUID) (*renewalChoiceOperation, error)
	Insert(renewalChoiceOperation) error
	Save(string) error
}

type renewalChoiceStore interface {
	Transact(context.Context, renewalChoiceKey, func(renewalChoiceTransaction) error) error
}

// No production route or worker registers this service until its authority,
// provider verifier and guarded successor adapters are integrated.
type renewalChoiceService struct {
	Enabled    bool
	Store      renewalChoiceStore
	Authority  renewalChoiceAuthoritySource
	Provider   renewalChoiceProvider
	Successors renewalChoiceSuccessors
}

func (s *renewalChoiceService) available() error {
	if s == nil || !s.Enabled || s.Store == nil || s.Authority == nil {
		return errRenewalDisabled
	}
	return nil
}

func renewalHash(v any) string {
	if binding, ok := v.(renewalChoiceBinding); ok {
		binding.Anchor = binding.Anchor.UTC()
		v = binding
	}
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validRenewalKey(k renewalChoiceKey) bool {
	return k.Team != uuid.Nil && k.Assignment != uuid.Nil && !k.Boundary.IsZero() && k.Boundary.Equal(k.Boundary.Truncate(time.Second))
}

func validRenewalBinding(b renewalChoiceBinding, k renewalChoiceKey) bool {
	return b.Contract != uuid.Nil && b.ProviderBinding != uuid.Nil && b.Merchant != "" && b.Customer != "" && b.Fee != "" && b.Usage != "" && b.Fee != b.Usage && !b.Anchor.IsZero() && b.Anchor.Before(k.Boundary)
}

func validateRenewalTerms(choice string, t *renewalChoiceTerms) error {
	if choice == "free" && t == nil {
		return nil
	}
	if choice != "annual" && choice != "monthly" {
		return errRenewalConflict
	}
	months := 12
	if choice == "monthly" {
		months = 1
	}
	if t == nil || t.Offer != "pro_"+choice || t.Version <= 0 || t.RateCard == "" || t.Price == "" || t.Product == "" || t.Currency != "usd" || t.Amount <= 0 || t.Months != months || len(t.Allowances) != months {
		return errRenewalConflict
	}
	for _, amount := range t.Allowances {
		if amount <= 0 {
			return errRenewalConflict
		}
	}
	return nil
}

func validateRenewalProof(k renewalChoiceKey, op renewalChoiceOperation, p renewalChoiceProof, now time.Time) error {
	var evidence map[string]json.RawMessage
	if p.Operation != op.ID || !p.Boundary.Equal(k.Boundary) || p.BindingHash != renewalHash(op.Binding) || p.TermsHash != renewalHash(op.Terms) || p.VerifiedAt.IsZero() || p.VerifiedAt.After(now) || json.Unmarshal(p.Evidence, &evidence) != nil || len(evidence) == 0 {
		return errRenewalConflict
	}
	if (p.Timing == "boundary_history" && p.VerifiedAt.Before(k.Boundary)) || (p.Timing != "boundary_history" && !(p.Timing == "future_configuration" && now.Before(k.Boundary))) {
		return errRenewalConflict
	}
	if p.Outcome != "confirmed" && p.Outcome != "no_effect" {
		return errRenewalPending
	}
	return nil
}

func (s *renewalChoiceService) admittedTransaction(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, f func(context.Context, renewalChoiceTransaction) error) error {
	return s.Authority.Admit(ctx, k, actor, func(guardCtx context.Context) error {
		return s.Store.Transact(guardCtx, k, func(tx renewalChoiceTransaction) error { return f(guardCtx, tx) })
	})
}

func (s *renewalChoiceService) status(ctx context.Context, k renewalChoiceKey, actor uuid.UUID) (renewalChoiceJournal, error) {
	var result renewalChoiceJournal
	if err := s.available(); err != nil {
		return result, err
	}
	if !validRenewalKey(k) || actor == uuid.Nil {
		return result, errRenewalConflict
	}
	err := s.admittedTransaction(ctx, k, actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		if _, err := s.Authority.Authorize(ctx, tx.SQL(), k, actor); err != nil {
			return err
		}
		result = *tx.Journal()
		return nil
	})
	return result, err
}

// Initialization observes the provider outside regional transactions, then
// rechecks the exact actor, acceptance, binding and terms before confirmation.
func (s *renewalChoiceService) initialize(ctx context.Context, k renewalChoiceKey, actor uuid.UUID) error {
	if err := s.available(); err != nil {
		return err
	}
	if !validRenewalKey(k) || actor == uuid.Nil {
		return errRenewalConflict
	}
	var candidate *renewalChoiceOperation
	err := s.admittedTransaction(ctx, k, actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		a, err := s.Authority.Authorize(ctx, tx.SQL(), k, actor)
		if err != nil {
			return err
		}
		j := tx.Journal()
		if j.Confirmed != nil {
			return nil
		}
		if !validRenewalBinding(a.Binding, k) || a.Revision < 0 || a.Acceptance == uuid.Nil {
			return errRenewalConflict
		}
		terms, err := s.Authority.Resolve(ctx, tx.SQL(), k, "annual")
		if err != nil {
			return err
		}
		if err = validateRenewalTerms("annual", terms); err != nil {
			return err
		}
		candidate = &renewalChoiceOperation{ID: uuid.New(), Request: renewalChoiceRequest{ID: uuid.New(), Choice: "annual", ApprovalRevision: a.Revision, Acceptance: a.Acceptance, ChoiceRevision: j.Revision}, Actor: actor, Binding: a.Binding, Terms: terms, State: "confirmed", CreatedAt: tx.Now()}
		return nil
	})
	if err != nil || candidate == nil {
		return err
	}
	op := *candidate
	proof, err := s.Authority.DefaultProof(ctx, k, op)
	if err != nil {
		return err
	}
	return s.admittedTransaction(ctx, k, actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		if err := s.recheck(ctx, tx, k, op); err != nil {
			return err
		}
		j := tx.Journal()
		if j.Confirmed != nil {
			return nil
		}
		if j.Revision != op.Request.ChoiceRevision {
			return errRenewalConflict
		}
		terms, err := s.Authority.Resolve(ctx, tx.SQL(), k, "annual")
		if err != nil {
			return err
		}
		if renewalHash(terms) != renewalHash(op.Terms) {
			return errRenewalConflict
		}
		if err = validateRenewalProof(k, op, proof, tx.Now()); err != nil {
			return err
		}
		if proof.Outcome != "confirmed" {
			return errRenewalConflict
		}
		op.Proof = &proof
		if err = tx.Insert(op); err != nil {
			return err
		}
		j.Confirmed = &op
		j.SuccessorState = "scheduled"
		return tx.Save("default_confirmed")
	})
}

func (s *renewalChoiceService) submit(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, req renewalChoiceRequest) (renewalChoiceJournal, error) {
	var result renewalChoiceJournal
	if err := s.available(); err != nil {
		return result, err
	}
	if !validRenewalKey(k) || actor == uuid.Nil || req.ID == uuid.Nil || req.Acceptance == uuid.Nil || req.ChoiceRevision < 0 || req.ApprovalRevision < 0 {
		return result, errRenewalConflict
	}
	err := s.admittedTransaction(ctx, k, actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		a, err := s.Authority.Authorize(ctx, tx.SQL(), k, actor)
		if err != nil {
			return err
		}
		j := tx.Journal()
		old, err := tx.Find(req.ID)
		if err != nil {
			return err
		}
		if old != nil {
			if old.Actor != actor || old.Request != req {
				return errRenewalConflict
			}
			result = *j
			return nil
		}
		if j.Confirmed == nil || j.Revision != req.ChoiceRevision || a.Revision != req.ApprovalRevision || a.Acceptance != req.Acceptance || !validRenewalBinding(a.Binding, k) || renewalHash(a.Binding) != renewalHash(j.Confirmed.Binding) {
			return errRenewalConflict
		}
		if !tx.Now().Before(k.Boundary) {
			return errRenewalConflict
		}
		if j.Requested != nil && (j.Requested.State == "dispatched" || j.Requested.State == "outcome_unknown") {
			return errRenewalPending
		}
		if !renewalCalendarSupported(req.Choice, a.Binding.Anchor, k.Boundary) {
			return errRenewalDisabled
		}
		terms, err := s.Authority.Resolve(ctx, tx.SQL(), k, req.Choice)
		if err != nil {
			return err
		}
		if err = validateRenewalTerms(req.Choice, terms); err != nil {
			return err
		}
		op := renewalChoiceOperation{ID: uuid.New(), Request: req, Actor: actor, Binding: a.Binding, Terms: terms, State: "prepared", CreatedAt: tx.Now()}
		if err = tx.Insert(op); err != nil {
			return err
		}
		j.Requested = &op
		if err = tx.Save("requested"); err != nil {
			return err
		}
		result = *j
		return nil
	})
	return result, err
}

func (s *renewalChoiceService) recheck(ctx context.Context, tx renewalChoiceTransaction, k renewalChoiceKey, op renewalChoiceOperation) error {
	a, err := s.Authority.Authorize(ctx, tx.SQL(), k, op.Actor)
	if err != nil {
		return err
	}
	if a.Revision != op.Request.ApprovalRevision || a.Acceptance != op.Request.Acceptance || renewalHash(a.Binding) != renewalHash(op.Binding) {
		return errRenewalConflict
	}
	return nil
}

// Dispatch intent is committed before the external call. A crash, lost response,
// or competing worker thereafter may only observe the same operation.
func (s *renewalChoiceService) reconcile(ctx context.Context, k renewalChoiceKey) error {
	if err := s.available(); err != nil {
		return err
	}
	if s.Provider == nil || !validRenewalKey(k) {
		return errRenewalDisabled
	}
	if p, ok := s.Provider.(renewalChoiceStagedProvider); ok {
		return s.reconcileSteps(ctx, k, p)
	}
	var op *renewalChoiceOperation
	err := s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		if current := tx.Journal().Requested; current != nil && (current.State == "prepared" || current.State == "dispatched" || current.State == "outcome_unknown") {
			copy := *current
			op = &copy
		}
		return nil
	})
	if err != nil || op == nil {
		return err
	}
	var proof renewalChoiceProof
	var providerErr error
	directResult := false
	if op.State == "prepared" {
		dispatched := false
		err = s.admittedTransaction(ctx, k, op.Actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
			current := tx.Journal().Requested
			if current == nil || current.ID != op.ID || current.State != "prepared" {
				return nil
			}
			if err := s.recheck(ctx, tx, k, *current); err != nil {
				return err
			}
			if !tx.Now().Before(k.Boundary) {
				current.State = "review_required"
				return tx.Save("boundary_passed_without_dispatch")
			}
			now := tx.Now()
			current.State, current.DispatchedAt = "dispatched", &now
			if err := tx.Save("dispatch_intent"); err != nil {
				return err
			}
			copy := *current
			op = &copy
			dispatched = true
			return nil
		})
		if err != nil || !dispatched {
			return err
		}
		err = s.Authority.DispatchGuard(ctx, k, *op, func(ctx context.Context) error {
			proof, providerErr = s.Provider.Dispatch(ctx, k, *op)
			directResult = true
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		proof, providerErr = s.Provider.Observe(ctx, k, *op)
	}
	return s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		j := tx.Journal()
		current := j.Requested
		if current == nil || current.ID != op.ID {
			return errRenewalConflict
		}
		// An older observation must never undo a newer confirmed result.
		if current.State != "dispatched" && current.State != "outcome_unknown" {
			return nil
		}
		// Absence observed concurrently or after a lost response cannot prove that
		// an in-flight write will not arrive. Only a direct terminal rejection may
		// release the generation fence; observation can confirm but never reject.
		if providerErr != nil || (proof.Outcome == "no_effect" && !directResult) || validateRenewalProof(k, *current, proof, tx.Now()) != nil {
			current.State = "outcome_unknown"
			return tx.Save("provider_outcome_unknown")
		}
		current.Proof = &proof
		if proof.Outcome == "no_effect" {
			current.State = "rejected"
			return tx.Save("provider_rejected_without_effect")
		}
		// Actual provider outcomes remain auditable after revocation. They do not
		// authorize benefits; successor adoption rechecks current guarded authority.
		current.State = "confirmed"
		copy := *current
		j.Confirmed = &copy
		return tx.Save("provider_confirmed")
	})
}

func (s *renewalChoiceService) reconcileSuccessor(ctx context.Context, k renewalChoiceKey) error {
	if err := s.available(); err != nil {
		return err
	}
	if s.Successors == nil || s.Provider == nil || !validRenewalKey(k) {
		return errRenewalDisabled
	}
	var confirmed *renewalChoiceOperation
	var expectedRevision int64
	err := s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		j := tx.Journal()
		if j.Confirmed == nil || tx.Now().Before(k.Boundary) {
			return nil
		}
		copy := *j.Confirmed
		confirmed = &copy
		expectedRevision = j.Revision
		return nil
	})
	if err != nil || confirmed == nil {
		return err
	}
	// Even an initially confirmed default needs actual boundary history. In
	// particular, an unknown newer write may have changed what took effect.
	proof, observeErr := s.Provider.Observe(ctx, k, *confirmed)
	if financial, ok := s.Successors.(renewalChoiceFinancialSuccessors); ok && observeErr == nil && proof.Outcome == "confirmed" && proof.Timing == "boundary_history" && validateRenewalProof(k, *confirmed, proof, time.Now().UTC()) == nil {
		op := *confirmed
		op.Proof = &proof
		return financial.ReconcileFinancial(ctx, k, op, func(ctx context.Context, sql pgx.Tx, apply func() (string, error)) error {
			finish := func(tx renewalChoiceTransaction) error {
				j := tx.Journal()
				if j.Confirmed == nil || j.Confirmed.ID != op.ID || j.Revision != expectedRevision || j.Successor != renewalSuccessorID(k) {
					return errRenewalConflict
				}
				if err := s.recheck(ctx, tx, k, *j.Confirmed); err != nil {
					return err
				}
				if validateRenewalProof(k, *j.Confirmed, proof, tx.Now()) != nil {
					return errRenewalPending
				}
				state, err := apply()
				if err != nil {
					return err
				}
				if state != "payment_pending" && state != "review_required" && !(state == "active" && op.Request.Choice != "free") && !(state == "free" && op.Request.Choice == "free") {
					return errRenewalConflict
				}
				if (j.SuccessorState == "active" || j.SuccessorState == "free") && state != j.SuccessorState {
					return errRenewalPending
				}
				j.SuccessorState, j.Confirmed.Proof = state, &proof
				return tx.Save("successor_" + state)
			}
			if sql == nil {
				return s.admittedTransaction(ctx, k, op.Actor, func(_ context.Context, tx renewalChoiceTransaction) error { return finish(tx) })
			}
			joined, ok := s.Store.(interface {
				WithTx(context.Context, pgx.Tx, renewalChoiceKey, func(renewalChoiceTransaction) error) error
			})
			if !ok {
				return errRenewalDisabled
			}
			return joined.WithTx(ctx, sql, k, finish)
		})
	}
	return s.admittedTransaction(ctx, k, confirmed.Actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
		j := tx.Journal()
		if j.Confirmed == nil || j.Confirmed.ID != confirmed.ID || j.Revision != expectedRevision {
			return errRenewalConflict
		}
		if err := s.recheck(ctx, tx, k, *j.Confirmed); err != nil {
			return err
		}
		if observeErr != nil || proof.Outcome != "confirmed" || proof.Timing != "boundary_history" || validateRenewalProof(k, *j.Confirmed, proof, tx.Now()) != nil {
			if j.SuccessorState == "active" || j.SuccessorState == "free" {
				return errRenewalPending
			}
			j.SuccessorState = "review_required"
			return tx.Save("boundary_verification_required")
		}
		op := *j.Confirmed
		op.Proof = &proof
		state, err := s.Successors.Reconcile(ctx, tx.SQL(), k, op, j.Successor)
		if err != nil {
			return err
		}
		allowed := state == "payment_pending" || state == "active" || state == "review_required"
		if op.Request.Choice == "free" {
			allowed = state == "free" || state == "review_required"
		}
		if !allowed {
			return fmt.Errorf("invalid guarded successor result: %w", errRenewalConflict)
		}
		j.SuccessorState = state
		j.Confirmed.Proof = &proof
		return tx.Save("successor_" + state)
	})
}

// Until payment-to-grant mapping is integrated, all admission and execution paths
// use the same compatibility restriction for differing monthly calendars.
func renewalCalendarSupported(choice string, anchor, boundary time.Time) bool {
	return choice != "monthly" || annualBoundary(boundary, 1).Equal(annualBoundary(anchor, 13))
}
