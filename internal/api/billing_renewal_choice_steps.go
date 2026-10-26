package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const renewalStripeVersion = "2026-05-27.dahlia"

type renewalChoiceStepRequest struct {
	ID          uuid.UUID `json:"id"`
	Kind        string    `json:"kind"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Form        string    `json:"form"`
	Version     string    `json:"version"`
	Merchant    string    `json:"merchant"`
	Live        bool      `json:"live"`
	Idempotency string    `json:"idempotency_key"`
	BindingHash string    `json:"binding_hash"`
	Schedule    string    `json:"schedule,omitempty"`
}
type renewalChoiceStepProof struct {
	RequestHash    string              `json:"request_hash"`
	Outcome        string              `json:"outcome"`
	Schedule       string              `json:"schedule"`
	BindingHash    string              `json:"binding_hash"`
	VerifiedAt     time.Time           `json:"verified_at"`
	Evidence       json.RawMessage     `json:"evidence"`
	Choice         *renewalChoiceProof `json:"choice,omitempty"`
	OriginalChoice *renewalChoiceProof `json:"original_choice,omitempty"`
}
type renewalChoiceStep struct {
	Request renewalChoiceStepRequest `json:"request"`
	State   string                   `json:"state"`
	Proof   *renewalChoiceStepProof  `json:"proof,omitempty"`
}

// PrepareStep and ObserveStep are read-only. DispatchStep sends exactly one
// saved request without retries. A created schedule is not a renewal choice.
type renewalChoiceStagedProvider interface {
	renewalChoiceProvider
	PrepareStep(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceStepRequest, error)
	DispatchStep(context.Context, renewalChoiceKey, renewalChoiceOperation, renewalChoiceStepRequest) (renewalChoiceStepProof, error)
	ObserveStep(context.Context, renewalChoiceKey, renewalChoiceOperation, renewalChoiceStepRequest) (renewalChoiceStepProof, error)
}

func validRenewalStep(op renewalChoiceOperation, r renewalChoiceStepRequest) bool {
	if r.ID != uuid.NewSHA1(op.ID, []byte(r.Kind)) || r.Method != http.MethodPost || r.Version != renewalStripeVersion || r.Merchant != op.Binding.Merchant || r.Live != op.Binding.Live || r.BindingHash != renewalHash(op.Binding) || r.Idempotency != "renewal/"+r.ID.String() || r.Form == "" || len(r.Form) > 65536 {
		return false
	}
	switch r.Kind {
	case "create_schedule":
		return r.Path == "/v1/subscription_schedules" && r.Schedule == "" && len(op.Steps) == 0
	case "update_schedule":
		return strings.HasPrefix(r.Schedule, "sub_sched_") && !strings.ContainsAny(r.Schedule, "/?#") && r.Path == "/v1/subscription_schedules/"+r.Schedule && (len(op.Steps) == 0 || (len(op.Steps) == 1 && op.Steps[0].Request.Kind == "create_schedule" && op.Steps[0].State == "confirmed" && op.Steps[0].Proof != nil && op.Steps[0].Proof.Schedule == r.Schedule))
	}
	return false
}

func (s *renewalChoiceService) reconcileSteps(ctx context.Context, k renewalChoiceKey, p renewalChoiceStagedProvider) error {
	var captured renewalChoiceOperation
	var revision int64
	var boundaryPassed bool
	if err := s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		j := tx.Journal()
		if j.Requested == nil {
			return nil
		}
		captured = *j.Requested
		revision = j.Revision
		boundaryPassed = !tx.Now().Before(k.Boundary)
		return nil
	}); err != nil {
		return err
	}
	if captured.ID == uuid.Nil || (captured.State != "prepared" && captured.State != "dispatched" && captured.State != "outcome_unknown") {
		return nil
	}
	if len(captured.Steps) > 2 {
		return errRenewalConflict
	}
	// A legacy unknown write has no saved stage identity. Switching adapters
	// cannot turn it into a new create/update operation.
	if len(captured.Steps) == 0 && captured.State != "prepared" {
		return errRenewalPending
	}
	needsPlan := len(captured.Steps) == 0 || (len(captured.Steps) == 1 && captured.Steps[0].State == "confirmed" && captured.Steps[0].Request.Kind == "create_schedule")
	if needsPlan {
		if boundaryPassed {
			return s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
				j := tx.Journal()
				if j.Revision != revision || j.Requested == nil || j.Requested.ID != captured.ID {
					return errRenewalConflict
				}
				j.Requested.State = "review_required"
				return tx.Save("boundary_passed_without_step")
			})
		}
		request, err := p.PrepareStep(ctx, k, captured)
		if err != nil {
			return err
		}
		if !validRenewalStep(captured, request) {
			return errRenewalConflict
		}
		return s.admittedTransaction(ctx, k, captured.Actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
			j := tx.Journal()
			if j.Revision != revision || j.Requested == nil || j.Requested.ID != captured.ID {
				return errRenewalConflict
			}
			if err := s.recheck(ctx, tx, k, *j.Requested); err != nil {
				return err
			}
			if !tx.Now().Before(k.Boundary) {
				j.Requested.State = "review_required"
				return tx.Save("boundary_passed_without_step")
			}
			j.Requested.Steps = append(j.Requested.Steps, renewalChoiceStep{Request: request, State: "prepared"})
			// Planning has made no provider write. The first prepared request may still
			// be superseded; a confirmed creation keeps the generation fenced.
			return tx.Save("provider_step_prepared")
		})
	}
	index := len(captured.Steps) - 1
	step := captured.Steps[index]
	var proof renewalChoiceStepProof
	var providerErr error
	direct := false
	if step.State == "prepared" {
		sent := false
		err := s.admittedTransaction(ctx, k, captured.Actor, func(ctx context.Context, tx renewalChoiceTransaction) error {
			j := tx.Journal()
			if j.Requested == nil || j.Requested.ID != captured.ID || len(j.Requested.Steps) != len(captured.Steps) || j.Requested.Steps[index].State != "prepared" {
				return nil
			}
			if err := s.recheck(ctx, tx, k, *j.Requested); err != nil {
				return err
			}
			if !tx.Now().Before(k.Boundary) {
				j.Requested.State = "review_required"
				return tx.Save("boundary_passed_without_step")
			}
			j.Requested.Steps[index].State = "dispatched"
			j.Requested.State = "dispatched"
			now := tx.Now()
			j.Requested.DispatchedAt = &now
			if err := tx.Save("provider_step_dispatch_intent"); err != nil {
				return err
			}
			captured = *j.Requested
			step = captured.Steps[index]
			sent = true
			return nil
		})
		if err != nil || !sent {
			return err
		}
		err = s.Authority.DispatchGuard(ctx, k, captured, func(ctx context.Context) error {
			proof, providerErr = p.DispatchStep(ctx, k, captured, step.Request)
			direct = true
			return nil
		})
		if err != nil {
			return err
		}
	} else if step.State == "dispatched" || step.State == "outcome_unknown" {
		proof, providerErr = p.ObserveStep(ctx, k, captured, step.Request)
	} else {
		return errRenewalConflict
	}
	return s.Store.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		j := tx.Journal()
		if j.Requested == nil || j.Requested.ID != captured.ID || len(j.Requested.Steps) != len(captured.Steps) {
			return errRenewalConflict
		}
		current := &j.Requested.Steps[index]
		if current.State != "dispatched" && current.State != "outcome_unknown" {
			return nil
		}
		valid := providerErr == nil && proof.RequestHash == renewalHash(step.Request) && proof.BindingHash == renewalHash(captured.Binding) && !proof.VerifiedAt.IsZero() && !proof.VerifiedAt.After(tx.Now()) && len(proof.Evidence) > 0 && json.Valid(proof.Evidence)
		if proof.Outcome == "no_effect" && direct && valid {
			current.State = "rejected"
			current.Proof = &proof
			j.Requested.State = "rejected"
			return tx.Save("provider_step_rejected")
		}
		valid = valid && proof.Outcome == "confirmed" && strings.HasPrefix(proof.Schedule, "sub_sched_") && !strings.ContainsAny(proof.Schedule, "/?#")
		if step.Request.Kind == "update_schedule" {
			valid = valid && proof.Schedule == step.Request.Schedule && proof.Choice != nil && proof.Choice.Outcome == "confirmed"
			if valid {
				valid = validateRenewalProof(k, captured, *proof.Choice, tx.Now()) == nil
			}
		}
		if !valid {
			current.State = "outcome_unknown"
			j.Requested.State = "outcome_unknown"
			return tx.Save("provider_step_outcome_unknown")
		}
		current.State = "confirmed"
		current.Proof = &proof
		if step.Request.Kind == "create_schedule" {
			if owned := j.OwnedSchedule; owned != nil {
				if owned.Operation != captured.ID || renewalHash(owned.Request) != renewalHash(step.Request) || owned.Proof.Schedule != proof.Schedule || owned.Proof.BindingHash != proof.BindingHash {
					return errRenewalConflict
				}
			} else {
				j.OwnedSchedule = &renewalChoiceOwnedSchedule{Operation: captured.ID, Request: step.Request, Proof: proof}
			}
			j.Requested.State = "dispatched"
			return tx.Save("provider_schedule_created")
		}
		j.Requested.State = "confirmed"
		j.Requested.Proof = proof.Choice
		copy := *j.Requested
		j.Confirmed = &copy
		return tx.Save("provider_choice_confirmed")
	})
}
