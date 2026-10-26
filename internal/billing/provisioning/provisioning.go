// Package provisioning journals initial provider setup. It grants no billing
// authority without the separately verified acceptance and provider adapters.
package provisioning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnavailable = errors.New("automatic provisioning adapter unavailable")
	ErrConflict    = errors.New("provisioning identity or terms conflict")
	ErrUnknown     = errors.New("provider outcome requires recovery")
	ErrBusy        = errors.New("provisioning operation is already running")
	ErrHeld        = errors.New("provisioning is held")
	ErrRevoked     = errors.New("provisioning is revoked")
)

type Step string

const (
	Customer  Step = "customer"
	Waiver    Step = "waiver"
	Fee       Step = "fee"
	Usage     Step = "usage"
	UsageHold Step = "usage_hold"
)

var steps = []Step{Customer, Waiver, Fee, Usage, UsageHold}

// AcceptedOffer comes from durable server authority, never an HTTP request body.
// Snapshot includes the immutable offer version, rates and acceptance terms.
// The commercial anchor is recovered from provider evidence, not acceptance time.
type AcceptedOffer struct {
	AcceptanceID uuid.UUID       `json:"acceptance_id"`
	TermsDigest  string          `json:"terms_digest"`
	Merchant     string          `json:"merchant"`
	Live         bool            `json:"live"`
	APIVersion   string          `json:"api_version"`
	Snapshot     json.RawMessage `json:"snapshot"`
	// ProviderTerms is pinned separately without rewriting the acceptance receipt.
	ProviderTerms json.RawMessage `json:"provider_terms,omitempty"`
}

func (a AcceptedOffer) validate() error {
	if a.AcceptanceID == uuid.Nil || len(a.TermsDigest) != 64 || a.Merchant == "" || a.APIVersion == "" || !object(a.Snapshot) {
		return ErrConflict
	}
	if len(a.ProviderTerms) > 0 && !object(a.ProviderTerms) {
		return ErrConflict
	}
	if _, err := hex.DecodeString(a.TermsDigest); err != nil {
		return ErrConflict
	}
	return nil
}

type Operation struct {
	ID, TeamID, AssignmentID uuid.UUID
	Offer                    AcceptedOffer
	State                    string
	Held                     bool
	ControlPending           bool
	RevokedAt, FinalizedAt   *time.Time
	Requests                 map[Step]SavedRequest
}
type Request struct {
	// Payload is the exact provider body; it must exclude secrets.
	Method  string `json:"method"`
	Path    string `json:"path"`
	Payload string `json:"payload"`
	SHA256  string `json:"sha256"`
}

func NewRequest(path, payload string) Request {
	hash := sha256.Sum256([]byte(payload))
	return Request{Method: "POST", Path: path, Payload: payload, SHA256: hex.EncodeToString(hash[:])}
}
func (r Request) validate() error {
	if r.Method != "POST" || r.Path == "" || len(r.Payload) > 128*1024 || r.SHA256 != NewRequest(r.Path, r.Payload).SHA256 {
		return ErrConflict
	}
	return nil
}

type SavedRequest struct {
	OperationID  uuid.UUID
	Step         Step
	Key          string
	Offer        AcceptedOffer
	Request      Request
	State        string
	DispatchedAt *time.Time
	Receipt      json.RawMessage
}

// WithAcceptedOffer serializes team/account and current shared approval authority,
// validates durable acceptance, region, rollout and all new-signup conflict guards,
// then invokes f inside that transaction using its guard-owned context. It must reject revoked/changed authority.
// This guard authorizes pending metadata only. It is insufficient for benefit
// activation when shared and regional databases can commit independently.
type Admission interface {
	WithAcceptedOffer(context.Context, uuid.UUID, uuid.UUID, func(context.Context, pgx.Tx, AcceptedOffer) error) error
	// The regional dispatch marker is already committed. Recheck the exact
	// acceptance and retain shared approval authority across f; hold no regional
	// row locks, and do not acquire them from f. Revocation must wait for f.
	WithDispatchGuard(context.Context, uuid.UUID, uuid.UUID, func(context.Context, AcceptedOffer) error) error
}

// Verification retains the verifier's in-process proof through finalization. Only
// Evidence is journaled; a restart must obtain fresh proof through Verify.
type Verification struct {
	Evidence json.RawMessage
	Proof    any
}

type Activation interface {
	// WithFinalization requires durable activation authorization and regional
	// fencing against revocation. A session lock or cancellation alone cannot
	// authorize this transaction across independently committing databases.
	WithFinalization(context.Context, Operation, func(context.Context, pgx.Tx, AcceptedOffer) error) error
	Finalize(context.Context, pgx.Tx, Operation, Verification) error
	Readiness(context.Context, Operation) (Readiness, error)
}
type Authority interface {
	Admission
	Activation
}

func sameOffer(a, b AcceptedOffer) bool {
	decode := func(v AcceptedOffer) any {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return nil
		}
		return value
	}
	x, y := decode(a), decode(b)
	return x != nil && y != nil && equalJSON(x, y)
}

// Match JSONB numeric equality without losing large integers through float64.
func equalJSON(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(string(x))
		if !ok {
			return false
		}
		s, ok := new(big.Rat).SetString(string(y))
		return ok && r.Cmp(s) == 0
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equalJSON(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// Prepare and Recover are read-only. Recover must prove the original request's
// identity using complete inventory and saved provider evidence. In particular,
// absence after an uncertain dispatch is not permission to POST another object.
// Create must disable transport retries: the journal permits only one dispatch.
// Verify checks the complete pair, original calendar, bounded waiver and inventory.
type Provider interface {
	Prepare(context.Context, Operation, Step) (Request, error)
	// Preflight performs retryable reads before the irreversible dispatch marker.
	Preflight(context.Context, SavedRequest) error
	Create(context.Context, SavedRequest) (json.RawMessage, error)
	Recover(context.Context, SavedRequest) (json.RawMessage, error)
	Verify(context.Context, Operation) (Verification, error)
}

type Service struct {
	Pool      *pgxpool.Pool
	Authority Authority
	Provider  Provider
}

func (s *Service) available() bool {
	return s != nil && s.Pool != nil && s.Authority != nil && s.Provider != nil
}

func (s *Service) Enqueue(ctx context.Context, team, assignment uuid.UUID) (uuid.UUID, error) {
	if !s.available() {
		return uuid.Nil, ErrUnavailable
	}
	if team == uuid.Nil || assignment == uuid.Nil {
		return uuid.Nil, ErrConflict
	}
	var id uuid.UUID
	err := s.Authority.WithAcceptedOffer(ctx, team, assignment, func(ctx context.Context, tx pgx.Tx, offer AcceptedOffer) error {
		if err := offer.validate(); err != nil {
			return err
		}
		if err := CheckFinancialTarget(ctx, tx, InitialFinancialTarget(team, assignment)); err != nil {
			return err
		}
		raw, err := json.Marshal(offer)
		if err != nil {
			return err
		}
		// The authority adapter holds the same team/account locks as manual setup.
		id = uuid.New()
		_, err = tx.Exec(ctx, `INSERT INTO billing_offer_provisioning_operation(id,team_id,assignment_id,accepted_offer) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, team, assignment, raw)
		if err != nil {
			return err
		}
		var same bool
		err = tx.QueryRow(ctx, `SELECT id,accepted_offer=$3::jsonb FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2`, team, assignment, raw).Scan(&id, &same)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !same) {
			return ErrConflict
		}
		return err
	})
	return id, err
}

func object(raw json.RawMessage) bool {
	var v map[string]json.RawMessage
	return len(raw) > 0 && json.Unmarshal(raw, &v) == nil && v != nil
}
func key(id uuid.UUID, step Step) string { return fmt.Sprintf("offer-provisioning/%s/%s/v1", id, step) }

// Readiness is a fresh same-identity observation from the existing billing gate.
// ValidUntil bounds the observation; readiness never becomes permanent history.
type Readiness struct {
	AuthorityValid, PairVerified, AssignmentMaterialized, InvoiceEnrolled bool
	InventoryKnown, DebtClear, CurrentGrantEligible, FundingFresh         bool
	PositiveFunds, BillingEligible, Exhausted, PaymentNeeded              bool
	ValidUntil                                                            time.Time
}
type Status struct {
	OperationID    uuid.UUID `json:"operation_id"`
	State          string    `json:"state"`
	Ready          bool      `json:"ready"`
	Held           bool      `json:"held"`
	Revoked        bool      `json:"revoked"`
	ControlPending bool      `json:"control_pending"`
}

func project(o Operation, r Readiness, now time.Time) Status {
	out := Status{OperationID: o.ID, State: o.State, Held: o.Held, Revoked: o.RevokedAt != nil, ControlPending: o.ControlPending}
	switch {
	case o.ControlPending:
		out.State = "outcome_unknown"
	case o.RevokedAt != nil:
		out.State = "revoked"
	case o.Held:
		out.State = "held"
	case o.FinalizedAt == nil: // Preserve unknown/review rather than imply absence.
	case !r.AuthorityValid || !r.PairVerified || !r.AssignmentMaterialized || !r.InvoiceEnrolled || !r.InventoryKnown || !r.ValidUntil.After(now):
		out.State = "review_required"
	case r.PaymentNeeded:
		out.State = "payment_needed"
	case !r.DebtClear:
		out.State = "review_required"
	case !r.CurrentGrantEligible:
		out.State = "grant_pending"
	case !r.FundingFresh:
		out.State = "funding_pending"
	case r.Exhausted && !r.PositiveFunds:
		out.State = "exhausted"
	case r.PositiveFunds && !r.Exhausted && r.BillingEligible:
		out.State = "funding_ready"
		out.Ready = true
	default:
		out.State = "funding_pending"
	}
	return out
}

func (s *Service) Status(ctx context.Context, team, assignment uuid.UUID) (Status, error) {
	if !s.available() {
		return Status{State: "unavailable"}, ErrUnavailable
	}
	o, err := load(ctx, s.Pool, team, assignment)
	if err != nil {
		return Status{}, err
	}
	revoked, err := financialTargetRevoked(ctx, s.Pool, InitialFinancialTarget(team, assignment))
	if err != nil {
		return Status{OperationID: o.ID, State: "review_required"}, err
	}
	if revoked {
		return Status{OperationID: o.ID, State: "revoked", Revoked: true, Held: o.Held, ControlPending: o.ControlPending}, nil
	}
	var r Readiness
	if o.FinalizedAt != nil && !o.Held && o.RevokedAt == nil {
		r, err = s.Authority.Readiness(ctx, o)
		if err != nil {
			return Status{OperationID: o.ID, State: "review_required"}, err
		}
	}
	return project(o, r, time.Now()), nil
}
