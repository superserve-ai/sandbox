package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Financial receipts authorize one exact regional operation. Historical readback
// after invalidation is recovery evidence, never permission for another effect.
type YCFinancialAuthorization struct {
	AuthorizationID    uuid.UUID  `json:"authorization_id"`
	AcceptanceID       uuid.UUID  `json:"acceptance_id"`
	ClaimID            uuid.UUID  `json:"claim_id"`
	TeamID             uuid.UUID  `json:"team_id"`
	UserID             uuid.UUID  `json:"user_id"`
	HomeRegion         string     `json:"home_region"`
	Company            string     `json:"company_identity"`
	ApprovalID         uuid.UUID  `json:"approval_id"`
	ApprovalRevision   int64      `json:"approval_revision"`
	AssignmentID       uuid.UUID  `json:"assignment_id"`
	Phase              string     `json:"phase"`
	OperationID        uuid.UUID  `json:"operation_id"`
	TermsDigest        string     `json:"terms_digest"`
	RenewalTermsDigest string     `json:"renewal_terms_digest"`
	TargetTermsDigest  string     `json:"target_terms_digest"`
	AuthorizedAt       time.Time  `json:"authorized_at"`
	InvalidatedAt      *time.Time `json:"invalidated_at"`
}
type YCFinancialInvalidation struct {
	InvalidationID  uuid.UUID `json:"invalidation_id"`
	AuthorizationID uuid.UUID `json:"authorization_id"`
	AcceptanceID    uuid.UUID `json:"acceptance_id"`
	TeamID          uuid.UUID `json:"team_id"`
	HomeRegion      string    `json:"home_region"`
	AssignmentID    uuid.UUID `json:"assignment_id"`
	Phase           string    `json:"phase"`
	OperationID     uuid.UUID `json:"operation_id"`
	InvalidatedAt   time.Time `json:"invalidated_at"`
	Reason          string    `json:"reason"`
	LeaseID         uuid.UUID `json:"lease_id"`
}
type YCFinancialState struct {
	Kind                 string `json:"kind"`
	State                string `json:"state"`
	PendingInvalidations int    `json:"pending_invalidations"`
}

func (s YCFinancialState) valid() bool {
	return s.Kind == "accepted_offer" && s.State == "valid" && s.PendingInvalidations == 0
}

func ycFinancialRPC(ctx context.Context, q db.DBTX, op string, p any, out any) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var result json.RawMessage
	if err = q.QueryRow(ctx, `SELECT public.yc_financial_authority_rpc($1,$2::jsonb)`, op, raw).Scan(&result); err != nil {
		return err
	}
	return json.Unmarshal(result, out)
}

// IssueFinancialAuthorization commits before returning. Callers must already
// have frozen/verified the regional operation and target terms. The successor
// owner separately authorizes its requesting actor, which may differ from the
// original accepted user. No regional transaction or provider call spans this.
func (s *YCOfferAcceptanceService) IssueFinancialAuthorization(ctx context.Context, r YCAcceptanceRecord, phase string, operation uuid.UUID, targetDigest string) (YCFinancialAuthorization, error) {
	var result YCFinancialAuthorization
	if !s.available() || r.HomeRegion != s.Region || r.AssignmentID == nil || r.AcceptedAt == nil || r.RequestID == nil || operation == uuid.Nil {
		return result, errYCAcceptanceUnavailable
	}
	if phase != "initial" && phase != "successor" {
		return result, errYCAcceptanceConflict
	}
	if phase == "initial" {
		if err := s.Authorize(ctx, r.UserID, r.TeamID); err != nil {
			return result, err
		}
	}
	p := ycAcceptanceParameters(r)
	p["phase"] = phase
	p["operation_id"] = operation
	p["target_terms_digest"] = targetDigest
	tx, err := s.Shared.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return result, err
	}
	if err = ycFinancialRPC(ctx, tx, "issue", p, &result); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
func (s *YCOfferAcceptanceService) ReadFinancialAuthorization(ctx context.Context, acceptance uuid.UUID, phase string, operation uuid.UUID) (YCFinancialAuthorization, error) {
	var r YCFinancialAuthorization
	if !s.available() {
		return r, errYCAcceptanceUnavailable
	}
	err := ycFinancialRPC(ctx, s.Shared, "read", map[string]any{"acceptance_id": acceptance, "phase": phase, "operation_id": operation}, &r)
	if err == nil && r.HomeRegion != s.Region {
		return r, errYCAcceptanceConflict
	}
	return r, err
}
func (s *YCOfferAcceptanceService) LeaseFinancialInvalidations(ctx context.Context, lease uuid.UUID, limit int) ([]YCFinancialInvalidation, error) {
	var r []YCFinancialInvalidation
	if !s.available() {
		return nil, errYCAcceptanceUnavailable
	}
	err := ycFinancialRPC(ctx, s.Shared, "lease-invalidations", map[string]any{"home_region": s.Region, "lease_id": lease, "limit": limit}, &r)
	return r, err
}

// AcknowledgeFinancialInvalidation is called only after the regional permanent
// target fence and any required commercial-authority revocation commit.
func (s *YCOfferAcceptanceService) AcknowledgeFinancialInvalidation(ctx context.Context, d YCFinancialInvalidation, ack, fence uuid.UUID) error {
	if !s.available() || d.HomeRegion != s.Region {
		return errYCAcceptanceUnavailable
	}
	var out json.RawMessage
	return ycFinancialRPC(ctx, s.Shared, "ack-invalidation", map[string]any{"invalidation_id": d.InvalidationID, "lease_id": d.LeaseID, "home_region": s.Region, "acknowledgement_id": ack, "regional_fence_id": fence}, &out)
}
func (s *YCOfferAcceptanceService) FinancialState(ctx context.Context, claim uuid.UUID) (*YCFinancialState, error) {
	if !s.available() {
		return nil, errYCAcceptanceUnavailable
	}
	var state *YCFinancialState
	err := ycFinancialRPC(ctx, s.Shared, "state", map[string]any{"claim_id": claim, "automated": true}, &state)
	if err == nil && (state == nil || state.Kind != "accepted_offer") {
		return nil, errYCAcceptanceUnavailable
	}
	return state, err
}
