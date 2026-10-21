package provisioning

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FinancialTarget is permanent even when its regional operation has not arrived.
// Initial targets use the assignment ID; successors use their stable shared authorization operation ID.
type FinancialTarget struct {
	TeamID       uuid.UUID `json:"team_id"`
	AssignmentID uuid.UUID `json:"assignment_id"`
	Phase        string    `json:"phase"`
	TargetID     uuid.UUID `json:"target_id"`
}

func (t FinancialTarget) valid() bool {
	return t.TeamID != uuid.Nil && t.AssignmentID != uuid.Nil && t.TargetID != uuid.Nil &&
		(t.Phase == "initial" && t.TargetID == t.AssignmentID || t.Phase == "successor" && t.TargetID != t.AssignmentID)
}

func InitialFinancialTarget(team, assignment uuid.UUID) FinancialTarget {
	return FinancialTarget{TeamID: team, AssignmentID: assignment, Phase: "initial", TargetID: assignment}
}

// FinancialAuthorization must be read from committed shared authority by the
// trusted adapter. The regional fence does not turn user JSON into authorization.
type FinancialAuthorization struct {
	ID                uuid.UUID       `json:"authorization_id"`
	Target            FinancialTarget `json:"target"`
	OperationID       uuid.UUID       `json:"operation_id"`
	AcceptanceID      uuid.UUID       `json:"acceptance_id"`
	ApprovalRevision  int64           `json:"approval_revision"`
	HomeRegion        string          `json:"home_region"`
	TermsDigest       string          `json:"terms_digest"`
	TargetTermsDigest string          `json:"target_terms_digest"`
	// Boundary is zero for initial activation; successors retain original B.
	Boundary time.Time `json:"boundary"`
}

func (a FinancialAuthorization) valid() bool {
	digest, err := hex.DecodeString(a.TermsDigest)
	targetDigest, targetErr := hex.DecodeString(a.TargetTermsDigest)
	return (a.Target.Phase != "successor" || a.Target.TargetID == a.OperationID) && targetErr == nil && len(targetDigest) == 32 && (a.Target.Phase != "initial" || a.TargetTermsDigest == a.TermsDigest) && err == nil && len(digest) == 32 && a.ID != uuid.Nil && a.Target.valid() && a.OperationID != uuid.Nil && a.AcceptanceID != uuid.Nil && a.ApprovalRevision >= 0 && a.HomeRegion != "" &&
		len(a.TermsDigest) == 64 && (a.Target.Phase == "initial" && a.Boundary.IsZero() || a.Target.Phase == "successor" && a.Boundary.Unix() > 0 && a.Boundary.Nanosecond() == 0)
}

type financialFence struct {
	receipt            json.RawMessage
	finalized, revoked *time.Time
}

// All callers acquire their regional team/account locks before this fence, and
// the operation lock afterwards. No network calls may run while it is held.
func lockFinancialTarget(ctx context.Context, tx pgx.Tx, target FinancialTarget) (financialFence, error) {
	var f financialFence
	if tx == nil || !target.valid() {
		return f, ErrConflict
	}
	_, err := tx.Exec(ctx, `INSERT INTO billing_offer_financial_fence(team_id,assignment_id,phase,target_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, target.TeamID, target.AssignmentID, target.Phase, target.TargetID)
	if err != nil {
		return f, err
	}
	err = tx.QueryRow(ctx, `SELECT authorization_receipt,finalized_at,revoked_at FROM billing_offer_financial_fence WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4 FOR UPDATE`, target.TeamID, target.AssignmentID, target.Phase, target.TargetID).Scan(&f.receipt, &f.finalized, &f.revoked)
	return f, err
}

// CheckFinancialTarget rejects delayed creation or pending work after effective
// revocation. It creates no financial authority and never clears a tombstone.
func CheckFinancialTarget(ctx context.Context, tx pgx.Tx, target FinancialTarget) error {
	f, err := lockFinancialTarget(ctx, tx, target)
	if err != nil {
		return err
	}
	if f.revoked != nil {
		return ErrRevoked
	}
	return nil
}

// FinalizeFinancialAuthorization runs SQL-only materialization and its finalized
// receipt under the same durable fence. Caller commits or rolls back the entire
// transaction, including its operation finalized_at. Identical replay is a no-op.
func FinalizeFinancialAuthorization(ctx context.Context, tx pgx.Tx, a FinancialAuthorization, materialize func(context.Context, pgx.Tx) error) error {
	if !a.valid() || materialize == nil {
		return ErrConflict
	}
	f, err := lockFinancialTarget(ctx, tx, a.Target)
	if err != nil {
		return err
	}
	if f.revoked != nil {
		return ErrRevoked
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if len(f.receipt) > 0 {
		var same bool
		if err = tx.QueryRow(ctx, `SELECT authorization_receipt=$5::jsonb FROM billing_offer_financial_fence WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4`, a.Target.TeamID, a.Target.AssignmentID, a.Target.Phase, a.Target.TargetID, raw).Scan(&same); err != nil {
			return err
		}
		if !same {
			return ErrConflict
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE billing_offer_financial_fence SET authorization_receipt=$5 WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4`, a.Target.TeamID, a.Target.AssignmentID, a.Target.Phase, a.Target.TargetID, raw); err != nil {
			return err
		}
	}
	if f.finalized != nil {
		return nil
	}
	if err = materialize(ctx, tx); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_offer_financial_fence SET finalized_at=clock_timestamp() WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4`, a.Target.TeamID, a.Target.AssignmentID, a.Target.Phase, a.Target.TargetID)
	return err
}

// RevokeFinancialTarget acknowledges only a committed local fence and, when
// already finalized, SQL revocation of commercial authority. Provider request
// recovery is independent and cannot clear this financial revocation receipt.
func RevokeFinancialTarget(ctx context.Context, tx pgx.Tx, target FinancialTarget, invalidation uuid.UUID, revokeFinalized func(context.Context, pgx.Tx, FinancialAuthorization) error) error {
	if invalidation == uuid.Nil {
		return ErrConflict
	}
	f, err := lockFinancialTarget(ctx, tx, target)
	if err != nil {
		return err
	}
	if f.revoked == nil && f.finalized != nil {
		if revokeFinalized == nil {
			return ErrUnavailable
		}
		var a FinancialAuthorization
		if json.Unmarshal(f.receipt, &a) != nil || !a.valid() || a.Target != target {
			return ErrConflict
		}
		if err = revokeFinalized(ctx, tx, a); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_offer_financial_revocation(id,team_id,assignment_id,phase,target_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING`, invalidation, target.TeamID, target.AssignmentID, target.Phase, target.TargetID)
	if err != nil {
		return err
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT team_id=$2 AND assignment_id=$3 AND phase=$4 AND target_id=$5 FROM billing_offer_financial_revocation WHERE id=$1`, invalidation, target.TeamID, target.AssignmentID, target.Phase, target.TargetID).Scan(&same); err != nil {
		return err
	}
	if !same {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE billing_offer_financial_fence SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4`, target.TeamID, target.AssignmentID, target.Phase, target.TargetID)
	return err
}

func financialTargetRevoked(ctx context.Context, q querier, t FinancialTarget) (bool, error) {
	var revoked bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_offer_financial_fence WHERE team_id=$1 AND assignment_id=$2 AND phase=$3 AND target_id=$4 AND revoked_at IS NOT NULL)`, t.TeamID, t.AssignmentID, t.Phase, t.TargetID).Scan(&revoked)
	return revoked, err
}

type FinancialRevocationReceipt struct {
	InvalidationID    uuid.UUID
	AcknowledgementID uuid.UUID
	FenceID           uuid.UUID
}

// LoadFinancialRevocationReceipt must use the pool after the revocation commit,
// including after a lost commit response. Only this durable readback may be sent
// to shared authority as an effective revocation acknowledgement.
func LoadFinancialRevocationReceipt(ctx context.Context, q querier, t FinancialTarget, invalidation uuid.UUID) (FinancialRevocationReceipt, error) {
	var receipt FinancialRevocationReceipt
	err := q.QueryRow(ctx, `SELECT r.id,r.acknowledgement_id,f.id FROM billing_offer_financial_revocation r
 JOIN billing_offer_financial_fence f USING(team_id,assignment_id,phase,target_id)
 WHERE r.id=$1 AND r.team_id=$2 AND r.assignment_id=$3 AND r.phase=$4 AND r.target_id=$5 AND f.revoked_at IS NOT NULL`, invalidation, t.TeamID, t.AssignmentID, t.Phase, t.TargetID).Scan(&receipt.InvalidationID, &receipt.AcknowledgementID, &receipt.FenceID)
	return receipt, err
}
