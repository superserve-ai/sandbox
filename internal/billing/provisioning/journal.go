package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func load(ctx context.Context, q querier, team, assignment uuid.UUID) (Operation, error) {
	var o Operation
	var raw []byte
	err := q.QueryRow(ctx, `SELECT id,team_id,assignment_id,accepted_offer,state,held,control_pending,revoked_at,finalized_at FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2`, team, assignment).Scan(&o.ID, &o.TeamID, &o.AssignmentID, &raw, &o.State, &o.Held, &o.ControlPending, &o.RevokedAt, &o.FinalizedAt)
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal(raw, &o.Offer); err != nil {
		return o, err
	}
	o.Requests = make(map[Step]SavedRequest)
	rows, err := q.Query(ctx, `SELECT step,idempotency_key,request,state,dispatched_at,receipt FROM billing_offer_provisioning_request WHERE operation_id=$1`, o.ID)
	if err != nil {
		return o, err
	}
	defer rows.Close()
	for rows.Next() {
		r := SavedRequest{OperationID: o.ID, Offer: o.Offer}
		if err = rows.Scan(&r.Step, &r.Key, &raw, &r.State, &r.DispatchedAt, &r.Receipt); err != nil {
			return o, err
		}
		if err = json.Unmarshal(raw, &r.Request); err != nil {
			return o, err
		}
		o.Requests[r.Step] = r
	}
	return o, rows.Err()
}

func controls(o Operation) error {
	if o.RevokedAt != nil {
		return ErrRevoked
	}
	if o.Held {
		return ErrHeld
	}
	return nil
}

func (s *Service) guarded(ctx context.Context, o Operation, f func(context.Context, pgx.Tx) error) error {
	return s.guardOperation(o, func(f func(context.Context, pgx.Tx, AcceptedOffer) error) error {
		return s.Authority.WithAcceptedOffer(ctx, o.TeamID, o.AssignmentID, f)
	}, f)
}

func (s *Service) guardOperation(o Operation, guard func(func(context.Context, pgx.Tx, AcceptedOffer) error) error, f func(context.Context, pgx.Tx) error) error {
	return guard(func(ctx context.Context, tx pgx.Tx, offer AcceptedOffer) error {
		if err := CheckFinancialTarget(ctx, tx, InitialFinancialTarget(o.TeamID, o.AssignmentID)); err != nil {
			return err
		}
		if err := offer.validate(); err != nil {
			return err
		}
		raw, err := json.Marshal(offer)
		if err != nil {
			return err
		}
		var held, same bool
		var revoked *time.Time
		err = tx.QueryRow(ctx, `SELECT held,revoked_at,accepted_offer=$2::jsonb FROM billing_offer_provisioning_operation WHERE id=$1 FOR UPDATE`, o.ID, raw).Scan(&held, &revoked, &same)
		if err != nil {
			return err
		}
		if !same {
			return ErrConflict
		}
		if revoked != nil {
			return ErrRevoked
		}
		if held {
			return ErrHeld
		}
		return f(ctx, tx)
	})
}

// Reconcile performs at most five writes and one verification. Short transactions
// serialize saved requests and claim each dispatch exactly once. Concurrent calls
// may recover the same receipt read-only, but cannot repeat a provider write.
func (s *Service) Reconcile(ctx context.Context, team, assignment uuid.UUID) (err error) {
	if !s.available() {
		return ErrUnavailable
	}
	o, err := load(ctx, s.Pool, team, assignment)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.recordError(ctx, o.ID, err)
		}
	}()
	if o.FinalizedAt != nil {
		return controls(o)
	}
	for _, step := range steps {
		r, exists := o.Requests[step]
		if exists && r.State == "confirmed" {
			continue
		}
		if !exists {
			if err = controls(o); err != nil {
				return err
			}
			request, e := s.Provider.Prepare(ctx, o, step)
			if e != nil {
				return e
			}
			if e = request.validate(); e != nil {
				return e
			}
			raw, e := json.Marshal(request)
			if e != nil {
				return e
			}
			err = s.guarded(ctx, o, func(ctx context.Context, tx pgx.Tx) error {
				tag, e := tx.Exec(ctx, `INSERT INTO billing_offer_provisioning_request(operation_id,step,idempotency_key,request) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, o.ID, step, key(o.ID, step), raw)
				if e == nil && tag.RowsAffected() != 1 {
					return ErrBusy
				}
				return e
			})
			if err != nil {
				return err
			}
			r = SavedRequest{OperationID: o.ID, Step: step, Key: key(o.ID, step), Offer: o.Offer, Request: request, State: "prepared"}
		}
		var receipt json.RawMessage
		if r.State == "prepared" {
			if err = s.Provider.Preflight(ctx, r); err != nil {
				return err
			}
			err = s.guarded(ctx, o, func(ctx context.Context, tx pgx.Tx) error {
				e := tx.QueryRow(ctx, `UPDATE billing_offer_provisioning_request SET state='dispatched',dispatched_at=clock_timestamp() WHERE operation_id=$1 AND step=$2 AND state='prepared' RETURNING dispatched_at`, o.ID, step).Scan(&r.DispatchedAt)
				if errors.Is(e, pgx.ErrNoRows) {
					return ErrBusy
				}
				return e
			})
			if err != nil {
				return err
			}
			r.State = "dispatched"
			err = s.Authority.WithDispatchGuard(ctx, team, assignment, func(ctx context.Context, current AcceptedOffer) error {
				if current.validate() != nil || !sameOffer(current, o.Offer) {
					return ErrConflict
				}
				var e error
				receipt, e = s.Provider.Create(ctx, r)
				return e
			})
		} else {
			// Recovery records already-created effects even when authority was revoked.
			receipt, err = s.Provider.Recover(ctx, r)
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnknown, err)
		}
		if !object(receipt) {
			return ErrUnknown
		}
		if e := s.confirm(ctx, o.ID, step, receipt); e != nil {
			return fmt.Errorf("%w: %w", ErrUnknown, e)
		}
		o, err = load(ctx, s.Pool, team, assignment)
		if err != nil {
			return err
		}
	}
	if err = controls(o); err != nil {
		return err
	}
	evidence, err := s.Provider.Verify(ctx, o)
	if err != nil {
		return err
	}
	if !object(evidence.Evidence) {
		return ErrUnknown
	}
	return s.guardOperation(o, func(f func(context.Context, pgx.Tx, AcceptedOffer) error) error {
		return s.Authority.WithFinalization(ctx, o, f)
	}, func(ctx context.Context, tx pgx.Tx) error {
		// Re-read inside the transaction so a stale verifier cannot authorize a
		// different operation or finalize twice after a lost commit response.
		current, e := load(ctx, tx, team, assignment)
		if e != nil {
			return e
		}
		if current.FinalizedAt != nil {
			return nil
		}
		for _, step := range steps {
			if current.Requests[step].State != "confirmed" {
				return ErrUnknown
			}
		}
		if e = s.Authority.Finalize(ctx, tx, current, evidence); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE billing_offer_provisioning_operation SET state='grant_pending',verification=$2,finalized_at=clock_timestamp(),last_error=NULL,updated_at=clock_timestamp() WHERE id=$1 AND finalized_at IS NULL`, o.ID, evidence.Evidence)
		return e
	})
}

func (s *Service) confirm(ctx context.Context, id uuid.UUID, step Step, receipt json.RawMessage) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Control uses operation -> request order. Lock even when control_pending is
	// currently false so a concurrent control cannot miss this confirmation.
	if _, err = tx.Exec(ctx, `SELECT id FROM billing_offer_provisioning_operation WHERE id=$1 FOR UPDATE`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE billing_offer_provisioning_request SET state='confirmed',receipt=$3 WHERE operation_id=$1 AND step=$2 AND state='dispatched'`, id, step, receipt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		var same bool
		if err = tx.QueryRow(ctx, `SELECT state='confirmed' AND receipt=$3::jsonb FROM billing_offer_provisioning_request WHERE operation_id=$1 AND step=$2`, id, step, receipt).Scan(&same); err != nil {
			return err
		}
		if !same {
			return ErrConflict
		}
	}
	// Clear only the outstanding-outcome marker, never the desired hold/revoke.
	if _, err = tx.Exec(ctx, `UPDATE billing_offer_provisioning_operation o SET control_pending=false WHERE id=$1 AND control_pending AND NOT EXISTS(SELECT 1 FROM billing_offer_provisioning_request r WHERE r.operation_id=o.id AND r.state='dispatched')`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) recordError(ctx context.Context, id uuid.UUID, err error) {
	if errors.Is(err, ErrBusy) || errors.Is(err, ErrHeld) || errors.Is(err, ErrRevoked) {
		return
	}
	state, code := "review_required", "reconciliation_failed"
	if errors.Is(err, ErrUnknown) {
		state, code = "outcome_unknown", "provider_outcome_unknown"
	}
	ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	// Persist categories only; provider errors may contain account data or secrets.
	_, _ = s.Pool.Exec(ack, `UPDATE billing_offer_provisioning_operation SET state=$2,last_error=$3,next_check_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE id=$1 AND finalized_at IS NULL`, id, state, code)
}

// Control is called only after platform billing authorization by the API adapter.
// Revocation is irreversible; neither recovery nor release can erase its history.
func (s *Service) Control(ctx context.Context, team, assignment, actor uuid.UUID, action, reason string) error {
	if s == nil || s.Pool == nil {
		return ErrUnavailable
	}
	if actor == uuid.Nil || reason == "" || len(reason) > 2000 || (action != "hold" && action != "release" && action != "revoke") {
		return ErrConflict
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	var revoked, finalized *time.Time
	err = tx.QueryRow(ctx, `SELECT id,revoked_at,finalized_at FROM billing_offer_provisioning_operation WHERE team_id=$1 AND assignment_id=$2 FOR UPDATE`, team, assignment).Scan(&id, &revoked, &finalized)
	if err != nil {
		return err
	}
	if revoked != nil {
		return ErrRevoked
	}
	// Finalized commercial authority uses the existing administrative revoke path.
	if finalized != nil {
		return ErrConflict
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_offer_provisioning_request WHERE operation_id=$1 AND state='dispatched')`, id).Scan(&pending); err != nil {
		return err
	}
	if action == "release" && pending {
		return ErrUnknown
	}
	_, err = tx.Exec(ctx, `UPDATE billing_offer_provisioning_operation SET held=CASE WHEN $2='hold' THEN true WHEN $2='release' THEN false ELSE held END,revoked_at=CASE WHEN $2='revoke' THEN clock_timestamp() ELSE revoked_at END,control_actor=$3,control_reason=$4,control_pending=$5,updated_at=clock_timestamp() WHERE id=$1`, id, action, actor, reason, pending)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_offer_provisioning_audit(operation_id,actor_id,action,reason) VALUES($1,$2,$3,$4)`, id, actor, action, reason); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	// A marked POST can still reach the provider. Persist the desired control
	// now, but do not acknowledge a settled outcome until its receipt is known.
	if pending {
		return ErrUnknown
	}
	return nil
}
