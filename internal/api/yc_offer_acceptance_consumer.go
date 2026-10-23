package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *YCOfferAcceptanceService) Status(ctx context.Context, user, team, claim uuid.UUID) (YCAcceptanceRecord, error) {
	var r YCAcceptanceRecord
	if !s.available() {
		return r, errYCAcceptanceUnavailable
	}
	if err := s.Authorize(ctx, user, team); err != nil {
		return r, err
	}
	r, err := loadYCAcceptance(ctx, s.Pool, team, claim)
	if err != nil {
		return r, err
	}
	if r.UserID != user || r.HomeRegion != s.Region {
		return r, errYCAcceptanceConflict
	}
	r.FinancialAuthority, err = s.FinancialState(ctx, claim)
	if err != nil {
		return r, err
	}
	if !r.FinancialAuthority.valid() {
		if r.FinancialAuthority.State != "acceptance_pending" {
			r.State = "review_required"
		} else if r.AcceptedAt == nil || r.State == "confirming" {
			// Pending shared state does not identify the locally disclosed approval.
			// Offer compares current authority with that immutable saved snapshot.
			if _, err = s.Offer(ctx, user, team, claim); err != nil {
				return r, err
			}
		}
		return r, nil
	}
	if r.AcceptedAt == nil || r.State == "confirming" {
		return r, nil
	}
	if r.State == "held" || r.State == "revoked" {
		return r, nil
	}
	if r.OperationID != nil && r.AssignmentID != nil {
		if s.Provisioning == nil {
			r.State = "unavailable"
			return r, nil
		}
		status, e := s.Provisioning.Status(ctx, team, *r.AssignmentID)
		if e != nil {
			r.State = "unavailable"
			return r, nil
		}
		if status.OperationID != *r.OperationID {
			r.State = "review_required"
			return r, nil
		}
		// Provider readiness can become true while a previously committed permit
		// is being invalidated. Read shared authority after that observation so two
		// states that were never valid together cannot synthesize readiness.
		r.FinancialAuthority, err = s.FinancialState(ctx, claim)
		if err != nil {
			return r, err
		}
		if !r.FinancialAuthority.valid() {
			r.State = "review_required"
			return r, nil
		}
		r.State = status.State
		r.Held, r.Revoked, r.ControlPending = status.Held, status.Revoked, status.ControlPending
		r.Ready = status.State == "funding_ready" && status.Ready && !status.Held && !status.Revoked && !status.ControlPending
	}
	return r, nil
}

// RunOnce leases at most one durable item. No database transaction spans an
// adapter call. Lost acknowledgements replay the same acceptance and assignment.
func (s *YCOfferAcceptanceService) RunOnce(ctx context.Context) (bool, error) {
	if !s.available() || s.Catalog == nil || s.Provisioning == nil {
		return false, errYCAcceptanceUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	lease := uuid.New()
	var team, claim uuid.UUID
	var priorAttempts int
	err := s.Pool.QueryRow(ctx, `WITH due AS (SELECT id,attempts FROM yc_offer_acceptance WHERE home_region=$1
 AND (state IN ('confirming','accepted','assignment_linked') OR (state='held' AND assignment_id IS NOT NULL AND operation_id IS NULL)) AND next_attempt_at<=clock_timestamp()
 AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
 UPDATE yc_offer_acceptance a SET lease_id=$2,lease_until=clock_timestamp()+interval '2 minutes',attempts=LEAST(8,a.attempts+1)
 FROM due WHERE a.id=due.id RETURNING a.team_id,a.claim_id,due.attempts`, s.Region, lease).Scan(&team, &claim, &priorAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	r, err := loadYCAcceptance(ctx, s.Pool, team, claim)
	if err == nil {
		if priorAttempts >= 8 || r.State == "held" {
			err = s.recoverExhausted(ctx, r, lease)
		} else {
			err = s.advance(ctx, &r, lease)
		}
	}
	if err != nil {
		state := ""
		category := "dependency_unavailable"
		var pg *pgconn.PgError
		if errors.Is(err, errYCAcceptanceConflict) || (errors.As(err, &pg) && (pg.Code == "22023" || pg.Code == "23505")) {
			state = "held"
			category = "authority_or_terms_conflict"
		}
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		_, saveErr := s.Pool.Exec(cleanup, `UPDATE yc_offer_acceptance SET state=CASE WHEN $3<>'' THEN $3 WHEN attempts>=8 THEN 'held' ELSE state END,
 last_error=$4,lease_id=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '30 seconds'*LEAST(60,power(2,attempts)::integer)
 WHERE team_id=$1 AND lease_id=$2`, team, lease, state, category)
		if saveErr != nil {
			return true, saveErr
		}
	}
	return true, err
}

// Recovery after the write budget expires can only attach an already committed
// exact journal. It never calls Enqueue or creates provider effects.
func (s *YCOfferAcceptanceService) recoverExhausted(ctx context.Context, r YCAcceptanceRecord, lease uuid.UUID) error {
	if r.AssignmentID != nil {
		if recovery, ok := s.Provisioning.(interface {
			RecoverAcceptance(context.Context, YCAcceptanceRecord) (uuid.UUID, bool, error)
		}); ok {
			operation, found, err := recovery.RecoverAcceptance(ctx, r)
			if err != nil {
				return err
			}
			if found {
				tag, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET operation_id=$3,state='dispatched',lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_id=$2`, r.ID, lease, operation)
				if err == nil && tag.RowsAffected() != 1 {
					return errYCAcceptanceConflict
				}
				return err
			}
		}
	}
	_, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET state='held',lease_id=NULL,lease_until=NULL,last_error='retry_exhausted',next_attempt_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 AND lease_id=$2`, r.ID, lease)
	return err
}

func (s *YCOfferAcceptanceService) advance(ctx context.Context, r *YCAcceptanceRecord, lease uuid.UUID) error {
	if r.UserID == uuid.Nil || r.AcceptedAt == nil || r.RequestID == nil || r.HomeRegion != s.Region {
		return errYCAcceptanceConflict
	}
	if err := s.Authorize(ctx, r.UserID, r.TeamID); err != nil {
		return err
	}
	if r.State == "confirming" {
		if _, err := s.rpc(ctx, s.Shared, "accept", ycAcceptanceParameters(*r)); err != nil {
			return err
		}
		tag, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET state='accepted' WHERE id=$1 AND lease_id=$2 AND state='confirming'`, r.ID, lease)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errYCAcceptanceConflict
		}
		r.State = "accepted"
	}
	if r.State == "accepted" {
		// Assign validates the original pinned terms and current shared authority
		// through its regional commit; it cannot resolve current prices on retry.
		assignment, err := s.Catalog.Assign(ctx, *r)
		if err != nil {
			return err
		}
		if assignment == uuid.Nil {
			return errYCAcceptanceConflict
		}
		r.AssignmentID = &assignment
		if _, err = s.rpc(ctx, s.Shared, "link", ycAcceptanceParameters(*r)); err != nil {
			return err
		}
		tag, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET assignment_id=$3,state='assignment_linked' WHERE id=$1 AND lease_id=$2 AND state='accepted'`, r.ID, lease, assignment)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errYCAcceptanceConflict
		}
		r.State = "assignment_linked"
	}
	if r.State == "assignment_linked" {
		if r.AssignmentID == nil {
			return errYCAcceptanceConflict
		}
		if err := s.WithGuard(ctx, *r, func(context.Context) error { return nil }); err != nil {
			return err
		}
		operation, err := s.Provisioning.Enqueue(ctx, r.TeamID, *r.AssignmentID)
		if err != nil {
			return err
		}
		if operation == uuid.Nil {
			return errYCAcceptanceConflict
		}
		tag, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET operation_id=$3,state='dispatched',lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_id=$2 AND state='assignment_linked'`, r.ID, lease, operation)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errYCAcceptanceConflict
		}
	}
	return nil
}

func (h *Handlers) StartYCOfferAcceptance(ctx context.Context) {
	if h.YCOfferAcceptance == nil && h.Pool != nil && h.PromotionAuthPool != nil {
		service := &YCOfferAcceptanceService{Pool: h.Pool, Shared: h.PromotionAuthPool, Region: ycClaimRegion(), Authorize: h.authorizeYCAcceptance}
		service.Catalog = ycAcceptedCatalog{h: h, s: service}
		h.YCOfferAcceptance = service
	}
	s := h.YCOfferAcceptance
	if s.available() && s.Provisioning == nil && h.OfferProvisioning.Available() {
		s.Provisioning = ycAcceptanceProvisioner{service: h.OfferProvisioning}
	}
	if !s.available() || s.Catalog == nil || s.Provisioning == nil {
		return
	}
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()
		nextSample := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			worked, err := s.RunOnce(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Warn("offer acceptance handoff deferred", "category", "dependency_or_authority")
			}
			if time.Now().After(nextSample) {
				sampleCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				var count int64
				var oldest float64
				err := s.Pool.QueryRow(sampleCtx, `SELECT count(*),COALESCE(max(extract(epoch FROM clock_timestamp()-accepted_at)),0) FROM (SELECT accepted_at FROM yc_offer_acceptance WHERE home_region=$1 AND state IN ('confirming','accepted','assignment_linked','held') AND accepted_at<clock_timestamp()-interval '30 minutes' ORDER BY accepted_at LIMIT 1000) pending`, s.Region).Scan(&count, &oldest)
				if err != nil {
					count = -1
					oldest = 0
				}
				currentBillingRecorder().RecordBillingBacklog(sampleCtx, "yc_offer_acceptance", count, oldest)
				cancel()
				nextSample = time.Now().Add(time.Minute)
			}
			delay := 15 * time.Second
			if worked && err == nil {
				delay = time.Second
			}
			timer.Reset(delay)
		}
	}()
}
