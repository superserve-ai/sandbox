package provisioning

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (s *Service) Available() bool { return s.available() }

func (s *Service) PendingDispatches(ctx context.Context) (int64, time.Duration, error) {
	if s == nil || s.Pool == nil {
		return 0, 0, ErrUnavailable
	}
	var count int64
	var seconds float64
	err := s.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(EXTRACT(EPOCH FROM clock_timestamp()-min(dispatched_at)),0)::float8 FROM billing_offer_provisioning_request WHERE state='dispatched'`).Scan(&count, &seconds)
	return count, time.Duration(seconds * float64(time.Second)), err
}

// RunBatch reserves bounded capacity before releasing row locks. Reconcile uses
// durable dispatch claims for concurrent operator recovery; reservation expiry
// alone never authorizes repeating a provider create.
func (s *Service) RunBatch(ctx context.Context) (int, error) {
	if !s.available() {
		return 0, ErrUnavailable
	}
	rows, err := s.Pool.Query(ctx, `WITH due AS (
 SELECT o.id FROM billing_offer_provisioning_operation o
 WHERE o.finalized_at IS NULL AND o.next_check_at<=clock_timestamp()
 AND ((NOT o.held AND o.revoked_at IS NULL) OR EXISTS(
 SELECT 1 FROM billing_offer_provisioning_request r WHERE r.operation_id=o.id AND r.state='dispatched'))
 ORDER BY o.next_check_at,o.id FOR UPDATE SKIP LOCKED LIMIT 2
 ) UPDATE billing_offer_provisioning_operation o SET next_check_at=clock_timestamp()+interval '2 minutes'
 FROM due WHERE o.id=due.id RETURNING o.team_id,o.assignment_id`)
	if err != nil {
		return 0, err
	}
	type job struct{ team, assignment uuid.UUID }
	var jobs []job
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.team, &j.assignment); err != nil {
			break
		}
		jobs = append(jobs, j)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	var failures []error
	for _, j := range jobs {
		work, cancel := context.WithTimeout(ctx, 45*time.Second)
		err = s.Reconcile(work, j.team, j.assignment)
		cancel()
		if err != nil && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrHeld) && !errors.Is(err, ErrRevoked) {
			failures = append(failures, err)
		}
	}
	return len(jobs), errors.Join(failures...)
}
