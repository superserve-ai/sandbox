package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const renewalChoicePageSize = 16

type renewalChoiceCandidate struct {
	Key     renewalChoiceKey
	Pending bool
	Due     bool
}

type renewalChoiceWorker struct {
	Pool    *pgxpool.Pool
	Service *renewalChoiceService
	cursor  *renewalChoiceKey
}

// Read a bounded primary-key range, including inactive rows. Filtering on the
// JSON state in SQL would let a small LIMIT hide an unbounded scan. The cursor
// advances past failed work so one unresolved operation cannot starve others.
func (w *renewalChoiceWorker) page(ctx context.Context) ([]renewalChoiceCandidate, error) {
	query := `SELECT team_id,assignment_id,intended_boundary,
 COALESCE(snapshot->'requested'->>'state' IN ('prepared','dispatched','outcome_unknown'),false),
 intended_boundary<=clock_timestamp() AND COALESCE(snapshot->>'successor_state' IN ('scheduled','payment_pending','review_required'),false)
 FROM billing_renewal_choice`
	args := []any{}
	if w.cursor != nil {
		query += ` WHERE (team_id,assignment_id,intended_boundary)>($1,$2,$3)`
		args = append(args, w.cursor.Team, w.cursor.Assignment, w.cursor.Boundary)
	}
	query += ` ORDER BY team_id,assignment_id,intended_boundary LIMIT 16`
	rows, err := w.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]renewalChoiceCandidate, 0, renewalChoicePageSize)
	for rows.Next() {
		var c renewalChoiceCandidate
		if err = rows.Scan(&c.Key.Team, &c.Key.Assignment, &c.Key.Boundary, &c.Pending, &c.Due); err != nil {
			return nil, err
		}
		c.Key.Boundary = c.Key.Boundary.UTC()
		result = append(result, c)
	}
	return result, rows.Err()
}

func (w *renewalChoiceWorker) tick(ctx context.Context) (attempted, failed int, err error) {
	if w.Pool == nil || w.Service.available() != nil || w.Service.Provider == nil {
		return 0, 0, errRenewalDisabled
	}
	candidates, err := w.page(ctx)
	if err != nil {
		return 0, 0, err
	}
	if len(candidates) == 0 {
		w.cursor = nil
		return 0, 0, nil
	}
	for _, c := range candidates {
		if err = ctx.Err(); err != nil {
			return attempted, failed, err
		}
		if c.Pending || (c.Due && w.Service.Successors != nil) {
			attempted++
			itemFailed := false
			if c.Pending {
				itemCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				itemFailed = w.Service.reconcile(itemCtx, c.Key) != nil
				cancel()
			}
			if err = ctx.Err(); err != nil {
				return attempted, failed, err
			}
			// Reconciliation re-reads the journal and DB time; this page grants no
			// authority. Benefit activation requires its separately registered port.
			if c.Due && w.Service.Successors != nil {
				itemCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				if w.Service.reconcileSuccessor(itemCtx, c.Key) != nil {
					itemFailed = true
				}
				cancel()
			}
			if err = ctx.Err(); err != nil {
				return attempted, failed, err
			}
			if itemFailed {
				failed++
			}
		}
		key := c.Key
		w.cursor = &key
	}
	return attempted, failed, nil
}

// Registration is explicit; no main/startup caller enables this worker yet.
func (h *Handlers) StartRenewalChoiceService(ctx context.Context) {
	if h.Pool == nil || h.RenewalChoices.available() != nil || h.RenewalChoices.Provider == nil {
		return
	}
	w := &renewalChoiceWorker{Pool: h.Pool, Service: h.RenewalChoices}
	go func() {
		timer := time.NewTimer(time.Duration(uuid.New()[0]%10+1) * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			tickCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			attempted, failed, err := w.tick(tickCtx)
			cancel()
			if err != nil || failed != 0 {
				// Provider errors may contain sensitive evidence; report counts only.
				log.Warn().Int("attempted", attempted).Int("failed", failed).Bool("scan_failed", err != nil).Msg("renewal reconciliation requires retry")
			} else if attempted != 0 {
				log.Info().Int("attempted", attempted).Msg("renewal reconciliation batch completed")
			}
			timer.Reset(10 * time.Second)
		}
	}()
}
