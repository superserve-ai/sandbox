package api

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/billing"
)

type billingBacklogSchedule struct {
	next time.Time
}

func (s *billingBacklogSchedule) due(now time.Time) bool {
	if !s.next.IsZero() && now.Before(s.next) {
		return false
	}
	due := !s.next.IsZero()
	// Pace the first sample and every subsequent attempt, including failures.
	// Per-replica jitter avoids synchronized scans without another database lease.
	s.next = now.Add(5*time.Minute + time.Duration(rand.Int64N(int64(time.Minute))))
	return due
}

// StartIncrementalBillingService has no heartbeat, rollup scheduler, or sandbox
// lifecycle caller. One team at a time bounds both database and Stripe load.
func (h *Handlers) StartIncrementalBillingService(ctx context.Context) {
	if h.Pool == nil || h.Stripe == nil || os.Getenv("BILLING_INCREMENTAL_EXPORT_DISABLED") == "true" {
		return
	}
	cadence := time.Hour
	if raw := os.Getenv("BILLING_INCREMENTAL_EXPORT_INTERVAL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < time.Hour {
			log.Error().Msg("invalid BILLING_INCREMENTAL_EXPORT_INTERVAL; incremental service not started")
			return
		}
		cadence = parsed
	}
	go func() {
		// Jitter startup, then claim one bounded team batch per poll. Replicas
		// share discovery and team leases, including after process restarts.
		timer := time.NewTimer(time.Duration(uuid.New()[0]%30+1) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var backlogSchedule billingBacklogSchedule
		for {
			tickCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			started := time.Now()
			if backlogSchedule.due(started) {
				sampleStarted := time.Now()
				sampleCtx, sampleCancel := context.WithTimeout(tickCtx, 2*time.Second)
				samples, sampleErr := (billing.ExportStore{Pool: h.Pool}).Backlog(sampleCtx)
				sampleCancel()
				currentBillingRecorder().RecordBillingWork(tickCtx, "backlog_sample", sampleErr != nil, time.Since(sampleStarted), 0)
				if sampleErr != nil {
					log.Warn().Err(sampleErr).Msg("billing backlog sample failed")
				} else {
					for _, sample := range samples {
						currentBillingRecorder().RecordBillingBacklog(tickCtx, sample.State, sample.Count, sample.OldestAgeSeconds)
					}
				}
			}
			err := h.discoverIncrementalBillingWork(tickCtx)
			var measured int
			var worked bool
			if err == nil {
				worked, measured, err = h.incrementalBillingTick(tickCtx, cadence)
			}
			var workItems int64
			if worked {
				workItems = 1
			}
			currentBillingRecorder().RecordBillingWork(tickCtx, "tick", err != nil, time.Since(started), workItems)
			cancel()
			event := log.Debug()
			if err != nil {
				event = log.Warn().Err(err)
			} else if worked {
				event = log.Info()
			}
			event.Dur("duration", time.Since(started)).Bool("worked", worked).Int("measurements", measured).Msg("incremental billing worker tick")
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (h *Handlers) discoverIncrementalBillingWork(ctx context.Context) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var after pgtype.UUID
	var resetExisting bool
	err = tx.QueryRow(ctx, `SELECT after_team,reset_existing FROM billing_export_discovery WHERE next_run_at<=now() FOR UPDATE SKIP LOCKED`).Scan(&after, &resetExisting)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT team_id FROM team_billing_account WHERE team_id>COALESCE($1::uuid,'00000000-0000-0000-0000-000000000000'::uuid)
        ORDER BY team_id LIMIT 100`, after)
	if err != nil {
		return err
	}
	var teams []uuid.UUID
	for rows.Next() {
		var team uuid.UUID
		if err = rows.Scan(&team); err != nil {
			rows.Close()
			return err
		}
		teams = append(teams, team)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, team := range teams {
		_, err = tx.Exec(ctx, `INSERT INTO billing_export_work(team_id,next_run_at)
            SELECT team_id,now()+interval '1 second'*(get_byte(uuid_send(team_id),0)%60) FROM team_billing_account
            WHERE team_id=$1 AND stripe_subscription_status='active' AND commercial_billing_anchor IS NOT NULL
              AND stripe_customer_id IS NOT NULL AND feature_enabled('billing_export_enabled',team_id)
            ON CONFLICT(team_id) DO UPDATE SET seed_after=NULL,seed_complete=false,next_run_at=EXCLUDED.next_run_at
            WHERE $2::boolean`, team, resetExisting)
		if err != nil {
			return err
		}
	}
	var next *uuid.UUID
	if len(teams) == 100 {
		next = &teams[len(teams)-1]
	}
	_, err = tx.Exec(ctx, `UPDATE billing_export_discovery SET after_team=$1,reset_existing=$2,next_run_at=now()+interval '1 minute'`, next, resetExisting && next != nil)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) incrementalBillingTick(ctx context.Context, cadence time.Duration) (bool, int, error) {
	token := uuid.New()
	var team uuid.UUID
	var dueLagSeconds float64
	var reconcileOnly bool
	err := h.Pool.QueryRow(ctx, `WITH candidate AS (
        SELECT w.team_id,least(w.next_run_at,w.next_reconcile_at) AS due_at,
          w.next_reconcile_at<w.next_run_at AS reconcile_only FROM billing_export_work w JOIN team_billing_account a USING(team_id)
        WHERE least(w.next_run_at,w.next_reconcile_at)<=now() AND (w.lease_until IS NULL OR w.lease_until<=now())
          AND a.stripe_subscription_status='active' AND feature_enabled('billing_export_enabled',w.team_id)
        ORDER BY least(w.next_run_at,w.next_reconcile_at),w.team_id LIMIT 1 FOR UPDATE OF w SKIP LOCKED)
        UPDATE billing_export_work w SET lease_token=$1,lease_until=now()+interval '2 minutes',
          updated_at=now()
        FROM candidate c WHERE w.team_id=c.team_id RETURNING w.team_id,extract(epoch FROM clock_timestamp()-c.due_at)::float8,c.reconcile_only`, token).Scan(&team, &dueLagSeconds, &reconcileOnly)
	if err == pgx.ErrNoRows {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	currentBillingRecorder().RecordBillingLag(ctx, dueLagSeconds)
	log.Info().Str("team_id", team.String()).Float64("due_lag_seconds", dueLagSeconds).Msg("incremental billing work claimed")
	var measured int
	var more bool
	var workErr error
	if reconcileOnly {
		workErr = h.reconcileIncrementalBillingTeam(ctx, team)
	} else {
		measured, more, workErr = h.processIncrementalBillingTeam(ctx, team)
	}
	var message *string
	if workErr != nil {
		m := workErr.Error()
		message = &m
	}
	delay := cadence
	if reconcileOnly {
		delay = 6 * time.Hour
	}
	if workErr != nil {
		delay = min(delay, 10*time.Minute)
	}
	if more && workErr == nil {
		delay = time.Minute
	}
	_, ackErr := h.Pool.Exec(ctx, `UPDATE billing_export_work SET lease_token=NULL,lease_until=NULL,
        last_error=CASE WHEN $5 THEN last_error ELSE $3 END,
        reconcile_error=CASE WHEN $5 THEN $3 ELSE reconcile_error END,
        next_reconcile_at=CASE WHEN $5 THEN now()+($4*interval '1 second') ELSE next_reconcile_at END,
        next_run_at=CASE WHEN $5 THEN next_run_at ELSE greatest(now()+interval '1 minute',least(
          now()+($4*interval '1 second')+interval '1 second'*(get_byte(uuid_send(team_id),0)%60),
          COALESCE((SELECT min(e.next_attempt_at) FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
            WHERE a.team_id=$1 AND e.active AND e.status IN ('pending','uncertain')),'infinity'::timestamptz))) END,updated_at=now()
        WHERE team_id=$1 AND lease_token=$2`, team, token, message, delay.Seconds(), reconcileOnly)
	if ackErr != nil {
		return true, measured, ackErr
	}
	return true, measured, workErr
}

func (h *Handlers) processIncrementalBillingTeam(ctx context.Context, team uuid.UUID) (int, bool, error) {
	account, err := h.DB.GetTeamBillingAccount(ctx, team)
	if err != nil {
		return 0, false, err
	}
	if !account.CommercialBillingAnchor.Valid {
		return 0, false, fmt.Errorf("commercial anchor missing")
	}
	complete, err := h.seedExportMeasurements(ctx, team, account.CommercialBillingAnchor.Time)
	if err != nil {
		return 0, false, err
	}
	measurementStarted := time.Now()
	measured, err := h.consumeExportMeasurements(ctx, team, account.CommercialBillingAnchor.Time)
	currentBillingRecorder().RecordBillingWork(ctx, "measurement", err != nil, time.Since(measurementStarted), int64(measured))
	if err != nil {
		return measured, false, err
	}
	if !complete || measured == exportMeasurementBatch {
		return measured, true, nil
	}
	rows, err := h.Pool.Query(ctx, `SELECT p.period_start,p.period_end FROM team_billing_period p
        JOIN billing_export_usage u USING(team_id,period_start,period_end)
        WHERE p.team_id=$1 AND p.status IN ('open','approved','exporting') AND p.finalized_at IS NULL
        AND (NOT EXISTS(SELECT 1 FROM billing_export_observation o WHERE o.team_id=p.team_id AND o.period_start=p.period_start AND o.period_end=p.period_end)
          OR EXISTS(SELECT 1 FROM billing_export_observation o WHERE o.team_id=p.team_id AND o.period_start=p.period_start AND o.period_end=p.period_end
             AND (o.observed_at<u.updated_at OR o.observed_at<now()-interval '6 hours' OR o.last_error IS NOT NULL
               OR o.submitted_quantity<>o.local_quantity OR o.counted_quantity IS DISTINCT FROM o.local_quantity)))
        ORDER BY u.last_export_attempt_at NULLS FIRST,p.period_start LIMIT 2`, team)
	if err != nil {
		return measured, false, err
	}
	var periods []billing.ExportPeriod
	for rows.Next() {
		p := billing.ExportPeriod{TeamID: team}
		if err = rows.Scan(&p.Start, &p.End); err != nil {
			rows.Close()
			return measured, false, err
		}
		periods = append(periods, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return measured, false, err
	}
	var failures []error
	for _, p := range periods {
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_export_usage SET last_export_attempt_at=clock_timestamp()
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
			return measured, false, err
		}
		if _, err = h.exportIncrementalPeriod(ctx, p); err != nil {
			failures = append(failures, fmt.Errorf("export period %s: %w", billingPeriodID(p.Start, p.End), err))
		}
	}
	var frozen billing.ExportPeriod
	frozen.TeamID = team
	err = h.Pool.QueryRow(ctx, `SELECT p.period_start,p.period_end FROM team_billing_period p
        JOIN billing_incremental_period i USING(team_id,period_start,period_end)
        WHERE p.team_id=$1 AND p.status IN ('exported','finalized')
        AND NOT EXISTS(SELECT 1 FROM billing_export_observation o WHERE o.team_id=p.team_id AND o.period_start=p.period_start
          AND o.period_end=p.period_end AND o.observed_at>now()-interval '6 hours')
        ORDER BY i.last_reconcile_attempt_at NULLS FIRST,p.period_start LIMIT 1`, team).Scan(&frozen.Start, &frozen.End)
	if err == nil {
		err = h.markIncrementalReconciliationAttempt(ctx, frozen)
		if err == nil {
			_, err = h.reconcileFrozenIncrementalPeriod(ctx, frozen)
		}
	} else if err == pgx.ErrNoRows {
		err = nil
	}
	return measured, false, errors.Join(append(failures, err)...)
}

// Reconciliation reads the persisted cumulative usage without allocating events,
// consuming measurements, or advancing the independent export deadline.
func (h *Handlers) reconcileIncrementalBillingTeam(ctx context.Context, team uuid.UUID) error {
	rows, err := h.Pool.Query(ctx, `SELECT p.period_start,p.period_end,p.status FROM team_billing_period p
        JOIN billing_incremental_period i USING(team_id,period_start,period_end)
        WHERE p.team_id=$1
        ORDER BY i.last_reconcile_attempt_at NULLS FIRST,p.period_start LIMIT 2`, team)
	if err != nil {
		return err
	}
	type periodWork struct {
		period billing.ExportPeriod
		frozen bool
	}
	var periods []periodWork
	for rows.Next() {
		p := periodWork{period: billing.ExportPeriod{TeamID: team}}
		var status string
		if err = rows.Scan(&p.period.Start, &p.period.End, &status); err != nil {
			rows.Close()
			return err
		}
		p.frozen = status == "exporting" || status == "exported" || status == "finalized"
		periods = append(periods, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures []error
	for _, p := range periods {
		if err = h.markIncrementalReconciliationAttempt(ctx, p.period); err != nil {
			return err
		}
		_, err = h.reconcileIncrementalPeriod(ctx, p.period, p.frozen)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (h *Handlers) markIncrementalReconciliationAttempt(ctx context.Context, p billing.ExportPeriod) error {
	_, err := h.Pool.Exec(ctx, `UPDATE billing_incremental_period SET last_reconcile_attempt_at=clock_timestamp()
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
	return err
}
