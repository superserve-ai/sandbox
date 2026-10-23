package api

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

// Sampling has its own deadline and cadence, independent of provider recovery.
func (h *Handlers) startProBillingMonitoring(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	recorder, ok := currentBillingRecorder().(telemetry.ProBillingRecorder)
	if !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			sample, cancel := context.WithTimeout(ctx, 5*time.Second)
			started := time.Now()
			err := h.sampleProBillingBacklog(sample, recorder)
			cancel()
			currentBillingRecorder().RecordBillingWork(ctx, "pro_backlog_sample", err != nil, time.Since(started), 0)
			if err != nil {
				log.Warn().Err(err).Msg("Pro recovery backlog observation failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (h *Handlers) sampleProBillingBacklog(ctx context.Context, recorder telemetry.ProBillingRecorder) error {
	rows, err := h.Pool.Query(ctx, `SELECT offer_key FROM billing_plan ORDER BY sort_order,offer_key`)
	if err != nil {
		return err
	}
	offers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, offer := range offers {
		var paid, overdue int64
		var paidAge, overdueAge float64
		err := h.Pool.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM (SELECT 1 FROM billing_signup_choice WHERE state='pending' AND offer_key=$1 AND paid_observed_at IS NOT NULL ORDER BY paid_observed_at LIMIT 1000) p),
    COALESCE((SELECT extract(epoch FROM clock_timestamp()-paid_observed_at)::double precision FROM billing_signup_choice WHERE state='pending' AND offer_key=$1 AND paid_observed_at IS NOT NULL ORDER BY paid_observed_at LIMIT 1),0),
    (SELECT count(*) FROM (SELECT 1 FROM billing_signup_choice WHERE state='pending' AND offer_key=$1 AND next_check_at<clock_timestamp() ORDER BY next_check_at LIMIT 1000) d),
    COALESCE((SELECT extract(epoch FROM clock_timestamp()-next_check_at)::double precision FROM billing_signup_choice WHERE state='pending' AND offer_key=$1 AND next_check_at<clock_timestamp() ORDER BY next_check_at LIMIT 1),0)`, offer).Scan(&paid, &paidAge, &overdue, &overdueAge)
		if err != nil {
			return err
		}
		recorder.RecordProBillingBacklog(ctx, offer, paid, paidAge, overdue, overdueAge)
	}
	return nil
}
