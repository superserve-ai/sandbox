package api

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

const closeWorkTimeout = 60 * time.Second

// Shared with the admin path. Provider calls remain outside this transaction;
// export and settlement revalidate the canonical snapshot before collection.
func (h *Handlers) approveBillingPeriod(ctx context.Context, p billing.ExportPeriod, actor uuid.UUID) (db.TeamBillingPeriod, error) {
	if p.End.After(h.nowUTC()) {
		return db.TeamBillingPeriod{}, fmt.Errorf("cannot approve an open billing period")
	}
	ctx, cancel := context.WithTimeout(ctx, billing.StorageReportSettlementTimeout)
	defer cancel()
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return db.TeamBillingPeriod{}, err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	var anchor pgtype.Timestamptz
	err = tx.QueryRow(ctx, `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1 FOR SHARE`, p.TeamID).Scan(&anchor)
	// Human approval also supports non-commercial periods without an account.
	if err != nil && !(errors.Is(err, pgx.ErrNoRows) && actor != uuid.Nil) {
		return db.TeamBillingPeriod{}, err
	}
	if anchor.Valid {
		start, end, ok := billing.AnniversaryPeriod(anchor.Time, p.Start)
		if !ok || !start.Equal(p.Start) || !end.Equal(p.End) {
			return db.TeamBillingPeriod{}, fmt.Errorf("period does not match commercial anchor")
		}
	}
	// Match export's period-before-storage-fence lock ordering.
	if _, err = tx.Exec(ctx, `SELECT 1 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3 FOR UPDATE`, p.TeamID, p.Start, p.End); err != nil {
		return db.TeamBillingPeriod{}, err
	}
	if err = prepareBillingStorageSnapshot(ctx, tx, p.TeamID, p.End); err != nil {
		return db.TeamBillingPeriod{}, err
	}
	if _, _, err = h.upsertBillingSnapshotWithQueries(ctx, q, p.TeamID, p.Start, p.End); err != nil {
		return db.TeamBillingPeriod{}, err
	}
	period, err := q.ApproveTeamBillingPeriod(ctx, db.ApproveTeamBillingPeriodParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End, ApprovedBy: pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil}})
	if err != nil {
		return db.TeamBillingPeriod{}, err
	}
	return period, tx.Commit(ctx)
}

func (h *Handlers) StartBillingPeriodCloseService(ctx context.Context) {
	if h.Pool == nil || os.Getenv("BILLING_AUTOMATIC_CLOSE_DISABLED") == "true" {
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		return
	}
	h.startBillingInvoiceCollectionService(ctx)
	go func() {
		timer := time.NewTimer(time.Duration(1+rand.IntN(10)) * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			discoveryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := h.discoverBillingPeriodCloseWork(discoveryCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Msg("billing close discovery failed")
			}
			// Each replica is sequential; claims also cap the regional fleet at four.
			// Fast work drains a small batch; slow work remains bounded by one deadline.
			batchCtx, stop := context.WithTimeout(ctx, closeWorkTimeout)
			for i := 0; i < 4 && batchCtx.Err() == nil; i++ {
				worked, e := h.billingPeriodCloseTick(batchCtx)
				if e != nil {
					log.Warn().Err(e).Msg("billing close attempt held")
				}
				if !worked {
					break
				}
			}
			stop()
			timer.Reset(5*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond)
		}
	}()
}

// Keyset traversal examines at most 100 existing periods per discovery pass.
// Ineligible history never becomes approved merely because it was discovered.
func (h *Handlers) discoverBillingPeriodCloseWork(ctx context.Context) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var team uuid.UUID
	var start, end pgtype.Timestamptz
	err = tx.QueryRow(ctx, `SELECT after_team,after_start,after_end FROM billing_period_close_discovery WHERE next_run_at<=now() FOR UPDATE SKIP LOCKED`).Scan(&team, &start, &end)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT team_id,period_start,period_end FROM team_billing_period WHERE (team_id,period_start,period_end)>($1,$2,$3) ORDER BY team_id,period_start,period_end LIMIT 100`, team, start, end)
	if err != nil {
		return err
	}
	var periods []billing.ExportPeriod
	for rows.Next() {
		var p billing.ExportPeriod
		if err = rows.Scan(&p.TeamID, &p.Start, &p.End); err != nil {
			rows.Close()
			return err
		}
		periods = append(periods, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(periods) > 0 {
		first, last := periods[0], periods[len(periods)-1]
		_, err = tx.Exec(ctx, `INSERT INTO billing_period_close_work(team_id,period_start,period_end)
            SELECT p.team_id,p.period_start,p.period_end FROM team_billing_period p JOIN team_billing_account a USING(team_id)
            LEFT JOIN billing_invoice_account i USING(team_id) LEFT JOIN billing_invoice_close c USING(team_id,period_start,period_end)
            WHERE (p.team_id,p.period_start,p.period_end)>=($1,$2,$3) AND (p.team_id,p.period_start,p.period_end)<=($4,$5,$6)
             AND p.period_end<=now() AND (
               (a.stripe_customer_id IS NOT NULL AND a.stripe_subscription_id IS NOT NULL
                AND a.commercial_billing_anchor IS NOT NULL AND feature_enabled('billing_export_enabled',p.team_id))
               OR (p.status IN ('exporting','exported','finalized') AND i.enrolled_at<p.period_end))
             AND (i.team_id IS NULL OR i.enrolled_at<p.period_end)
             AND (p.finalized_at IS NULL OR (c.state IS NOT NULL AND c.state<>'released')) AND COALESCE(c.state,'')<>'released'
            ON CONFLICT DO NOTHING`, first.TeamID, first.Start, first.End, last.TeamID, last.Start, last.End)
		if err != nil {
			return err
		}
	}
	if len(periods) == 100 {
		p := periods[len(periods)-1]
		_, err = tx.Exec(ctx, `UPDATE billing_period_close_discovery SET after_team=$1,after_start=$2,after_end=$3,next_run_at=now()+interval '1 second'`, p.TeamID, p.Start, p.End)
	} else {
		_, err = tx.Exec(ctx, `UPDATE billing_period_close_discovery SET after_team='00000000-0000-0000-0000-000000000000',after_start='-infinity',after_end='-infinity',next_run_at=now()+interval '1 minute'`)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type billingCloseClaim struct {
	billing.ExportPeriod
	Token uuid.UUID
	Stage string
}

func (h *Handlers) claimBillingPeriodClose(ctx context.Context) (billingCloseClaim, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return billingCloseClaim{}, err
	}
	defer tx.Rollback(ctx)
	// Serialize only scheduling, not provider work, to enforce a fleet-wide cap.
	var singleton bool
	if err = tx.QueryRow(ctx, `SELECT singleton FROM billing_period_close_discovery FOR UPDATE SKIP LOCKED`).Scan(&singleton); err != nil {
		return billingCloseClaim{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM billing_period_close_work WHERE lease_token IS NOT NULL AND lease_until>now()`).Scan(&count); err != nil {
		return billingCloseClaim{}, err
	}
	if count >= 4 {
		return billingCloseClaim{}, pgx.ErrNoRows
	}
	c := billingCloseClaim{Token: uuid.New()}
	err = tx.QueryRow(ctx, `WITH candidate AS (
  SELECT w.team_id,w.period_start,w.period_end FROM billing_period_close_work w
  WHERE w.completed_at IS NULL AND w.next_attempt_at<=now() AND (w.lease_until IS NULL OR w.lease_until<=now())
   AND NOT EXISTS(SELECT 1 FROM billing_period_close_work busy WHERE busy.team_id=w.team_id AND busy.lease_token IS NOT NULL AND busy.lease_until>now())
   AND NOT EXISTS(SELECT 1 FROM billing_export_work busy WHERE busy.team_id=w.team_id AND busy.lease_until>now())
  ORDER BY w.next_attempt_at,w.team_id,w.period_start LIMIT 1 FOR UPDATE SKIP LOCKED)
  UPDATE billing_period_close_work w SET lease_token=$1,lease_until=now()+interval '2 minutes',attempts=attempts+1,last_attempt_at=clock_timestamp()
  FROM candidate c WHERE (w.team_id,w.period_start,w.period_end)=(c.team_id,c.period_start,c.period_end)
  RETURNING w.team_id,w.period_start,w.period_end,w.stage`, c.Token).Scan(&c.TeamID, &c.Start, &c.End, &c.Stage)
	if err != nil {
		return c, err
	}
	// Share the existing exporter lease, including with older replicas. The
	// conditional upsert resolves a claim racing the export worker atomically.
	tag, err := tx.Exec(ctx, `INSERT INTO billing_export_work(team_id,lease_token,lease_until)
 VALUES($1,$2,now()+interval '2 minutes') ON CONFLICT(team_id) DO UPDATE
 SET lease_token=EXCLUDED.lease_token,lease_until=EXCLUDED.lease_until,updated_at=now()
 WHERE billing_export_work.lease_until IS NULL OR billing_export_work.lease_until<=now()`, c.TeamID, c.Token)
	if err != nil {
		return c, err
	}
	if tag.RowsAffected() != 1 {
		return c, pgx.ErrNoRows
	}
	return c, tx.Commit(ctx)
}

func (h *Handlers) billingPeriodCloseTick(ctx context.Context) (bool, error) {
	if os.Getenv("BILLING_AUTOMATIC_CLOSE_DISABLED") == "true" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, closeWorkTimeout)
	defer cancel()
	c, err := h.claimBillingPeriodClose(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	started := time.Now()
	stage, delay, done, workErr := h.advanceBillingPeriodClose(ctx, c.ExportPeriod)
	var message *string
	if workErr != nil {
		s := strings.ToValidUTF8(workErr.Error(), "\uFFFD")
		if len(s) > 2048 {
			s = s[:2048]
			for !utf8.ValidString(s) {
				s = s[:len(s)-1]
			}
		}
		message = &s
	}
	ack, cancelAck := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancelAck()
	tag, ackErr := h.Pool.Exec(ack, `UPDATE billing_period_close_work SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+$5*interval '1 second',
   last_progress_at=CASE WHEN stage<>$6 THEN clock_timestamp() ELSE last_progress_at END,stage=$6,last_error=$7,
   completed_at=CASE WHEN $8 THEN clock_timestamp() ELSE NULL END
   WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND lease_token=$4`, c.TeamID, c.Start, c.End, c.Token, delay.Seconds(), stage, message, done)
	if ackErr == nil && tag.RowsAffected() != 1 {
		ackErr = fmt.Errorf("billing close ownership changed")
	}
	_, leaseErr := h.Pool.Exec(ack, `UPDATE billing_export_work SET lease_token=NULL,lease_until=NULL,updated_at=now() WHERE team_id=$1 AND lease_token=$2`, c.TeamID, c.Token)
	ackErr = errors.Join(ackErr, leaseErr)
	currentBillingRecorder().RecordBillingWork(ack, "period_close", workErr != nil || ackErr != nil, time.Since(started), 1)
	return true, errors.Join(workErr, ackErr)
}

func (h *Handlers) advanceBillingPeriodClose(ctx context.Context, p billing.ExportPeriod) (string, time.Duration, bool, error) {
	hold := func(stage string, err error) (string, time.Duration, bool, error) {
		return stage, 5 * time.Minute, false, err
	}
	var active, enabled bool
	var anchor pgtype.Timestamptz
	err := h.Pool.QueryRow(ctx, `SELECT COALESCE(stripe_subscription_status='active',false),feature_enabled('billing_export_enabled',team_id),commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, p.TeamID).Scan(&active, &enabled, &anchor)
	if err != nil {
		return hold("eligibility", err)
	}
	period, err := h.DB.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
	if err != nil {
		return hold("eligibility", err)
	}
	if p.End.After(h.nowUTC()) {
		return "waiting_period", p.End.Sub(h.nowUTC()), false, nil
	}
	a, enrolled, err := h.invoiceAccountForPeriod(ctx, p)
	if err != nil {
		return hold("eligibility", err)
	}
	frozen := period.Status == "exporting" || period.Status == "exported" || period.FinalizedAt.Valid
	if !enabled && !frozen {
		return hold("disabled", fmt.Errorf("billing export is disabled"))
	}
	if !frozen {
		if !active || !anchor.Valid {
			return hold("eligibility", fmt.Errorf("verified active commercial subscription is required"))
		}
		start, end, ok := billing.AnniversaryPeriod(anchor.Time, p.Start)
		if !ok || !start.Equal(p.Start) || !end.Equal(p.End) {
			return hold("eligibility", fmt.Errorf("period does not match commercial anchor"))
		}
	}
	if !enrolled {
		if !active {
			return hold("enrollment", fmt.Errorf("subscription sync requires operator investigation"))
		}
		if err = h.enrollInvoiceAccount(ctx, p.TeamID, nil); err != nil {
			return hold("enrollment", err)
		}
		a, enrolled, err = h.invoiceAccountForPeriod(ctx, p)
		if err != nil {
			return hold("enrollment", err)
		}
	}
	if !enrolled || !a.EnrolledAt.Before(p.End) {
		return hold("pre_enrollment", fmt.Errorf("period predates verified invoice enrollment"))
	}
	// Previously verified exports also need this gate before local finalization.
	if err = h.requireEarlierInvoicePeriodsReleased(ctx, p, a.EnrolledAt); err != nil {
		return hold("earlier_period", err)
	}
	if !frozen && period.Status != "approved" {
		if _, err = h.approveBillingPeriod(ctx, p, uuid.Nil); err != nil {
			return hold("validation", err)
		}
	}
	// Export remains responsible for canonical completeness and immutable event
	// reconciliation. Never infer successful export from approval alone.
	if !period.FinalizedAt.Valid {
		if !enabled {
			// Disabling new exports must not strand an already frozen invoice.
			// Observe its existing usage without allocating or submitting new usage.
			_, err = h.reconcileFrozenIncrementalPeriod(ctx, p)
			if err == nil {
				err = h.reconcileInvoicePeriod(ctx, p)
			}
			if err == nil && period.Status == "exporting" {
				err = h.markBillingPeriodExported(ctx, p)
			}
		} else {
			_, err = h.exportIncrementalPeriod(ctx, p)
		}
		if err != nil {
			var invoiceEnd time.Time
			e := h.Pool.QueryRow(ctx, `SELECT invoice_end FROM billing_invoice_calendar WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&invoiceEnd)
			if e == nil && invoiceEnd.After(h.nowUTC()) {
				return "waiting_provider", min(invoiceEnd.Sub(h.nowUTC()), 6*time.Hour), false, err
			}
			return hold("export", err)
		}
		// A prepared invoice may still await provider aggregation/verification.
		if _, err = billing.FinalizeTeamBillingPeriodWithCredits(ctx, h.Pool, p.TeamID, p.Start, p.End, h.ResolveActiveBillingMeter); err != nil {
			return hold("settlement", err)
		}
	}
	if err = h.reconcileInvoicePeriod(ctx, p); err != nil {
		return hold("release", err)
	}
	var released bool
	if err = h.Pool.QueryRow(ctx, `SELECT state='released' FROM billing_invoice_close WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&released); err != nil {
		return hold("release", err)
	}
	if released {
		return "released", time.Minute, true, nil
	}
	return "settlement", time.Minute, false, nil
}
