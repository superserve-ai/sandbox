package api

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Free calendar buckets are reporting records, not a paid anniversary. Keep
// their identity and usage history while allowing the first commercial month.
func retireFirstProCycleReportingPeriods(ctx context.Context, tx pgx.Tx, u proUpgrade) error {
	if u.InitialAssignment == nil {
		return errors.New("first Pro month has no accepted Free predecessor")
	}
	if _, err := u.creditExpiry(); err != nil {
		return err
	}
	var paid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE id=$1 AND team_id=$2 AND request_payload->>'FirstPaidProCycle'='true' AND state IN ('credited','active') AND payment_evidence IS NOT NULL AND (grant_id IS NOT NULL OR bridge_credit_cents=0) AND anchor=$3 AND period_start=$3 AND quoted_at=$3 AND period_end=$4)`, u.ID, u.Team, u.Start, u.End).Scan(&paid); err != nil {
		return err
	}
	if !paid {
		return errors.New("first Pro month reporting transition requires durable paid credit proof")
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, u.Team); err != nil {
		return err
	}
	var free bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE id=$1 AND team_id=$2 AND kind='free')`, u.InitialAssignment, u.Team).Scan(&free); err != nil {
		return err
	}
	if !free {
		return errors.New("first Pro month predecessor is not Free")
	}
	// Lock outstanding work before inspecting it, so a concurrent claim cannot
	// pass the same boundary while these reporting records are being retired.
	rows, err := tx.Query(ctx, `SELECT lease_token IS NOT NULL FROM billing_export_work WHERE team_id=$1 FOR UPDATE`, u.Team)
	if err != nil {
		return err
	}
	var leased bool
	for rows.Next() {
		if err = rows.Scan(&leased); err != nil {
			rows.Close()
			return err
		}
		if leased {
			rows.Close()
			return errors.New("Free usage export is still leased")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT lease_token IS NOT NULL OR attempts>0 OR stage<>'pending' OR last_attempt_at IS NOT NULL OR last_progress_at IS NOT NULL OR last_error IS NOT NULL FROM billing_period_close_work WHERE team_id=$1 AND period_start<$3 AND period_end>$2 AND completed_at IS NULL FOR UPDATE`, u.Team, u.Start, u.End)
	if err != nil {
		return err
	}
	for rows.Next() {
		if err = rows.Scan(&leased); err != nil {
			rows.Close()
			return err
		}
		if leased {
			rows.Close()
			return errors.New("Free reporting period close has already started")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var ownedPaidTarget bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade u JOIN billing_commercial_contract c ON c.id=u.contract_id AND c.team_id=u.team_id AND c.customer_id=u.customer_id AND c.subscription_id=u.subscription_id
 WHERE u.id=$1 AND c.starts_at=u.period_end AND c.entitlement_anchor=u.anchor
 AND EXISTS(SELECT 1 FROM team_plan_assignment a WHERE a.team_id=u.team_id AND a.contract_id=c.id AND a.source='checkout' AND a.idempotency_key='checkout:'||c.id::text AND a.plan_version_id=(u.request_payload#>>'{PlanTerms,VersionID}')::uuid))`, u.ID).Scan(&ownedPaidTarget); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT period_start,period_end,status='open' AND exported_at IS NULL AND approved_at IS NULL AND approved_by IS NULL AND blocked_at IS NULL AND blocked_reason IS NULL
 AND COALESCE(gross_charges_usd,0)=0 AND COALESCE(credits_applied_usd,0)=0 AND COALESCE(net_invoice_amount_usd,0)=0
 FROM team_billing_period WHERE team_id=$1 AND period_start<$3 AND period_end>$2 AND finalized_at IS NULL
 AND NOT($4::boolean AND period_start=$2 AND period_end=$3) ORDER BY period_start FOR UPDATE`, u.Team, u.Start, u.End, ownedPaidTarget)
	if err != nil {
		return err
	}
	// Retire only records selected and locked in this transaction. A new paid
	// period at the accepted boundaries is never mistaken for a Free bucket.
	type boundary struct{ start, end time.Time }
	var periods []boundary
	reuseFreeTarget := false
	for rows.Next() {
		var p boundary
		var safe bool
		if err = rows.Scan(&p.start, &p.end, &safe); err != nil {
			rows.Close()
			return err
		}
		if !safe {
			rows.Close()
			return errors.New("Free reporting period already has financial activity")
		}
		if p.start.Equal(u.Start) && p.end.Equal(u.End) {
			// An untouched Free bucket with exactly the new boundaries can be
			// reused by this paid transaction; finalizing its key would prevent
			// materializing the same commercial interval on replay.
			reuseFreeTarget = true
		} else {
			periods = append(periods, p)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(periods) == 0 && !reuseFreeTarget {
		return nil
	}
	var touched bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_invoice_close WHERE team_id=$1 AND period_start<$3 AND period_end>$2)
 OR EXISTS(SELECT 1 FROM billing_usage_export WHERE team_id=$1 AND period_start<$3 AND period_end>$2)
 OR EXISTS(SELECT 1 FROM billing_export_allocation WHERE team_id=$1 AND period_start<$3 AND period_end>$2)
 OR EXISTS(SELECT 1 FROM team_billing_usage WHERE team_id=$1 AND period_start<$3 AND period_end>$2 AND (finalized_at IS NOT NULL OR exported_at IS NOT NULL))`, u.Team, u.Start, u.End).Scan(&touched)
	if err != nil {
		return err
	}
	if touched {
		return errors.New("Free reporting period has retained invoice or export evidence")
	}
	for _, p := range periods {
		if _, err = tx.Exec(ctx, `UPDATE team_billing_period SET status='finalized',blocked_reason='reporting_only_calendar_period',gross_charges_usd=0,credits_applied_usd=0,net_invoice_amount_usd=0,finalized_at=clock_timestamp(),updated_at=clock_timestamp() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, u.Team, p.start, p.end); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO billing_period_close_work(team_id,period_start,period_end,completed_at,stage,last_progress_at) VALUES($1,$2,$3,clock_timestamp(),'reporting_only_calendar_period',clock_timestamp()) ON CONFLICT(team_id,period_start,period_end) DO UPDATE SET completed_at=EXCLUDED.completed_at,stage=EXCLUDED.stage,last_progress_at=EXCLUDED.last_progress_at WHERE billing_period_close_work.completed_at IS NULL AND billing_period_close_work.attempts=0 AND billing_period_close_work.lease_token IS NULL
AND billing_period_close_work.stage='pending'`, u.Team, p.start, p.end)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("Free reporting period close progressed during retirement")
		}
	}
	return nil
}
