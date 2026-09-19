package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	exportMeasurementBatch        = 48
	exportCorrectionPageInterval  = 6 * time.Hour
	exportCorrectionSweepInterval = 24 * time.Hour
)

// Forward discovery retains its high-water mark. Separate, paced sweeps catch
// corrections and late commits behind it without rescanning history every tick.
func (h *Handlers) seedExportMeasurements(ctx context.Context, team uuid.UUID, anchor time.Time) (bool, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var after, earliest, correctionAfter, correctionThrough pgtype.Timestamptz
	var wasComplete bool
	var correctionDue time.Time
	err = tx.QueryRow(ctx, `SELECT seed_after,seed_complete,correction_after,correction_through,next_correction_at,
        (SELECT min(hour_start) FROM billing_export_measurement_queue WHERE team_id=$1)
        FROM billing_export_work WHERE team_id=$1 FOR UPDATE`, team).Scan(&after, &wasComplete, &correctionAfter, &correctionThrough, &correctionDue, &earliest)
	if err != nil {
		return false, err
	}
	now := h.nowUTC()
	periodStart, _, ok := billing.AnniversaryPeriod(anchor, now)
	if !ok {
		return false, billing.ErrExportRecoveryRequired
	}
	floor := periodStart.Truncate(time.Hour).Add(-time.Hour)
	if earliest.Valid && !earliest.Time.After(floor) {
		at := earliest.Time
		if at.Before(anchor) {
			at = anchor
		}
		if trackedStart, _, ok := billing.AnniversaryPeriod(anchor, at); ok {
			floor = trackedStart.Truncate(time.Hour).Add(-time.Hour)
		}
	}
	start := floor
	if after.Valid {
		start = after.Time
	}
	count, next, err := seedExportMeasurementPage(ctx, tx, team, start, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true})
	if err != nil {
		return false, err
	}
	complete := count < exportMeasurementBatch
	_, err = tx.Exec(ctx, `UPDATE billing_export_work SET seed_after=$2,seed_complete=$3 WHERE team_id=$1
        AND (seed_after IS DISTINCT FROM $2::timestamptz OR seed_complete IS DISTINCT FROM $3::boolean)`, team, next, complete)
	if err != nil {
		return false, err
	}
	if complete && !wasComplete && !correctionThrough.Valid {
		// Start correction work only after initial catch-up has drained.
		_, err = tx.Exec(ctx, `UPDATE billing_export_work SET correction_after=NULL,correction_through=NULL,next_correction_at=$2 WHERE team_id=$1`, team, now.Add(exportCorrectionPageInterval))
	} else if complete && !now.Before(correctionDue) {
		start = floor
		if correctionAfter.Valid {
			start = correctionAfter.Time
		}
		if !correctionThrough.Valid {
			correctionThrough = pgtype.Timestamptz{Time: next, Valid: true}
		}
		count, next, err = seedExportMeasurementPage(ctx, tx, team, start, correctionThrough)
		if err != nil {
			return false, err
		}
		correctionAfter = pgtype.Timestamptz{Time: next, Valid: true}
		delay := exportCorrectionPageInterval
		if count < exportMeasurementBatch {
			correctionAfter = pgtype.Timestamptz{}
			correctionThrough = pgtype.Timestamptz{}
			delay = exportCorrectionSweepInterval
		}
		_, err = tx.Exec(ctx, `UPDATE billing_export_work SET correction_after=$2,correction_through=$3,next_correction_at=$4 WHERE team_id=$1`, team, correctionAfter, correctionThrough, now.Add(delay))
	}
	if err != nil {
		return false, err
	}
	return complete, tx.Commit(ctx)
}

func seedExportMeasurementPage(ctx context.Context, tx pgx.Tx, team uuid.UUID, start time.Time, through pgtype.Timestamptz) (int, time.Time, error) {
	rows, err := tx.Query(ctx, `WITH page AS MATERIALIZED (
        SELECT hour_start,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds
        FROM team_billing_usage_hourly WHERE team_id=$1 AND hour_start>$2
        AND hour_start<=$4
        ORDER BY hour_start LIMIT $3
        ) SELECT p.hour_start, q.team_id IS NULL OR (NOT q.pending AND
        ROW(p.hour_end,p.vcpu_seconds,p.memory_mib_seconds,p.storage_mib_seconds)
        IS DISTINCT FROM ROW(q.hour_end,q.vcpu_seconds,q.memory_mib_seconds,q.storage_mib_seconds))
        FROM page p LEFT JOIN LATERAL (
        SELECT team_id,pending,hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds
        FROM billing_export_measurement_queue WHERE team_id=$1 AND hour_start=p.hour_start LIMIT 1
        ) q ON true ORDER BY p.hour_start`, team, start, exportMeasurementBatch, through)
	if err != nil {
		return 0, start, err
	}
	var hours []time.Time
	count := 0
	for rows.Next() {
		var hour time.Time
		var changed bool
		if err = rows.Scan(&hour, &changed); err != nil {
			rows.Close()
			return 0, start, err
		}
		count++
		start = hour
		if changed {
			hours = append(hours, hour)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, start, err
	}
	for _, hour := range hours {
		if _, err = tx.Exec(ctx, `INSERT INTO billing_export_measurement_queue(team_id,hour_start) VALUES($1,$2)
        ON CONFLICT(team_id,hour_start) DO UPDATE SET pending=true WHERE NOT billing_export_measurement_queue.pending`, team, hour); err != nil {
			return 0, start, err
		}
	}
	return count, start, nil
}

// consumeExportMeasurements applies changed hour contributions, including
// corrections, once. No export tick recomputes an entire period's raw history.
func (h *Handlers) consumeExportMeasurements(ctx context.Context, team uuid.UUID, anchor time.Time) (int, error) {
	processed := 0
	for ; processed < exportMeasurementBatch; processed++ {
		found, err := h.consumeExportMeasurement(ctx, team, anchor)
		if err != nil {
			return processed, err
		}
		if !found {
			break
		}
	}
	return processed, nil
}

func (h *Handlers) consumeExportMeasurement(ctx context.Context, team uuid.UUID, anchor time.Time) (bool, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var hour time.Time
	err = tx.QueryRow(ctx, `SELECT hour_start FROM billing_export_measurement_queue
        WHERE team_id=$1 AND pending ORDER BY hour_start LIMIT 1 FOR UPDATE SKIP LOCKED`, team).Scan(&hour)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var end time.Time
	var cpu, memory, storage pgtype.Numeric
	err = tx.QueryRow(ctx, `SELECT hour_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds
        FROM team_billing_usage_hourly WHERE team_id=$1 AND hour_start=$2`, team, hour).Scan(&end, &cpu, &memory, &storage)
	if err != nil {
		return false, err
	}
	// Incomplete current-hour measurements stay queued until their boundary.
	if end.After(h.nowUTC()) {
		return false, nil
	}
	storageSnapshot := storage
	at := hour
	if at.Before(anchor) {
		at = anchor
	}
	for at.Before(end) {
		start, periodEnd, ok := billing.AnniversaryPeriod(anchor, at)
		if !ok {
			break
		}
		until := end
		if periodEnd.Before(until) {
			until = periodEnd
		}
		c, m, s := cpu, memory, storage
		if at.After(hour) || until.Before(end) {
			enabled, err := h.billingStorageBillingEnabled(ctx, team)
			if err != nil {
				return false, err
			}

			err = tx.QueryRow(ctx, `SELECT COALESCE(sum(EXTRACT(epoch FROM(least(COALESCE(ended_at,$3),$3)-greatest(started_at,$2)))*vcpu_count),0)::numeric,
                COALESCE(sum(EXTRACT(epoch FROM(least(COALESCE(ended_at,$3),$3)-greatest(started_at,$2)))*memory_mib),0)::numeric
                FROM sandbox_compute_billing_interval WHERE team_id=$1 AND started_at<$3 AND COALESCE(ended_at,$3)>$2`, team, at, until).Scan(&c, &m)
			if err != nil {
				return false, err
			}
			_ = s.Scan("0")
			if enabled {
				if err = tx.QueryRow(ctx, billingBoundaryUsageSQL, team, at, until).Scan(&c, &m, &s); err != nil {
					return false, err
				}
			} else {
				// Keep omitted boundary storage discoverable when billing is enabled.
				_ = storageSnapshot.Scan("0")
			}
		}
		q := h.DB.WithTx(tx)
		_, err = q.GetTeamBillingPeriodForUpdate(ctx, db.GetTeamBillingPeriodForUpdateParams{TeamID: team, PeriodStart: start, PeriodEnd: periodEnd})
		if err == pgx.ErrNoRows {
			_, err = q.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{TeamID: team, PeriodStart: start, PeriodEnd: periodEnd, Status: h.periodStatusForWindow(periodEnd, h.nowUTC())})
		}
		if err != nil && err != pgx.ErrNoRows {
			return false, err
		}
		var immutable bool
		err = tx.QueryRow(ctx, `SELECT finalized_at IS NOT NULL OR exported_at IS NOT NULL OR status='exporting'
            FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3 FOR UPDATE`, team, start, periodEnd).Scan(&immutable)
		if err != nil {
			return false, err
		}
		if immutable {
			// Hourly totals may lag the authoritative close snapshot. Compare the
			// next measured total, preserving downward revisions as review evidence.
			_, err = tx.Exec(ctx, `INSERT INTO billing_period_anomaly(team_id,period_start,period_end,severity,kind,details)
                SELECT $1,$2,$3,'error','usage_after_export_freeze',jsonb_build_object('hour_start',$4::timestamptz,'source','hourly_rollup_requires_authoritative_remeasurement',
                    'observed_vcpu_seconds',$5::numeric::text,'observed_memory_mib_seconds',$6::numeric::text,'observed_storage_mib_seconds',$7::numeric::text)
                WHERE EXISTS(SELECT 1 FROM billing_incremental_period i
                    LEFT JOIN team_billing_usage f USING(team_id,period_start,period_end)
                    LEFT JOIN billing_export_usage u USING(team_id,period_start,period_end)
                    LEFT JOIN billing_export_measurement o ON o.team_id=i.team_id AND o.period_start=i.period_start
                        AND o.period_end=i.period_end AND o.hour_start=$4
                    WHERE i.team_id=$1 AND i.period_start=$2 AND i.period_end=$3
                    AND (f.team_id IS NULL
                        OR COALESCE(u.vcpu_seconds,0)+$5-COALESCE(o.vcpu_seconds,0)>f.vcpu_seconds
                        OR COALESCE(u.memory_mib_seconds,0)+$6-COALESCE(o.memory_mib_seconds,0)>f.memory_mib_seconds
                        OR COALESCE(u.storage_mib_seconds,0)+$7-COALESCE(o.storage_mib_seconds,0)>f.storage_mib_seconds
                        OR $5<o.vcpu_seconds OR $6<o.memory_mib_seconds OR $7<o.storage_mib_seconds))
                AND NOT EXISTS(SELECT 1 FROM billing_period_anomaly WHERE team_id=$1 AND period_start=$2 AND period_end=$3
                  AND kind='usage_after_export_freeze' AND resolved_at IS NULL AND details @> jsonb_build_object('hour_start',$4::timestamptz))`, team, start, periodEnd, hour, c, m, s)
			if err != nil {
				return false, err
			}
		}
		_, err = tx.Exec(ctx, `WITH old AS MATERIALIZED (
            SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_measurement
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND hour_start=$4
        ), contribution AS (
            INSERT INTO billing_export_measurement(team_id,period_start,period_end,hour_start,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(team_id,period_start,period_end,hour_start) DO UPDATE
            SET vcpu_seconds=EXCLUDED.vcpu_seconds,memory_mib_seconds=EXCLUDED.memory_mib_seconds,storage_mib_seconds=EXCLUDED.storage_mib_seconds
            RETURNING *
        ) INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds)
        SELECT $1,$2,$3,c.vcpu_seconds-COALESCE(o.vcpu_seconds,0),c.memory_mib_seconds-COALESCE(o.memory_mib_seconds,0),c.storage_mib_seconds-COALESCE(o.storage_mib_seconds,0)
        FROM contribution c LEFT JOIN old o ON true
        ON CONFLICT(team_id,period_start,period_end) DO UPDATE SET
        vcpu_seconds=billing_export_usage.vcpu_seconds+EXCLUDED.vcpu_seconds,
        memory_mib_seconds=billing_export_usage.memory_mib_seconds+EXCLUDED.memory_mib_seconds,
        storage_mib_seconds=billing_export_usage.storage_mib_seconds+EXCLUDED.storage_mib_seconds,updated_at=now()
        `, team, start, periodEnd, hour, c, m, s)
		if err != nil {
			return false, err
		}
		at = until
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_export_measurement_queue SET pending=false,hour_end=$3,vcpu_seconds=$4,memory_mib_seconds=$5,storage_mib_seconds=$6
        WHERE team_id=$1 AND hour_start=$2`, team, hour, end, cpu, memory, storageSnapshot); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
