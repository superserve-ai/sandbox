package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type ExportCorrection struct {
	ID uuid.UUID `json:"id"`
	ExportPeriod
	Resource  string     `json:"resource"`
	Version   int64      `json:"version"`
	Frozen    bool       `json:"frozen"`
	Measured  string     `json:"measured_quantity"`
	Baseline  string     `json:"baseline_quantity"`
	Reserved  string     `json:"reserved_quantity"`
	Target    string     `json:"target_quantity"`
	Previous  *uuid.UUID `json:"previous_id"`
	Snapshot  string     `json:"measurement_snapshot"`
	AppliedAt *time.Time `json:"applied_at"`
	Action    *string    `json:"action"`
	Evidence  *string    `json:"evidence"`
}

func resourceMeterKey(resource string) (string, error) {
	switch resource {
	case "cpu":
		return "vcpu", nil
	case "memory":
		return "memory_gib", nil
	case "storage":
		return "storage_gib", nil
	default:
		return "", fmt.Errorf("invalid billing resource")
	}
}

func maximumQuantity(values ...string) string {
	result := "0.000000000000"
	max := new(big.Rat)
	for _, value := range values {
		n, ok := new(big.Rat).SetString(value)
		if ok && n.Cmp(max) > 0 {
			max = n
			result = n.FloatString(12)
		}
	}
	return result
}

// measureCorrection takes one MVCC snapshot. Closed periods use raw remeasurement,
// never a difference between the asynchronous hourly rollup and frozen totals.
// No period lock or provider I/O is held during the potentially expensive read.
func measureCorrection(ctx context.Context, tx pgx.Tx, p ExportPeriod, resource string) (ExportCorrection, error) {
	c := ExportCorrection{ID: uuid.New(), ExportPeriod: p, Resource: resource}
	var claimed bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1::text,0))`, "billing-correction:"+p.TeamID.String()).Scan(&claimed); err != nil {
		return c, err
	}
	if !claimed {
		return c, ErrExportRecoveryRequired
	}
	key, err := resourceMeterKey(resource)
	if err != nil {
		return c, err
	}
	err = tx.QueryRow(ctx, `SELECT p.status IN ('exporting','exported','finalized') OR p.exported_at IS NOT NULL OR p.finalized_at IS NOT NULL,
        pg_current_snapshot()::text,i.correction_version FROM team_billing_period p JOIN billing_incremental_period i USING(team_id,period_start,period_end)
        WHERE p.team_id=$1 AND p.period_start=$2 AND p.period_end=$3`, p.TeamID, p.Start, p.End).Scan(&c.Frozen, &c.Snapshot, &c.Version)
	if err != nil {
		return c, err
	}
	var cpu, memory, storage pgtype.Numeric
	if c.Frozen {
		if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='20s'`); err != nil {
			return c, err
		}
		err = tx.QueryRow(ctx, ExportRemeasurementSQL, p.TeamID, p.Start, p.End).Scan(&cpu, &memory, &storage)
	} else {
		err = tx.QueryRow(ctx, `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_usage
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&cpu, &memory, &storage)
	}
	if err != nil {
		return c, err
	}
	value := cpu
	if resource == "memory" {
		value = memory
	}
	if resource == "storage" {
		value = storage
	}
	c.Measured, err = MeterUsageQuantity(value, key)
	if err != nil {
		return c, err
	}
	c.Baseline = c.Measured
	if c.Frozen {
		err = tx.QueryRow(ctx, `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM team_billing_usage
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&cpu, &memory, &storage)
		if err != nil {
			return c, err
		}
		value = cpu
		if resource == "memory" {
			value = memory
		}
		if resource == "storage" {
			value = storage
		}
		c.Baseline, err = MeterUsageQuantity(value, key)
		if err != nil {
			return c, err
		}
	}
	err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT coverage_end FROM billing_export_allocation
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4 ORDER BY coverage_end DESC LIMIT 1),0)::text`, p.TeamID, p.Start, p.End, resource).Scan(&c.Reserved)
	if err != nil {
		return c, err
	}
	var previous uuid.UUID
	var target string
	err = tx.QueryRow(ctx, `SELECT id,target_quantity::text FROM billing_export_correction
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4 AND applied_at IS NOT NULL
        ORDER BY applied_at DESC,id DESC LIMIT 1`, p.TeamID, p.Start, p.End, resource).Scan(&previous, &target)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c, err
	}
	if err == nil {
		c.Previous = &previous
	} else {
		target = "0"
	}
	c.Target = maximumQuantity(c.Measured, c.Baseline, c.Reserved, target)
	return c, nil
}

func (s ExportStore) MeasureCorrection(ctx context.Context, p ExportPeriod, resource string) (ExportCorrection, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return ExportCorrection{}, err
	}
	defer tx.Rollback(ctx)
	c, err := measureCorrection(ctx, tx, p, resource)
	if err != nil {
		return c, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_export_correction(id,team_id,period_start,period_end,resource_type,frozen,
        measured_quantity,baseline_quantity,reserved_quantity,target_quantity,previous_id,measurement_snapshot,version)
        VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9::numeric,$10::numeric,$11,$12,$13)`,
		c.ID, p.TeamID, p.Start, p.End, resource, c.Frozen, c.Measured, c.Baseline, c.Reserved, c.Target, c.Previous, c.Snapshot, c.Version)
	if err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}

// ApplyCorrection remeasures before taking locks and rejects a changed proposal.
// Retrying a committed proposal returns success without allocating another event.
func (s ExportStore) ApplyCorrection(ctx context.Context, id uuid.UUID, actor uuid.UUID, action, evidence string, payload ExportPayload) error {
	if actor == uuid.Nil || strings.TrimSpace(evidence) == "" || (action != "accept_usage" && action != "retain_exported") {
		return fmt.Errorf("reviewed action and evidence required")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var c ExportCorrection
	err = tx.QueryRow(ctx, `SELECT id,team_id,period_start,period_end,resource_type,frozen,measured_quantity::text,
        baseline_quantity::text,reserved_quantity::text,target_quantity::text,previous_id,measurement_snapshot,version,applied_at,action,evidence
        FROM billing_export_correction WHERE id=$1`, id).Scan(&c.ID, &c.TeamID, &c.Start, &c.End, &c.Resource, &c.Frozen, &c.Measured, &c.Baseline, &c.Reserved, &c.Target, &c.Previous, &c.Snapshot, &c.Version, &c.AppliedAt, &c.Action, &c.Evidence)
	if err != nil {
		return err
	}
	if c.AppliedAt != nil {
		if *c.Action != action || *c.Evidence != evidence {
			return ErrExportRecoveryRequired
		}
		return nil
	}
	fresh, err := measureCorrection(ctx, tx, c.ExportPeriod, c.Resource)
	if err != nil {
		return err
	}
	sameDecimal := func(a, b string) bool {
		x, xok := new(big.Rat).SetString(a)
		y, yok := new(big.Rat).SetString(b)
		return xok && yok && x.Cmp(y) == 0
	}
	samePrevious := c.Previous == nil && fresh.Previous == nil || c.Previous != nil && fresh.Previous != nil && *c.Previous == *fresh.Previous
	if c.Version != fresh.Version || c.Frozen != fresh.Frozen || !samePrevious || !sameDecimal(c.Measured, fresh.Measured) || !sameDecimal(c.Baseline, fresh.Baseline) ||
		!sameDecimal(c.Reserved, fresh.Reserved) || !sameDecimal(c.Target, fresh.Target) {
		return ErrExportRecoveryRequired
	}
	if _, err = lockExportRecoveryPeriod(ctx, tx, c.ExportPeriod); err != nil {
		return err
	}
	// This write makes concurrent snapshot approvals conflict, including no-op
	// corrections that do not allocate an event or change a frozen period row.
	tag, err := tx.Exec(ctx, `UPDATE billing_incremental_period SET correction_version=correction_version+1
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND correction_version=$4`, c.TeamID, c.Start, c.End, c.Version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrExportRecoveryRequired
	}
	if !c.Frozen {
		// Detect a consumer changing the authoritative open-period source after
		// this transaction's snapshot, without involving raw interval writers.
		if _, err = tx.Exec(ctx, `UPDATE billing_export_usage SET updated_at=updated_at
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, c.TeamID, c.Start, c.End); err != nil {
			return err
		}
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT feature_enabled('billing_export_enabled',$1) AND ($2<>'storage' OR feature_enabled('billing_storage_billing_enabled',$1))`, c.TeamID, c.Resource).Scan(&enabled)
	if err != nil {
		return err
	}
	if !enabled && !sameDecimal(c.Target, c.Reserved) {
		return fmt.Errorf("billing export is disabled")
	}
	measured, _ := new(big.Rat).SetString(c.Measured)
	floor, _ := new(big.Rat).SetString(maximumQuantity(c.Baseline, c.Reserved))
	if (measured.Cmp(floor) < 0) != (action == "retain_exported") {
		return fmt.Errorf("downward discrepancy requires explicit retain_exported disposition")
	}
	_, err = tx.Exec(ctx, `UPDATE billing_export_correction SET applied_at=clock_timestamp(),action=$2,evidence=$3,applied_by=$4,approval_snapshot=$5 WHERE id=$1`, id, action, evidence, actor, fresh.Snapshot)
	if err != nil {
		return err
	}
	payload.EventName, err = periodMeterEventName(ctx, tx, c.ExportPeriod, c.Resource, payload.EventName)
	if err != nil {
		return err
	}
	// At most two exact payload parts, sharing the ordinary event reservation ledger.
	through := c.End
	if !c.Frozen && time.Now().UTC().Truncate(time.Hour).Before(through) {
		through = time.Now().UTC().Truncate(time.Hour)
	}
	reserved := c.Reserved
	for part := 0; part < 2; part++ {
		delta, err := DecimalDelta(c.Target, reserved)
		if err != nil {
			return err
		}
		if delta == "0.000000000000" {
			break
		}
		quantity, err := meterQuantityPrefix(delta)
		if err != nil {
			return err
		}
		r, _ := new(big.Rat).SetString(reserved)
		d, _ := new(big.Rat).SetString(quantity)
		end := new(big.Rat).Add(r, d).FloatString(12)
		var allocation uuid.UUID
		err = tx.QueryRow(ctx, `INSERT INTO billing_export_allocation(team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through,correction_id)
            VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8) RETURNING id`, c.TeamID, c.Start, c.End, c.Resource, reserved, end, through, id).Scan(&allocation)
		if err != nil {
			return err
		}
		event := ExportEvent{ID: uuid.New(), AllocationID: allocation, Status: "pending", ExportPayload: payload}
		event.Identifier = "usage-" + event.ID.String()
		event.IdempotencyKey = event.Identifier
		event.Quantity = quantity
		if err = insertExportEvent(ctx, tx, event, "export", &evidence, nil); err != nil {
			return err
		}
		reserved = end
	}
	// Only evidence predating the proposal is resolved; later discoveries
	// remain visible for another operator measurement.
	_, err = tx.Exec(ctx, `UPDATE billing_period_anomaly SET resolved_at=now(),resolved_by=$5 WHERE team_id=$1 AND period_start=$2 AND period_end=$3
        AND resolved_at IS NULL AND detected_at<=(SELECT created_at FROM billing_export_correction WHERE id=$6)
        AND kind='incremental_export_exceeds_usage' AND details->>'resource'=$4`, c.TeamID, c.Start, c.End, c.Resource, actor, c.ID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_period_anomaly a SET resolved_at=now(),resolved_by=$4
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resolved_at IS NULL
        AND a.kind='usage_after_export_freeze' AND a.detected_at<=now()
        AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['cpu','memory','storage']) AS r(resource)
            WHERE (r.resource<>'storage' OR feature_enabled('billing_storage_billing_enabled',$1))
            AND NOT EXISTS(SELECT 1 FROM billing_export_correction c WHERE c.team_id=a.team_id AND c.period_start=a.period_start
                AND c.period_end=a.period_end AND c.resource_type=r.resource AND c.applied_at IS NOT NULL
                AND c.created_at>=a.detected_at))`, c.TeamID, c.Start, c.End, actor)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CorrectionTarget retains the reviewed excess without changing financial usage.
// For frozen periods it also includes explicitly authorized late usage.
func (s ExportStore) CorrectionTarget(ctx context.Context, p ExportPeriod, resource, measured string) (string, error) {
	var target, approved string
	var frozen bool
	err := s.Pool.QueryRow(ctx, `SELECT target_quantity::text,measured_quantity::text,frozen FROM billing_export_correction
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4 AND applied_at IS NOT NULL
        ORDER BY applied_at DESC,id DESC LIMIT 1`, p.TeamID, p.Start, p.End, resource).Scan(&target, &approved, &frozen)
	if errors.Is(err, pgx.ErrNoRows) {
		return measured, nil
	}
	if err != nil {
		return "", err
	}
	if !frozen {
		m, _ := new(big.Rat).SetString(measured)
		a, _ := new(big.Rat).SetString(approved)
		if m == nil || a == nil || m.Cmp(a) < 0 {
			return measured, nil
		}
	}
	return maximumQuantity(measured, target), nil
}
