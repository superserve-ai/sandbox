package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActiveMeterResolver performs a fresh provider lookup, not a cached or pinned read.
type ActiveMeterResolver func(context.Context, string) (string, error)

type MeterCloseMapping struct {
	checkedAt time.Time
	meters    map[string]string
}

// RevalidateMeterCloseMapping runs before acquiring period locks. The result is
// bound to immutable evidence IDs so concurrent replacement observations cannot
// reuse a mapping check made for earlier evidence.
func RevalidateMeterCloseMapping(ctx context.Context, pool *pgxpool.Pool, p ExportPeriod, resolve ActiveMeterResolver) (MeterCloseMapping, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := MeterCloseMapping{meters: map[string]string{}}
	rows, err := pool.Query(ctx, `SELECT e.id::text,e.event_name,e.meter_id,clock_timestamp()
 FROM billing_export_observation o
 JOIN team_billing_period p USING(team_id,period_start,period_end)
 JOIN LATERAL (SELECT * FROM billing_meter_reconciliation r
   WHERE r.team_id=o.team_id AND r.period_start=o.period_start AND r.period_end=o.period_end
     AND r.resource_type=o.resource_type AND r.observed_at=o.observed_at ORDER BY r.id LIMIT 1) e ON true
 WHERE o.team_id=$1 AND o.period_start=$2 AND o.period_end=$3
   AND p.finalized_at IS NULL AND o.counted_quantity<>o.local_quantity
 ORDER BY o.resource_type LIMIT 4`, p.TeamID, p.Start, p.End)
	if err != nil {
		return result, err
	}
	type scope struct{ id, event, meter string }
	var scopes []scope
	for rows.Next() {
		var s scope
		if err := rows.Scan(&s.id, &s.event, &s.meter, &result.checkedAt); err != nil {
			rows.Close()
			return result, err
		}
		scopes = append(scopes, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(scopes) > 3 {
		return result, fmt.Errorf("%w: meter mapping scope exceeds resource bound", ErrExportRecoveryRequired)
	}
	for _, s := range scopes {
		if resolve == nil {
			return result, fmt.Errorf("%w: current meter mapping unavailable", ErrExportRecoveryRequired)
		}
		meter, err := resolve(ctx, s.event)
		if err != nil {
			return result, fmt.Errorf("%w: current meter mapping: %w", ErrExportRecoveryRequired, err)
		}
		if meter == "" || meter != s.meter {
			return result, fmt.Errorf("%w: active meter mapping changed", ErrExportRecoveryRequired)
		}
		result.meters[s.id] = meter
	}
	return result, nil
}

// Bind is transaction-local: old writers and direct updates without a current
// revalidation cannot use historical drift evidence to close.
func (m MeterCloseMapping) Bind(ctx context.Context, tx pgx.Tx) error {
	value, err := json.Marshal(struct {
		CheckedAt time.Time         `json:"checked_at"`
		Meters    map[string]string `json:"meters"`
	}{m.checkedAt, m.meters})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT set_config('billing.close_meter_mapping',$1,true)`, string(value))
	return err
}
