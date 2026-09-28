package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/billing"
)

type meterCloseBucket struct {
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
	Quantity string `json:"quantity"`
}

type meterCloseEvidence struct {
	MeterID, EventName, Customer, Snapshot string
	CollectedAt                            time.Time
	Passes                                 [][]meterCloseBucket
}

// Missing provider intervals have already been proved to have zero local usage.
// Persist the complete partition so the database can independently check coverage.
func completeMeterBuckets(buckets []meterUsageBucket, start, end time.Time) []meterCloseBucket {
	windows, _ := meterEvidenceWindows(start, end)
	complete := make([]meterCloseBucket, 0, len(windows))
	for _, w := range windows {
		quantity := "0"
		for _, b := range buckets {
			if w.Start.Equal(b.Start) && w.End.Equal(b.End) {
				quantity = b.Quantity
				break
			}
		}
		complete = append(complete, meterCloseBucket{Start: w.Start.Unix(), End: w.End.Unix(), Quantity: quantity})
	}
	return complete
}

func (h *Handlers) meterAccountingSnapshot(ctx context.Context, p billing.ExportPeriod, resource string) (string, time.Time, error) {
	var snapshot *string
	var collected time.Time
	err := h.Pool.QueryRow(ctx, `SELECT billing_meter_accounting_snapshot($1,$2,$3,$4)::text,clock_timestamp()`, p.TeamID, p.Start, p.End, resource).Scan(&snapshot, &collected)
	if err != nil {
		return "", collected, err
	}
	if snapshot == nil {
		return "", collected, fmt.Errorf("incomplete bounded accounting snapshot")
	}
	return *snapshot, collected, nil
}

func persistMeterCloseEvidence(ctx context.Context, tx pgx.Tx, p billing.ExportPeriod, resource string, evidence meterCloseEvidence) error {
	passes, err := json.Marshal(evidence.Passes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_meter_reconciliation
        (team_id,period_start,period_end,resource_type,event_name,customer_id,meter_id,
         local_quantity,reserved_quantity,submitted_quantity,provider_quantity,difference,
         query_start,query_end,observed_at,collected_at,policy,accounting_snapshot,bucket_passes)
        SELECT team_id,period_start,period_end,resource_type,$5,$6,$7,
          local_quantity,reserved_quantity,submitted_quantity,counted_quantity,counted_quantity-reserved_quantity,
          query_start,query_end,observed_at,$8,$9,$10::jsonb,$11::jsonb
        FROM billing_export_observation WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4`,
		p.TeamID, p.Start, p.End, resource, evidence.EventName, evidence.Customer, evidence.MeterID,
		evidence.CollectedAt, meterPrecisionPolicy, evidence.Snapshot, passes)
	return err
}
