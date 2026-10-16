package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type entitlementCoverageSample struct {
	Contract uuid.UUID
	Age      float64
	Unknown  bool
}

// Audit contracts rather than queue entries: a missing or deferred work item
// must not hide a paid customer from monitoring. This never authorizes issuance.
func (h *Handlers) startEntitlementCoverageMonitoring(ctx context.Context) {
	go func() {
		var after uuid.UUID
		var missing, unknown int64
		var oldest, unknownOldest float64
		at := time.Now()
		for ctx.Err() == nil {
			wait := 30 * time.Second
			if h.Config != nil && h.Config.BillingUsageEntitlementsEnabled {
				if after == uuid.Nil {
					at = time.Now()
				}
				sample, cancel := context.WithTimeout(ctx, 3*time.Second)
				started := time.Now()
				rows, err := h.entitlementCoveragePage(sample, after, at, 1000)
				cancel()
				currentBillingRecorder().RecordBillingWork(ctx, "entitlement_coverage_sample", err != nil, time.Since(started), 0)
				if err != nil {
					log.Warn().Err(err).Msg("paid entitlement coverage observation failed")
				} else {
					for _, row := range rows {
						after = row.Contract
						if row.Age <= 15*60 {
							continue
						}
						missing = min(missing+1, 1000)
						oldest = max(oldest, row.Age)
						if row.Unknown {
							unknown = min(unknown+1, 1000)
							unknownOldest = max(unknownOldest, row.Age)
						}
					}
					if len(rows) == 1000 {
						wait = time.Second
					} else {
						currentBillingRecorder().RecordBillingBacklog(ctx, "entitlement_paid_missing", missing, oldest)
						currentBillingRecorder().RecordBillingBacklog(ctx, "entitlement_debt_unknown", unknown, unknownOldest)
						after, missing, unknown, oldest, unknownOldest = uuid.Nil, 0, 0, 0, 0
						at = time.Now()
					}
				}
			} else {
				after, missing, unknown, oldest, unknownOldest = uuid.Nil, 0, 0, 0, 0
				at = time.Now()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
}

func (h *Handlers) entitlementCoveragePage(ctx context.Context, after uuid.UUID, at time.Time, limit int) ([]entitlementCoverageSample, error) {
	rows, err := h.Pool.Query(ctx, `WITH page AS MATERIALIZED (
 SELECT * FROM billing_commercial_contract WHERE status='active' AND offer_key IN ('pro_monthly','pro_annual') AND id>$1 ORDER BY id LIMIT $3
)
SELECT c.id,
 CASE WHEN c.starts_at<=p.period_start AND (c.ends_at IS NULL OR c.ends_at>=p.period_end)
  AND pay.paid_at IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=c.id AND e.period_start=p.period_start AND e.state='issued')
  AND NOT COALESCE(w.observed_at>$2::timestamptz-interval '1 minute' AND w.evidence->>'unpaid_invoice'<>'',false)
 THEN greatest(0,extract(epoch FROM $2::timestamptz-greatest(p.period_start,pay.paid_at)))::double precision ELSE 0 END,
 NOT COALESCE(c.collection_has_overdue_balance IS FALSE AND c.collection_valid_until>$2
  AND c.collection_evidence->>'gate'='finalized_invoice_gate_v1'
  AND (c.collection_evidence->>'period_start')::timestamptz=p.period_start
  AND (c.collection_evidence->>'period_end')::timestamptz=p.period_end,false)
FROM page c LEFT JOIN LATERAL billing_contract_entitlement(c,$2) p ON true
LEFT JOIN LATERAL (SELECT paid_at FROM billing_contract_payment pay WHERE pay.contract_id=c.id
 AND pay.service_period_start<=p.period_start AND pay.service_period_end>=p.period_end
 AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=pay.invoice_id AND v.review_required)
 ORDER BY pay.service_period_start DESC LIMIT 1) pay ON true
LEFT JOIN billing_entitlement_withheld w ON w.contract_id=c.id AND w.period_start=p.period_start
ORDER BY c.id`, after, at, max(1, min(limit, 1000)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []entitlementCoverageSample
	for rows.Next() {
		var row entitlementCoverageSample
		if err := rows.Scan(&row.Contract, &row.Age, &row.Unknown); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
