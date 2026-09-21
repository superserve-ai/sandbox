package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type stripeMeterSummaryReader interface {
	CountedMeterUsage(context.Context, string, string, time.Time, time.Time) (string, error)
}

// Attribute aggregate events inside complete provider minutes while retaining
// the exact anniversary and measured-through boundaries in local coverage.
func meterObservationWindow(start, end time.Time) (time.Time, time.Time) {
	first := start.Truncate(time.Minute)
	if first.Before(start) {
		first = first.Add(time.Minute)
	}
	return first, end.Truncate(time.Minute)
}

func (c *stripeHTTPClient) CountedMeterUsage(ctx context.Context, eventName, customer string, start, end time.Time) (string, error) {
	start, end = meterObservationWindow(start, end)
	if !start.Before(end) {
		return "", fmt.Errorf("meter observation window is not yet complete")
	}

	var meterID string
	after := ""
	for page := 0; page < 5; page++ {
		var list struct {
			Data []struct {
				ID                 string  `json:"id"`
				EventName          string  `json:"event_name"`
				EventTimeWindow    *string `json:"event_time_window"`
				DefaultAggregation struct {
					Formula string `json:"formula"`
				} `json:"default_aggregation"`
				CustomerMapping struct {
					Key string `json:"event_payload_key"`
				} `json:"customer_mapping"`
				ValueSettings struct {
					Key string `json:"event_payload_key"`
				} `json:"value_settings"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		values := url.Values{"status": {"active"}, "limit": {"100"}}
		if after != "" {
			values.Set("starting_after", after)
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/meters?"+values.Encode(), nil, &list, ""); err != nil {
			return "", err
		}
		for _, m := range list.Data {
			if m.EventName != eventName {
				continue
			}
			if m.DefaultAggregation.Formula != "sum" || m.EventTimeWindow != nil || m.CustomerMapping.Key != "stripe_customer_id" || m.ValueSettings.Key != "value" {
				return "", fmt.Errorf("meter configuration is incompatible with incremental sums")
			}
			meterID = m.ID
		}
		if meterID != "" || !list.HasMore {
			break
		}
		if len(list.Data) == 0 {
			return "", fmt.Errorf("empty paginated meter response")
		}
		after = list.Data[len(list.Data)-1].ID
	}
	if meterID == "" {
		return "", fmt.Errorf("configured meter was not found within bounded lookup")
	}
	values := url.Values{"customer": {customer}, "start_time": {strconv.FormatInt(start.Unix(), 10)}, "end_time": {strconv.FormatInt(end.Unix(), 10)}, "limit": {"100"}}
	var summary struct {
		Data []struct {
			Value json.Number `json:"aggregated_value"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/meters/"+url.PathEscape(meterID)+"/event_summaries?"+values.Encode(), nil, &summary, ""); err != nil {
		return "", err
	}
	if summary.HasMore || len(summary.Data) > 1 {
		return "", fmt.Errorf("unexpected grouped meter summary")
	}
	if len(summary.Data) == 0 {
		return "0", nil
	}
	value := summary.Data[0].Value.String()
	if _, err := billing.DecimalDelta(value, "0"); err != nil {
		return "", err
	}
	return value, nil
}

type incrementalExportItem struct {
	ResourceType string
	EventName    string
	Quantity     string
}

func incrementalExportItems(usage db.TeamBillingUsage, resources []billingResourceState) ([]incrementalExportItem, error) {
	items := make([]incrementalExportItem, 0, len(resources))
	for _, resource := range resources {
		if !resource.Billable || !resource.CheckoutEnabled {
			continue
		}
		var seconds pgtype.Numeric
		switch resource.ResourceKey {
		case "vcpu":
			seconds = usage.VcpuSeconds
		case "memory_gib":
			seconds = usage.MemoryMibSeconds
		case "storage_gib":
			seconds = usage.StorageMibSeconds
		default:
			continue
		}
		quantity, err := billing.MeterUsageQuantity(seconds, resource.ResourceKey)
		if err != nil {
			return nil, err
		}
		items = append(items, incrementalExportItem{
			ResourceType: billingExportResourceType(resource.ResourceKey),
			EventName:    resource.StripeEventName,
			Quantity:     quantity,
		})
	}
	return items, nil
}

// Existing allocations still require provider evidence after billing is disabled.
// These items are only for observation; allocation uses the current billing gates.
func (h *Handlers) incrementalReconciliationItems(ctx context.Context, p billing.ExportPeriod, usage db.TeamBillingUsage, resources []billingResourceState) ([]incrementalExportItem, error) {
	items, err := incrementalExportItems(usage, resources)
	if err != nil {
		return nil, err
	}
	configured := make(map[string]bool, len(items))
	for _, item := range items {
		configured[item.ResourceType] = true
	}
	rows, err := h.Pool.Query(ctx, `SELECT DISTINCT resource_type FROM billing_export_allocation
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3 ORDER BY resource_type`, p.TeamID, p.Start, p.End)
	if err != nil {
		return nil, err
	}
	var persisted []string
	for rows.Next() {
		var resource string
		if err = rows.Scan(&resource); err != nil {
			rows.Close()
			return nil, err
		}
		persisted = append(persisted, resource)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	store := billing.ExportStore{Pool: h.Pool}
	for _, resource := range persisted {
		if configured[resource] {
			continue
		}
		totals, err := store.Totals(ctx, p, resource)
		if err != nil {
			return nil, err
		}
		name, err := store.MeterEventName(ctx, p, resource, "")
		if err != nil {
			return nil, err
		}
		// Disabled or removed resources retain their existing coverage, not
		// any subsequent measurements. The persisted events pin the meter.
		items = append(items, incrementalExportItem{ResourceType: resource, EventName: name, Quantity: totals.Reserved})
	}
	return items, nil
}

type incrementalExportResult struct {
	PeriodID  string                          `json:"period_id"`
	Status    string                          `json:"status"`
	Resources map[string]billing.ExportTotals `json:"resources"`
}

// exportIncrementalPeriod is shared by the independent worker and the existing
// internal export endpoint. It never measures raw usage during an open period.
func (h *Handlers) exportIncrementalPeriod(ctx context.Context, p billing.ExportPeriod) (incrementalExportResult, error) {
	result := incrementalExportResult{PeriodID: billingPeriodID(p.Start, p.End), Resources: map[string]billing.ExportTotals{}}
	enabled, err := h.billingExportEnabled(ctx, p.TeamID)
	if err != nil {
		return result, err
	}
	if !enabled {
		return result, fmt.Errorf("billing export is disabled")
	}
	account, err := h.DB.GetTeamBillingAccount(ctx, p.TeamID)
	if err != nil {
		return result, err
	}
	if account.StripeCustomerID == nil || !account.CommercialBillingAnchor.Valid {
		return result, fmt.Errorf("active subscription, customer and commercial anchor are required")
	}
	if account.StripeSubscriptionStatus == nil || *account.StripeSubscriptionStatus != "active" {
		// Persisted frozen recovery remains deliverable after cancellation, but
		// inactive subscriptions cannot enroll periods or export open usage.
		var frozenRecovery bool
		if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_incremental_period i
            JOIN team_billing_period p USING(team_id,period_start,period_end)
            WHERE i.team_id=$1 AND i.period_start=$2 AND i.period_end=$3
              AND (p.status IN ('exporting','exported') OR p.finalized_at IS NOT NULL))`, p.TeamID, p.Start, p.End).Scan(&frozenRecovery); err != nil {
			return result, err
		}
		if !frozenRecovery {
			return result, fmt.Errorf("active subscription, customer and commercial anchor are required")
		}
	}
	start, end, ok := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, p.Start)
	if !ok || !start.Equal(p.Start) || !end.Equal(p.End) {
		return result, fmt.Errorf("period does not match commercial anchor")
	}
	if h.Stripe == nil {
		return result, fmt.Errorf("Stripe billing is not configured")
	}
	reader, ok := h.Stripe.(stripeMeterSummaryReader)
	if !ok {
		return result, fmt.Errorf("Stripe reconciliation is not configured")
	}
	store := billing.ExportStore{Pool: h.Pool}
	storage, err := h.billingStorageBillingEnabled(ctx, p.TeamID)
	if err != nil {
		return result, err
	}
	if err = store.Enroll(ctx, p); err != nil {
		return result, err
	}
	period, err := h.DB.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
	if err != nil {
		return result, err
	}
	result.Status = period.Status
	if period.Status == "exported" || period.FinalizedAt.Valid {
		if err = h.submitIncrementalEvents(ctx, p, 2*len(h.billingResourceStates(storage))); err != nil {
			return result, err
		}
		return h.reconcileFrozenIncrementalPeriod(ctx, p)
	}

	var usage db.TeamBillingUsage
	through := h.nowUTC().Truncate(time.Hour)
	closing := !h.nowUTC().Before(p.End)
	if closing {
		if period.Status != "approved" && period.Status != "exporting" {
			return result, fmt.Errorf("closed billing period requires approval before final export")
		}
		tx, err := h.Pool.Begin(ctx)
		if err != nil {
			return result, err
		}
		defer tx.Rollback(ctx)
		q := h.DB.WithTx(tx)
		locked, err := q.GetTeamBillingPeriodForUpdate(ctx, db.GetTeamBillingPeriodForUpdateParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
		if err != nil {
			return result, err
		}
		if locked.Status == "approved" {
			row, _, err := h.upsertBillingSnapshotWithQueries(ctx, q, p.TeamID, p.Start, p.End)
			if err != nil {
				return result, err
			}
			usage = billingTeamUsageFromUpsertRow(row)
			if _, err = q.MarkTeamBillingPeriodExporting(ctx, db.MarkTeamBillingPeriodExportingParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End}); err != nil {
				return result, err
			}
		} else if locked.Status == "exporting" {
			usage, err = q.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
			if err != nil {
				return result, err
			}
		} else {
			return result, billing.ErrExportRecoveryRequired
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		through = p.End
	} else {
		usage.TeamID = p.TeamID
		usage.PeriodStart = p.Start
		usage.PeriodEnd = p.End
		err = h.Pool.QueryRow(ctx, `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_usage
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&usage.VcpuSeconds, &usage.MemoryMibSeconds, &usage.StorageMibSeconds)
		if err != nil {
			return result, err
		}
	}
	items, err := incrementalExportItems(usage, h.billingResourceStates(storage))
	if err != nil {
		return result, err
	}
	if !through.After(p.Start) {
		return result, nil
	}
	// A frozen boundary is coverage metadata. A timestamp is solely the
	// persisted semantic attribution of the event, never a summary bucket.
	queryStart, queryEnd := meterObservationWindow(p.Start, through)
	timestamp := queryEnd.Add(-time.Second).Unix()
	if timestamp < queryStart.Unix() {
		return result, nil
	}
	for _, item := range items {
		item.EventName, err = store.MeterEventName(ctx, p, item.ResourceType, item.EventName)
		if err != nil {
			return result, err
		}
		cumulative, targetErr := store.CorrectionTarget(ctx, p, item.ResourceType, item.Quantity)
		if targetErr != nil {
			return result, targetErr
		}
		totals, totalErr := store.Totals(ctx, p, item.ResourceType)
		if totalErr != nil {
			return result, totalErr
		}
		counted, countErr := reader.CountedMeterUsage(ctx, item.EventName, *account.StripeCustomerID, p.Start, through)
		if countErr != nil {
			return result, countErr
		}
		provider, _ := new(big.Rat).SetString(counted)
		reserved, _ := new(big.Rat).SetString(totals.Reserved)
		if provider == nil || reserved == nil || provider.Cmp(reserved) > 0 {
			_, observeErr := h.observeIncrementalResource(ctx, p, item, through, reader, *account.StripeCustomerID)
			return result, errors.Join(billing.ErrExportRecoveryRequired, observeErr)
		}
		for part := 0; part < 2; part++ {
			_, reserveErr := store.Reserve(ctx, p, item.ResourceType, cumulative, through, billing.ExportPayload{
				EventName: item.EventName, CustomerID: *account.StripeCustomerID, Timestamp: timestamp,
			})
			if reserveErr != nil {
				if errors.Is(reserveErr, billing.ErrExportRecoveryRequired) {
					_, recordErr := h.Pool.Exec(ctx, `INSERT INTO billing_period_anomaly(team_id,period_start,period_end,severity,kind,details)
                    SELECT $1,$2,$3,'error','incremental_export_exceeds_usage',jsonb_build_object('resource',$4::text,'local_quantity',$5::text)
                    WHERE NOT EXISTS(SELECT 1 FROM billing_period_anomaly WHERE team_id=$1 AND period_start=$2 AND period_end=$3
                    AND kind='incremental_export_exceeds_usage' AND resolved_at IS NULL AND details->>'resource'=$4)`, p.TeamID, p.Start, p.End, item.ResourceType, cumulative)
					if recordErr != nil {
						return result, recordErr
					}
				}
				return result, reserveErr
			}
		}
	}

	if err = h.submitIncrementalEvents(ctx, p, 2*len(items)); err != nil {
		return result, err
	}
	reconciliationItems, err := h.incrementalReconciliationItems(ctx, p, usage, h.billingResourceStates(storage))
	if err != nil {
		return result, err
	}
	var reconcileErrors []error
	for _, item := range reconciliationItems {
		totals, observeErr := h.observeIncrementalResource(ctx, p, item, through, reader, *account.StripeCustomerID)
		result.Resources[item.ResourceType] = totals
		if observeErr != nil {
			reconcileErrors = append(reconcileErrors, observeErr)
		}
	}
	if err = errors.Join(reconcileErrors...); err != nil {
		return result, err
	}
	if closing {
		if _, err = h.DB.MarkTeamBillingPeriodExported(ctx, db.MarkTeamBillingPeriodExportedParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End}); err != nil {
			return result, err
		}
		result.Status = "exported"
	}
	return result, nil
}

func (h *Handlers) observeIncrementalResource(ctx context.Context, p billing.ExportPeriod, item incrementalExportItem, through time.Time, reader stripeMeterSummaryReader, customer string) (billing.ExportTotals, error) {
	target, err := (billing.ExportStore{Pool: h.Pool}).CorrectionTarget(ctx, p, item.ResourceType, item.Quantity)
	if err != nil {
		return billing.ExportTotals{}, err
	}
	item.Quantity = target
	item.EventName, err = (billing.ExportStore{Pool: h.Pool}).MeterEventName(ctx, p, item.ResourceType, item.EventName)
	if err != nil {
		return billing.ExportTotals{}, err
	}
	totals, err := (billing.ExportStore{Pool: h.Pool}).Totals(ctx, p, item.ResourceType)
	if err != nil {
		return totals, err
	}
	started := time.Now()
	previousAge, ageErr := (billing.ExportStore{Pool: h.Pool}).PreviousObservationAge(ctx, p, item.ResourceType)
	if ageErr != nil {
		log.Warn().Err(ageErr).Msg("billing observation freshness read failed")
	}
	counted, countErr := reader.CountedMeterUsage(ctx, item.EventName, customer, p.Start, through)
	var countedMetric *float64
	if countErr == nil {
		if value, parseErr := strconv.ParseFloat(counted, 64); parseErr == nil {
			countedMetric = &value
		}
	}
	localMetric, _ := strconv.ParseFloat(item.Quantity, 64)
	currentBillingRecorder().RecordBillingReconciliation(ctx, item.ResourceType, localMetric, countedMetric, previousAge)
	var countedValue *string
	var message *string
	if countErr != nil {
		m := countErr.Error()
		message = &m
	} else {
		countedValue = &counted
	}
	queryStart, queryEnd := meterObservationWindow(p.Start, through)
	_, err = h.Pool.Exec(ctx, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end,last_error)
        VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11)
        ON CONFLICT(team_id,period_start,period_end,resource_type) DO UPDATE SET
        local_quantity=EXCLUDED.local_quantity,submitted_quantity=EXCLUDED.submitted_quantity,reserved_quantity=EXCLUDED.reserved_quantity,
        counted_quantity=EXCLUDED.counted_quantity,query_start=EXCLUDED.query_start,query_end=EXCLUDED.query_end,last_error=EXCLUDED.last_error,observed_at=now()`,
		p.TeamID, p.Start, p.End, item.ResourceType, item.Quantity, totals.Submitted, totals.Reserved, countedValue, queryStart, queryEnd, message)
	currentBillingRecorder().RecordBillingWork(ctx, "reconciliation", err != nil || countErr != nil || ageErr != nil, time.Since(started), 1)
	return totals, errors.Join(err, countErr)
}

func (h *Handlers) submitIncrementalEvents(ctx context.Context, p billing.ExportPeriod, limit int) error {
	store := billing.ExportStore{Pool: h.Pool}
	// At most two exact payload parts per configured resource. Subsequent passes
	// continue the durable backlog without holding a transaction over Stripe.
	for i := 0; i < limit; i++ {
		event, err := store.Claim(ctx, p)
		if err != nil {
			return err
		}
		if event == nil {
			break
		}
		started := time.Now()
		submitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		submitErr := h.Stripe.ReportMeterEvent(submitCtx, StripeReportMeterEventParams{Identifier: event.Identifier, IdempotencyKey: event.IdempotencyKey,
			EventName: event.EventName, CustomerID: event.CustomerID, Value: event.Quantity, Timestamp: event.Timestamp})
		cancel()
		err = store.Acknowledge(ctx, *event, submitErr)
		currentBillingRecorder().RecordBillingWork(ctx, "submission", err != nil || submitErr != nil, time.Since(started), 1)
		if err != nil {
			return err
		}
		if submitErr != nil {
			log.Warn().Err(submitErr).Str("event_id", event.Identifier).Msg("incremental billing submission unresolved")
		}
	}
	return nil
}

func (h *Handlers) reconcileFrozenIncrementalPeriod(ctx context.Context, p billing.ExportPeriod) (incrementalExportResult, error) {
	return h.reconcileIncrementalPeriod(ctx, p, true)
}

func (h *Handlers) reconcileIncrementalPeriod(ctx context.Context, p billing.ExportPeriod, frozen bool) (incrementalExportResult, error) {
	result := incrementalExportResult{PeriodID: billingPeriodID(p.Start, p.End), Resources: map[string]billing.ExportTotals{}}
	account, err := h.DB.GetTeamBillingAccount(ctx, p.TeamID)
	if err != nil {
		return result, err
	}
	reader, ok := h.Stripe.(stripeMeterSummaryReader)
	if !ok || account.StripeCustomerID == nil {
		return result, fmt.Errorf("provider reconciliation unavailable")
	}
	var usage db.TeamBillingUsage
	through := p.End
	if frozen {
		usage, err = h.DB.GetTeamBillingUsageRollup(ctx, db.GetTeamBillingUsageRollupParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
	} else {
		through = h.nowUTC().Truncate(time.Hour)
		if through.After(p.End) {
			through = p.End
		}
		err = h.Pool.QueryRow(ctx, `SELECT vcpu_seconds,memory_mib_seconds,storage_mib_seconds FROM billing_export_usage
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&usage.VcpuSeconds, &usage.MemoryMibSeconds, &usage.StorageMibSeconds)
	}
	if err != nil {
		return result, err
	}
	storage, err := h.billingStorageBillingEnabled(ctx, p.TeamID)
	if err != nil {
		return result, err
	}
	items, err := h.incrementalReconciliationItems(ctx, p, usage, h.billingResourceStates(storage))
	if err != nil {
		return result, err
	}
	var observedErrors []error
	for _, item := range items {
		totals, observeErr := h.observeIncrementalResource(ctx, p, item, through, reader, *account.StripeCustomerID)
		result.Resources[item.ResourceType] = totals
		if observeErr != nil {
			observedErrors = append(observedErrors, observeErr)
		}
	}
	period, err := h.DB.GetTeamBillingPeriod(ctx, db.GetTeamBillingPeriodParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
	if err != nil {
		return result, err
	}
	result.Status = period.Status
	return result, errors.Join(observedErrors...)
}
