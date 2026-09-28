package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
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

	meterID, err := c.incrementalMeterID(ctx, eventName)
	if err != nil {
		return "", err
	}
	values := url.Values{"customer": {customer}, "start_time": {strconv.FormatInt(start.Unix(), 10)}, "end_time": {strconv.FormatInt(end.Unix(), 10)}, "limit": {"100"}}
	var summary struct {
		Data *[]struct {
			Value json.Number `json:"aggregated_value"`
		} `json:"data"`
		HasMore *bool `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/meters/"+url.PathEscape(meterID)+"/event_summaries?"+values.Encode(), nil, &summary, ""); err != nil {
		return "", err
	}
	if summary.Data == nil || summary.HasMore == nil || *summary.HasMore || len(*summary.Data) > 1 {
		return "", fmt.Errorf("unexpected grouped meter summary")
	}
	if len(*summary.Data) == 0 {
		return "0", nil
	}
	value := (*summary.Data)[0].Value.String()
	if _, err := meterDecimal(value); err != nil {
		return "", err
	}
	return value, nil
}

func (c *stripeHTTPClient) incrementalMeterID(ctx context.Context, eventName string) (string, error) {
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
	return meterID, nil
}

// Precision reconciliation is deliberately narrower than Stripe's possible
// aggregation error: exact daily evidence plus at most one binary64 spacing.
// It is not an event acceptance oracle and never changes reserved coverage.
const meterPrecisionPolicy = "exact-daily-one-ulp-v1"
const meterEvidenceLimit = 4096

var errMeterBucketMismatch = errors.New("provider bucket differs from submitted quantity")

var meterDecimalPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]{1,3})?$`)

func meterDecimal(value string) (*big.Rat, error) {
	if len(value) > 128 || !meterDecimalPattern.MatchString(value) {
		return nil, fmt.Errorf("invalid meter decimal")
	}
	r, ok := new(big.Rat).SetString(value)
	if !ok || r.Sign() < 0 {
		return nil, fmt.Errorf("invalid meter decimal")
	}
	return r, nil
}

// meterQuantity validates a provider or local quantity without applying the
// narrower residual precision policy. Equality and provider lag remain valid
// at any supported cumulative magnitude; the precision range is checked only
// when a positive excess is being considered for an explained-drift bypass.
func meterQuantity(value string) (*big.Rat, error) {
	return meterDecimal(value)
}

// meterPrecisionBound is consulted only for a positive provider excess. The
// exact comparison path intentionally permits equality and provider lag at
// cumulative magnitudes outside this residual policy range.
func meterPrecisionBound(local *big.Rat) (*big.Rat, error) {
	if local.Sign() == 0 {
		return new(big.Rat), nil
	}
	if local.Cmp(big.NewRat(1, 1_000_000_000_000)) < 0 || local.Cmp(big.NewRat(1_000_000_000, 1)) > 0 {
		return nil, fmt.Errorf("quantity outside precision policy range [1e-12,1e9]")
	}
	power := func(exponent int) *big.Rat {
		if exponent < 0 {
			return new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), uint(-exponent)))
		}
		return new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(exponent)))
	}
	exponent := local.Num().BitLen() - local.Denom().BitLen()
	if local.Cmp(power(exponent)) < 0 {
		exponent--
	}
	return power(exponent - 52), nil
}

type meterUsageBucket struct {
	Start, End time.Time
	Quantity   string
}

type stripeMeterBucketReader interface {
	BucketedMeterUsage(context.Context, string, string, time.Time, time.Time) ([]meterUsageBucket, error)
}

func meterEvidenceWindows(start, end time.Time) ([]meterUsageBucket, error) {
	if !start.Before(end) || end.Sub(start) > 32*24*time.Hour || !start.Equal(start.Truncate(time.Minute)) || !end.Equal(end.Truncate(time.Minute)) {
		return nil, fmt.Errorf("unsupported meter evidence window")
	}
	var windows []meterUsageBucket
	for cursor := start.UTC(); cursor.Before(end); {
		next := cursor.Truncate(24 * time.Hour).Add(24 * time.Hour)
		if next.After(end) {
			next = end
		}
		windows = append(windows, meterUsageBucket{Start: cursor, End: next})
		cursor = next
	}
	return windows, nil
}

// Full UTC days fit in one page. Partial-day edges use ungrouped summaries;
// widening to day boundaries would admit events outside the decision window.
func (c *stripeHTTPClient) BucketedMeterUsage(ctx context.Context, event, customer string, start, end time.Time) ([]meterUsageBucket, error) {
	windows, err := meterEvidenceWindows(start, end)
	if err != nil {
		return nil, err
	}
	meterID, err := c.incrementalMeterID(ctx, event)
	if err != nil {
		return nil, err
	}
	var result []meterUsageBucket
	for i := 0; i < len(windows); {
		j := i + 1
		grouped := windows[i].End.Sub(windows[i].Start) == 24*time.Hour
		if grouped {
			for j < len(windows) && windows[j].End.Sub(windows[j].Start) == 24*time.Hour {
				j++
			}
		}
		values := url.Values{"customer": {customer}, "start_time": {strconv.FormatInt(windows[i].Start.Unix(), 10)},
			"end_time": {strconv.FormatInt(windows[j-1].End.Unix(), 10)}, "limit": {"100"}}
		if grouped {
			values.Set("value_grouping_window", "day")
		}
		var response struct {
			Data *[]struct {
				ID    string      `json:"id"`
				Meter string      `json:"meter"`
				Start *int64      `json:"start_time"`
				End   *int64      `json:"end_time"`
				Value json.Number `json:"aggregated_value"`
			} `json:"data"`
			HasMore *bool `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/meters/"+url.PathEscape(meterID)+"/event_summaries?"+values.Encode(), nil, &response, ""); err != nil {
			return nil, err
		}
		// A completed grouped response may omit empty intervals. Local event
		// evidence below decides whether an omitted interval is safe to treat as
		// zero; the provider reader must still reject pagination and malformed
		// rows.
		if response.HasMore == nil || *response.HasMore {
			return nil, fmt.Errorf("incomplete bounded meter buckets")
		}
		if response.Data == nil {
			return nil, fmt.Errorf("missing meter bucket data")
		}
		seen := map[string]bool{}
		for _, row := range *response.Data {
			if row.ID == "" || seen[row.ID] || row.Meter != meterID || row.Start == nil || row.End == nil {
				return nil, fmt.Errorf("malformed meter bucket identity or window")
			}
			seen[row.ID] = true
			bucketStart := time.Unix(*row.Start, 0).UTC()
			bucketEnd := time.Unix(*row.End, 0).UTC()
			validWindow := false
			for _, window := range windows[i:j] {
				if bucketStart.Equal(window.Start) && bucketEnd.Equal(window.End) {
					validWindow = true
					break
				}
			}
			if !validWindow {
				return nil, fmt.Errorf("meter bucket coverage differs from requested window")
			}
			if _, err := meterQuantity(row.Value.String()); err != nil {
				return nil, err
			}
			result = append(result, meterUsageBucket{Start: bucketStart, End: bucketEnd, Quantity: row.Value.String()})
		}
		i = j
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Start.Before(result[j].Start) })
	return result, nil
}

type meterLocalEvent struct {
	ID, EventName, Customer, Quantity, Status string
	Timestamp                                 int64
	Updated                                   time.Time
}

func (h *Handlers) meterLocalEvidence(ctx context.Context, p billing.ExportPeriod, resource string) ([]meterLocalEvent, error) {
	rows, err := h.Pool.Query(ctx, `SELECT e.id::text,e.event_name,e.customer_id,e.quantity_payload,e.status,e.event_timestamp,e.updated_at
        FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id AND e.active
        WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND a.resource_type=$4
        ORDER BY a.coverage_end DESC LIMIT $5`, p.TeamID, p.Start, p.End, resource, meterEvidenceLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []meterLocalEvent
	for rows.Next() {
		var event meterLocalEvent
		if err := rows.Scan(&event.ID, &event.EventName, &event.Customer, &event.Quantity, &event.Status, &event.Timestamp, &event.Updated); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) > meterEvidenceLimit {
		return nil, fmt.Errorf("local meter evidence exceeds event budget")
	}
	return events, nil
}

func matchMeterBuckets(events []meterLocalEvent, buckets []meterUsageBucket, event, customer string, start, end time.Time, reserved *big.Rat) error {
	windows, err := meterEvidenceWindows(start, end)
	if err != nil {
		return err
	}
	if len(events) > meterEvidenceLimit {
		return fmt.Errorf("incomplete meter evidence")
	}
	totals := make([]*big.Rat, len(windows))
	for i := range totals {
		totals[i] = new(big.Rat)
	}
	sum := new(big.Rat)
	for _, e := range events {
		if (e.Status != "submitted" && e.Status != "adopted") || e.EventName != event || e.Customer != customer || e.Timestamp < start.Unix() || e.Timestamp >= end.Unix() {
			return fmt.Errorf("unsettled or out-of-window local meter evidence")
		}
		quantity, err := meterQuantity(e.Quantity)
		if err != nil {
			return err
		}
		sum.Add(sum, quantity)
		for i, w := range windows {
			if e.Timestamp >= w.Start.Unix() && e.Timestamp < w.End.Unix() {
				totals[i].Add(totals[i], quantity)
				break
			}
		}
	}
	if sum.Cmp(reserved) != 0 {
		return fmt.Errorf("submitted snapshot differs from reservations")
	}
	bucketByWindow := make(map[string]meterUsageBucket, len(buckets))
	for _, b := range buckets {
		key := b.Start.UTC().Format(time.RFC3339) + "/" + b.End.UTC().Format(time.RFC3339)
		if _, exists := bucketByWindow[key]; exists {
			return fmt.Errorf("duplicate meter bucket window")
		}
		valid := false
		for _, w := range windows {
			if b.Start.Equal(w.Start) && b.End.Equal(w.End) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("incomplete meter bucket windows")
		}
		if _, err := meterQuantity(b.Quantity); err != nil {
			return err
		}
		bucketByWindow[key] = b
	}
	for i, w := range windows {
		key := w.Start.UTC().Format(time.RFC3339) + "/" + w.End.UTC().Format(time.RFC3339)
		b, present := bucketByWindow[key]
		if !present {
			// Stripe omits empty grouped intervals. An omitted interval is
			// complete evidence only when the local submitted snapshot is also
			// empty for that exact persisted event-time window.
			if totals[i].Sign() != 0 {
				return fmt.Errorf("incomplete meter bucket windows")
			}
			continue
		}
		quantity, err := meterQuantity(b.Quantity)
		if err != nil {
			return err
		}
		if quantity.Cmp(totals[i]) != 0 {
			return fmt.Errorf("%w at %s", errMeterBucketMismatch, b.Start.Format(time.RFC3339))
		}
	}
	return nil
}

type meterReconciliationDecision struct {
	Outcome, Difference, Bound string
	Err                        error
}

func compareMeterSummary(counted, reservedValue string) (decision meterReconciliationDecision, needsEvidence bool) {
	decision.Outcome = "incomplete"
	provider, err := meterDecimal(counted)
	reserved, localErr := meterDecimal(reservedValue)
	if err != nil || localErr != nil {
		decision.Err = errors.Join(billing.ErrExportRecoveryRequired, err, localErr)
		return
	}
	difference := new(big.Rat).Sub(provider, reserved)
	decision.Difference = difference.RatString()
	if difference.Sign() <= 0 {
		decision.Outcome = "equal"
		if difference.Sign() < 0 {
			decision.Outcome = "provider_lag"
		}
		return
	}
	decision.Outcome = "unexplained_excess"
	bound, err := meterPrecisionBound(reserved)
	if err != nil {
		decision.Err = errors.Join(billing.ErrExportRecoveryRequired, err)
		return
	}
	decision.Bound = bound.RatString()
	if difference.Cmp(bound) > 0 {
		decision.Err = billing.ErrExportRecoveryRequired
		return
	}
	decision.Outcome = "incomplete"
	decision.Err = billing.ErrExportRecoveryRequired
	return decision, true
}

func (h *Handlers) assessMeterSummary(ctx context.Context, p billing.ExportPeriod, item incrementalExportItem, through time.Time, reader stripeMeterSummaryReader, customer, counted string, totals billing.ExportTotals, countErr error) (decision meterReconciliationDecision) {
	decision.Outcome = "incomplete"
	defer func() {
		start, end := meterObservationWindow(p.Start, through)
		log.Info().Str("team_id", p.TeamID.String()).Str("resource", item.ResourceType).Str("event_name", item.EventName).
			Time("query_start", start).Time("query_end", end).Str("local_quantity", item.Quantity).
			Str("reserved_quantity", totals.Reserved).Str("submitted_quantity", totals.Submitted).Str("provider_quantity", counted).
			Str("difference", decision.Difference).Str("precision_bound", decision.Bound).Str("policy", meterPrecisionPolicy).
			Str("outcome", decision.Outcome).Err(decision.Err).Msg("billing meter reconciliation decision")
	}()
	if countErr != nil {
		decision.Err = countErr
		return
	}
	for _, value := range []string{item.Quantity, totals.Submitted, totals.Pending} {
		if value == "" {
			continue
		}
		if _, err := meterDecimal(value); err != nil {
			decision.Err = errors.Join(billing.ErrExportRecoveryRequired, err)
			return
		}
	}
	var needsEvidence bool
	decision, needsEvidence = compareMeterSummary(counted, totals.Reserved)
	if !needsEvidence {
		return
	}
	provider, _ := meterDecimal(counted)
	reserved, _ := meterDecimal(totals.Reserved)
	bucketReader, ok := reader.(stripeMeterBucketReader)
	if !ok {
		decision.Err = fmt.Errorf("%w: bucket reader unavailable", decision.Err)
		return
	}
	// The timeout covers both provider reads and bounded local snapshots, outside
	// period locks. Reserve still rechecks authoritative coverage transactionally.
	evidenceTimeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		// Leave time for the worker to persist lease release and backoff even
		// when the provider consumes the remainder of the tick budget.
		remaining := time.Until(deadline) - 5*time.Second
		if remaining <= 0 {
			decision.Err = errors.Join(decision.Err, context.DeadlineExceeded)
			return
		}
		if remaining < evidenceTimeout {
			evidenceTimeout = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()
	start, end := meterObservationWindow(p.Start, through)
	events, err := h.meterLocalEvidence(ctx, p, item.ResourceType)
	if err == nil {
		for pass := 0; pass < 2; pass++ {
			var buckets []meterUsageBucket
			buckets, err = bucketReader.BucketedMeterUsage(ctx, item.EventName, customer, start, end)
			if err == nil {
				err = matchMeterBuckets(events, buckets, item.EventName, customer, start, end, reserved)
			}
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		var reread string
		reread, err = reader.CountedMeterUsage(ctx, item.EventName, customer, p.Start, through)
		if err == nil {
			var value *big.Rat
			value, err = meterDecimal(reread)
			if err == nil && value.Cmp(provider) != 0 {
				err = fmt.Errorf("provider summary changed during reconciliation")
			}
		}
	}
	if err == nil {
		var after []meterLocalEvent
		after, err = h.meterLocalEvidence(ctx, p, item.ResourceType)
		if err == nil && !reflect.DeepEqual(events, after) {
			err = fmt.Errorf("local evidence changed during reconciliation")
		}
	}
	if err != nil {
		decision.Err = errors.Join(decision.Err, err)
		if errors.Is(err, errMeterBucketMismatch) {
			decision.Outcome = "unexplained_excess"
		}
		return
	}
	decision.Outcome, decision.Err = "explained_precision", nil
	return
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
	var shadowHandoff bool
	if err := h.Pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM billing_usage_export
			WHERE team_id=$1 AND period_start=$2 AND period_end=$3
			  AND status='skipped_shadow'
		)
	`, p.TeamID, p.Start, p.End).Scan(&shadowHandoff); err != nil {
		return result, err
	}
	if account.StripeCustomerID == nil || (!account.CommercialBillingAnchor.Valid && !shadowHandoff) {
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
	if account.CommercialBillingAnchor.Valid {
		start, end, ok := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, p.Start)
		if !ok || !start.Equal(p.Start) || !end.Equal(p.End) {
			return result, fmt.Errorf("period does not match commercial anchor")
		}
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
		frozenResult, reconcileErr := h.reconcileFrozenIncrementalPeriod(ctx, p)
		if reconcileErr != nil {
			return frozenResult, reconcileErr
		}
		if err = h.submitIncrementalEvents(ctx, p, 2*len(h.billingResourceStates(storage))); err != nil {
			return frozenResult, err
		}
		return frozenResult, nil
	}

	var usage db.TeamBillingUsage
	through := h.nowUTC().Truncate(time.Hour)
	closing := !h.nowUTC().Before(p.End)
	if closing {
		if period.Status != "approved" && period.Status != "exporting" {
			return result, fmt.Errorf("closed billing period requires approval before final export")
		}
		txCtx, cancelTx := context.WithTimeout(ctx, billing.StorageReportSettlementTimeout)
		defer cancelTx()
		tx, err := h.Pool.BeginTx(txCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return result, err
		}
		defer tx.Rollback(txCtx)
		q := h.DB.WithTx(tx)
		locked, err := q.GetTeamBillingPeriodForUpdate(txCtx, db.GetTeamBillingPeriodForUpdateParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
		if err != nil {
			return result, err
		}
		if locked.Status == "approved" {
			if err := prepareBillingStorageSnapshot(txCtx, tx, p.TeamID, p.End); err != nil {
				return result, err
			}
			row, _, err := h.upsertBillingSnapshotWithQueries(txCtx, q, p.TeamID, p.Start, p.End)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return result, billing.ErrStorageReportsIncomplete
				}
				return result, err
			}
			usage = billingTeamUsageFromUpsertRow(row)
			if _, err = q.MarkTeamBillingPeriodExporting(txCtx, db.MarkTeamBillingPeriodExportingParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End}); err != nil {
				return result, err
			}
		} else if locked.Status == "exporting" {
			usage, err = q.GetTeamBillingUsageRollup(txCtx, db.GetTeamBillingUsageRollupParams{TeamID: p.TeamID, PeriodStart: p.Start, PeriodEnd: p.End})
			if err != nil {
				return result, err
			}
		} else {
			return result, billing.ErrExportRecoveryRequired
		}
		if err = tx.Commit(txCtx); err != nil {
			return result, err
		}
		cancelTx()
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
		started := time.Now()
		counted, countErr := reader.CountedMeterUsage(ctx, item.EventName, *account.StripeCustomerID, p.Start, through)
		decisionItem := item
		decisionItem.Quantity = cumulative
		decision := h.assessMeterSummary(ctx, p, decisionItem, through, reader, *account.StripeCustomerID, counted, totals, countErr)
		if decision.Err != nil {
			recordErr := h.recordMeterObservation(ctx, p, decisionItem, through, totals, counted, decision.Err, started)
			return result, errors.Join(decision.Err, recordErr)
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

	// Retry already-reserved pending/uncertain events only after every current
	// usage/correction target has passed the local safety checks above. This
	// prevents a downward measurement correction from delivering stale coverage
	// before the gate can return recovery-required.
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
	counted, countErr := reader.CountedMeterUsage(ctx, item.EventName, customer, p.Start, through)
	decision := h.assessMeterSummary(ctx, p, item, through, reader, customer, counted, totals, countErr)
	err = h.recordMeterObservation(ctx, p, item, through, totals, counted, decision.Err, started)
	return totals, errors.Join(err, decision.Err)
}

func (h *Handlers) recordMeterObservation(ctx context.Context, p billing.ExportPeriod, item incrementalExportItem, through time.Time, totals billing.ExportTotals, counted string, decisionErr error, started time.Time) error {
	previousAge, ageErr := (billing.ExportStore{Pool: h.Pool}).PreviousObservationAge(ctx, p, item.ResourceType)
	if ageErr != nil {
		log.Warn().Err(ageErr).Msg("billing observation freshness read failed")
	}
	var countedMetric *float64
	if _, parseErr := meterDecimal(counted); parseErr == nil {
		if value, parseErr := strconv.ParseFloat(counted, 64); parseErr == nil {
			countedMetric = &value
		}
	}
	localMetric, _ := strconv.ParseFloat(item.Quantity, 64)
	currentBillingRecorder().RecordBillingReconciliation(ctx, item.ResourceType, localMetric, countedMetric, previousAge)

	var countedValue *string
	var message *string
	if _, parseErr := meterDecimal(counted); parseErr == nil {
		countedValue = &counted
	}
	if decisionErr != nil {
		m := decisionErr.Error()
		message = &m
	}
	queryStart, queryEnd := meterObservationWindow(p.Start, through)
	_, err := h.Pool.Exec(ctx, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end,last_error)
        VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11)
        ON CONFLICT(team_id,period_start,period_end,resource_type) DO UPDATE SET
        local_quantity=EXCLUDED.local_quantity,submitted_quantity=EXCLUDED.submitted_quantity,reserved_quantity=EXCLUDED.reserved_quantity,
        counted_quantity=EXCLUDED.counted_quantity,query_start=EXCLUDED.query_start,query_end=EXCLUDED.query_end,last_error=EXCLUDED.last_error,observed_at=now()`,
		p.TeamID, p.Start, p.End, item.ResourceType, item.Quantity, totals.Submitted, totals.Reserved, countedValue, queryStart, queryEnd, message)
	currentBillingRecorder().RecordBillingWork(ctx, "reconciliation", err != nil || decisionErr != nil || ageErr != nil, time.Since(started), 1)
	return err
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
	// This reconciliation path has no Reserve call to recheck coverage before
	// retrying a pending event. Validate every current/correction target against
	// reserved coverage before any delivery claim, preserving the downward-usage
	// guard.
	store := billing.ExportStore{Pool: h.Pool}
	for _, item := range items {
		target, targetErr := store.CorrectionTarget(ctx, p, item.ResourceType, item.Quantity)
		if targetErr != nil {
			return result, targetErr
		}
		totals, totalsErr := store.Totals(ctx, p, item.ResourceType)
		if totalsErr != nil {
			return result, totalsErr
		}
		if _, deltaErr := billing.DecimalDelta(target, totals.Reserved); deltaErr != nil {
			return result, deltaErr
		}
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
