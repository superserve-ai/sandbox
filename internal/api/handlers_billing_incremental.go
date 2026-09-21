package api

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func (h *Handlers) AdoptBillingExports(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingWritePermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	start, end, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	var input struct {
		Evidence          string                  `json:"evidence"`
		Events            []billing.AdoptedExport `json:"events"`
		CompleteInventory bool                    `json:"complete_inventory"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	if err = c.ShouldBindJSON(&input); err != nil || !input.CompleteInventory || input.Evidence == "" || len(input.Events) == 0 || len(input.Events) > 100 {
		respondErrorMsg(c, "bad_request", "reviewed complete event inventory and evidence are required", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	enabled, err := h.billingExportEnabled(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if enabled {
		respondErrorMsg(c, "conflict", "export must remain disabled during adoption", http.StatusConflict)
		return
	}
	account, err := h.DB.GetTeamBillingAccount(ctx, team)
	if err != nil || !account.CommercialBillingAnchor.Valid || account.StripeCustomerID == nil {
		respondErrorMsg(c, "conflict", "commercial billing account is required", http.StatusConflict)
		return
	}
	expectedStart, expectedEnd, ok := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, start)
	if !ok || !expectedStart.Equal(start) || !expectedEnd.Equal(end) {
		respondErrorMsg(c, "conflict", "period does not match commercial anchor", http.StatusConflict)
		return
	}
	reader, ok := h.Stripe.(stripeMeterSummaryReader)
	if !ok {
		respondErrorMsg(c, "conflict", "provider reconciliation unavailable", http.StatusConflict)
		return
	}
	storage, err := h.billingStorageBillingEnabled(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	resources := map[[2]string]bool{}
	for _, resource := range h.billingResourceStates(storage) {
		if resource.Billable && resource.CheckoutEnabled {
			resources[[2]string{billingExportResourceType(resource.ResourceKey), resource.StripeEventName}] = true
		}
	}
	rows, err := h.Pool.Query(ctx, `SELECT DISTINCT resource_type,stripe_event_name FROM billing_usage_export
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3
        AND status NOT IN ('skipped_shadow','skipped_zero','skipped_disabled')`, team, start, end)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	for rows.Next() {
		var meter [2]string
		if err = rows.Scan(&meter[0], &meter[1]); err != nil {
			rows.Close()
			respondError(c, ErrInternal)
			return
		}
		resources[meter] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	totals := map[[2]string]*big.Rat{}
	seen := map[string]bool{}
	observationEnd := h.nowUTC()
	if end.Before(observationEnd) {
		observationEnd = end
	}
	queryStart, queryEnd := meterObservationWindow(start, observationEnd)
	p := billing.ExportPeriod{TeamID: team, Start: start, End: end}

	for _, event := range input.Events {
		if err := event.ValidateBoundary(p); err != nil {
			respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
			return
		}
		value, ok := new(big.Rat).SetString(event.Quantity)
		if !ok || value.Sign() <= 0 || event.Identifier == "" || event.IdempotencyKey == "" || seen[event.Identifier] || event.CustomerID != *account.StripeCustomerID || !resources[[2]string{event.Resource, event.EventName}] || event.EventName == "" || event.Through.After(h.nowUTC()) || event.Timestamp < queryStart.Unix() || event.Timestamp >= queryEnd.Unix() {
			respondErrorMsg(c, "bad_request", "invalid or duplicate adoption payload", http.StatusBadRequest)
			return
		}
		seen[event.Identifier] = true
		if totals[[2]string{event.Resource, event.EventName}] == nil {
			totals[[2]string{event.Resource, event.EventName}] = new(big.Rat)
		}
		totals[[2]string{event.Resource, event.EventName}].Add(totals[[2]string{event.Resource, event.EventName}], value)
	}
	through := h.nowUTC().Truncate(time.Minute)
	if end.Before(through) {
		through = end
	}
	// Read current and persisted legacy meters: omitting an additional resource must
	// fail the same way as a mismatch in a listed resource.
	for meter := range resources {
		counted, readErr := reader.CountedMeterUsage(ctx, meter[1], *account.StripeCustomerID, start, through)
		actual, valid := new(big.Rat).SetString(counted)
		expected := totals[meter]
		if expected == nil {
			expected = new(big.Rat)
		}
		if readErr != nil || !valid || actual.Cmp(expected) != 0 {
			respondErrorMsg(c, "conflict", "provider totals differ from complete adoption inventory; keep export disabled", http.StatusConflict)
			return
		}
	}
	store := billing.ExportStore{Pool: h.Pool}
	// Ordinary enrollment also reopens shadow-only periods. Live legacy
	// attempts require the verified inventory checked atomically by Adopt.
	if err = store.Enroll(ctx, p); err == nil || errors.Is(err, billing.ErrExportRecoveryRequired) {
		err = store.Adopt(ctx, p, input.Events, input.Evidence)
	}
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, gin.H{"adopted": len(input.Events), "export_enabled": false, "handover": "review provider evidence before explicitly enabling export"})
}

func (h *Handlers) RecoverBillingExport(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingWritePermission); !ok {
		return
	}
	id, err := uuid.Parse(c.Param("event_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid event id", http.StatusBadRequest)
		return
	}
	var input struct {
		Evidence string `json:"evidence"`
		Outcome  string `json:"outcome"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
	if err = c.ShouldBindJSON(&input); err != nil || input.Evidence == "" {
		respondErrorMsg(c, "bad_request", "reviewed evidence is required", http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	store := billing.ExportStore{Pool: h.Pool}
	if input.Outcome == "" {
		err = store.RecoverRejected(c.Request.Context(), id, input.Evidence)
	} else if input.Outcome == "accepted" || input.Outcome == "rejected" {
		err = store.ResolveRecovery(c.Request.Context(), id, input.Outcome, input.Evidence)
	} else {
		respondErrorMsg(c, "bad_request", "outcome must be accepted or rejected", http.StatusBadRequest)
		return
	}
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) GetBillingExportAccounting(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, "platform:billing:read"); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	start, end, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	after, correctionAfter := uuid.Nil, uuid.Nil
	var afterSequence, correctionSequence int64
	// Each collection has its own UUID cursor. The persisted sequence is
	// assigned under the period lock, so later commits cannot fall behind it.
	for _, cursor := range []struct {
		param    string
		id       *uuid.UUID
		sequence *int64
		query    string
	}{
		{"after", &after, &afterSequence, `SELECT e.accounting_sequence FROM billing_export_event e
            JOIN billing_export_allocation a ON a.id=e.allocation_id
            WHERE e.id=$4 AND a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3`},
		{"after_correction", &correctionAfter, &correctionSequence, `SELECT accounting_sequence FROM billing_export_correction
            WHERE id=$4 AND team_id=$1 AND period_start=$2 AND period_end=$3`},
	} {
		if raw := c.Query(cursor.param); raw != "" {
			*cursor.id, err = uuid.Parse(raw)
			if err != nil {
				respondErrorMsg(c, "bad_request", "invalid accounting cursor", http.StatusBadRequest)
				return
			}
			err = h.Pool.QueryRow(c.Request.Context(), cursor.query, team, start, end, *cursor.id).Scan(cursor.sequence)
			if errors.Is(err, pgx.ErrNoRows) {
				respondErrorMsg(c, "bad_request", "accounting cursor does not belong to this period", http.StatusBadRequest)
				return
			}
			if err != nil {
				respondError(c, ErrInternal)
				return
			}
		}
	}
	// JSON aggregation preserves numeric payloads as text and keeps provider
	// observations separate from event-derived submission accounting.
	var result []byte
	err = h.Pool.QueryRow(c.Request.Context(), `SELECT jsonb_build_object(
        'events',COALESCE((SELECT jsonb_agg(to_jsonb(e)-'lease_token'-'lease_until' ORDER BY e.accounting_sequence)
            FROM (SELECT e.* FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
            WHERE a.team_id=$1 AND a.period_start=$2 AND a.period_end=$3 AND e.accounting_sequence>$4 ORDER BY e.accounting_sequence LIMIT 500) e),'[]'::jsonb),
        'corrections',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.accounting_sequence) FROM
            (SELECT * FROM billing_export_correction WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND accounting_sequence>$5 ORDER BY accounting_sequence LIMIT 500) c),'[]'::jsonb),
        'local_measurement',(SELECT to_jsonb(u) FROM billing_export_usage u WHERE u.team_id=$1 AND u.period_start=$2 AND u.period_end=$3),
        'worker',(SELECT jsonb_build_object('next_run_at',w.next_run_at,'last_error',w.last_error,'seed_complete',w.seed_complete)
            FROM billing_export_work w WHERE w.team_id=$1),
        'observations',COALESCE((SELECT jsonb_agg(to_jsonb(o)) FROM billing_export_observation o
            WHERE o.team_id=$1 AND o.period_start=$2 AND o.period_end=$3),'[]'::jsonb))`, team, start, end, afterSequence, correctionSequence).Scan(&result)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json", result)
}

// MeasureBillingCorrection is an explicit, bounded operator read. Ordinary ticks
// continue to consume hourly aggregates without rescanning closed raw history.
func (h *Handlers) MeasureBillingCorrection(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingWritePermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	start, end, err := parseBillingPeriodID(c.Param("period_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	var input struct {
		Resource string `json:"resource"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
	if err = c.ShouldBindJSON(&input); err != nil {
		respondErrorMsg(c, "bad_request", "resource is required", http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	result, err := (billing.ExportStore{Pool: h.Pool}).MeasureCorrection(ctx, billing.ExportPeriod{TeamID: team, Start: start, End: end}, input.Resource)
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *Handlers) ApplyBillingCorrection(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("correction_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid correction id", http.StatusBadRequest)
		return
	}
	var input struct {
		Action   string `json:"action"`
		Evidence string `json:"evidence"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
	if err = c.ShouldBindJSON(&input); err != nil {
		respondErrorMsg(c, "bad_request", "reviewed action and evidence are required", http.StatusBadRequest)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	var p billing.ExportPeriod
	var resource string
	var needsAllocation bool
	if err = h.Pool.QueryRow(ctx, `SELECT team_id,period_start,period_end,resource_type,target_quantity>reserved_quantity FROM billing_export_correction WHERE id=$1`, id).Scan(&p.TeamID, &p.Start, &p.End, &resource, &needsAllocation); err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	account, err := h.DB.GetTeamBillingAccount(ctx, p.TeamID)
	if err != nil || account.StripeCustomerID == nil {
		respondErrorMsg(c, "conflict", "billing customer is required", http.StatusConflict)
		return
	}
	storage, err := h.billingStorageBillingEnabled(ctx, p.TeamID)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	eventName := ""
	for _, state := range h.billingResourceStates(storage) {
		if billingExportResourceType(state.ResourceKey) == resource && (!needsAllocation || state.Billable && state.CheckoutEnabled) {
			eventName = state.StripeEventName
		}
	}
	// Reviewed recovery keeps the period's meter even after configuration removal.
	eventName, err = (billing.ExportStore{Pool: h.Pool}).MeterEventName(ctx, p, resource, eventName)
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	if eventName == "" {
		respondErrorMsg(c, "conflict", "resource is not enabled for billing", http.StatusConflict)
		return
	}
	through := h.nowUTC().Truncate(time.Hour)
	if through.After(p.End) {
		through = p.End
	}
	first, last := meterObservationWindow(p.Start, through)
	if !last.After(first) {
		respondErrorMsg(c, "conflict", "measurement window is incomplete", http.StatusConflict)
		return
	}
	err = (billing.ExportStore{Pool: h.Pool}).ApplyCorrection(ctx, id, actor, input.Action, input.Evidence, billing.ExportPayload{
		CustomerID: *account.StripeCustomerID, EventName: eventName, Timestamp: last.Add(-time.Second).Unix(),
	})
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
		return
	}
	c.Status(http.StatusNoContent)
}
