package api

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

type StripeStorageSubscriptionParams struct {
	SubscriptionID, CustomerID, PriceID, EventName, UnitAmountDecimal string
	Reconcile, AllowInactive                                          bool
}

type storageSubscriptionClient interface {
	EnsureStorageSubscription(context.Context, StripeStorageSubscriptionParams) error
}

// storageReadinessError means Stripe was not contacted with a meter event.
// A hold does not start a retry window for a never-submitted event; any
// uncertainty from earlier submissions remains authoritative.
type storageReadinessError struct{ err error }

func (e *storageReadinessError) Error() string { return e.err.Error() }
func (e *storageReadinessError) Unwrap() error { return e.err }

type storagePrice struct {
	ID                string `json:"id"`
	Product           string `json:"product"`
	Currency          string `json:"currency"`
	Active            bool   `json:"active"`
	BillingScheme     string `json:"billing_scheme"`
	UnitAmountDecimal string `json:"unit_amount_decimal"`
	TransformQuantity any    `json:"transform_quantity"`
	Recurring         struct {
		UsageType     string `json:"usage_type"`
		Interval      string `json:"interval"`
		IntervalCount int    `json:"interval_count"`
		Meter         string `json:"meter"`
	} `json:"recurring"`
}

type storageSubscription struct {
	ID                 string `json:"id"`
	Customer           string `json:"customer"`
	Status             string `json:"status"`
	BillingCycleAnchor int64  `json:"billing_cycle_anchor"`
}

func (c *stripeHTTPClient) EnsureStorageSubscription(ctx context.Context, p StripeStorageSubscriptionParams) error {
	var price storagePrice
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(p.PriceID), nil, &price, ""); err != nil {
		return err
	}
	amount, ok := new(big.Rat).SetString(price.UnitAmountDecimal)
	expected, expectedOK := new(big.Rat).SetString(p.UnitAmountDecimal)
	if price.ID != p.PriceID || price.Product == "" || !price.Active || price.Currency != "usd" || price.BillingScheme != "per_unit" || price.TransformQuantity != nil || !ok || !expectedOK || amount.Cmp(expected) != 0 || price.Recurring.UsageType != "metered" || price.Recurring.Meter == "" || price.Recurring.Interval != "month" || price.Recurring.IntervalCount != 1 {
		return fmt.Errorf("storage price %s must match the canonical USD/GiB-hour rate and monthly metered configuration", p.PriceID)
	}
	var meter struct {
		EventName          string `json:"event_name"`
		Status             string `json:"status"`
		DefaultAggregation struct {
			Formula string `json:"formula"`
		} `json:"default_aggregation"`
		CustomerMapping struct {
			Type string `json:"type"`
			Key  string `json:"event_payload_key"`
		} `json:"customer_mapping"`
		ValueSettings struct {
			Key string `json:"event_payload_key"`
		} `json:"value_settings"`
		EventTimeWindow *string `json:"event_time_window"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/meters/"+url.PathEscape(price.Recurring.Meter), nil, &meter, ""); err != nil {
		return err
	}
	if meter.Status != "active" || meter.EventName != p.EventName || meter.DefaultAggregation.Formula != "sum" || meter.EventTimeWindow != nil || meter.CustomerMapping.Type != "by_id" || meter.CustomerMapping.Key != "stripe_customer_id" || meter.ValueSettings.Key != "value" {
		return fmt.Errorf("storage meter must use active sum aggregation and the configured event/customer/value mapping")
	}
	if p.SubscriptionID == "" {
		return nil
	}
	readSubscription := func() (storageSubscription, error) {
		var sub storageSubscription
		err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(p.SubscriptionID), nil, &sub, "")
		if err == nil && (sub.ID != p.SubscriptionID || sub.Customer != p.CustomerID || !p.AllowInactive && sub.Status != "active" && sub.Status != "trialing" && sub.Status != "past_due") {
			err = fmt.Errorf("current subscription/customer association is not active; reconcile billing account first")
		}
		return sub, err
	}
	before, err := readSubscription()
	if err != nil {
		return err
	}
	count, err := c.storageSubscriptionItems(ctx, p.SubscriptionID, price)
	if err != nil {
		return err
	}
	if count == 0 && p.Reconcile {
		form := url.Values{"subscription": {p.SubscriptionID}, "price": {p.PriceID}, "proration_behavior": {"none"}}
		// The account row lock serializes writers beyond Stripe's idempotency
		// retention; a fresh item inventory also handles an accepted lost reply.
		key := "storage-item:" + p.SubscriptionID + ":" + p.PriceID
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscription_items", form, nil, key); err != nil {
			return err
		}
		count, err = c.storageSubscriptionItems(ctx, p.SubscriptionID, price)
		if err != nil {
			return err
		}
	}
	if count != 1 {
		return fmt.Errorf("subscription %s has %d storage items; reconcile exactly one %s item before activation/export", p.SubscriptionID, count, p.PriceID)
	}
	after, err := readSubscription()
	if err != nil {
		return err
	}
	if after.BillingCycleAnchor != before.BillingCycleAnchor {
		return fmt.Errorf("subscription billing anchor changed during storage reconciliation; operator review required")
	}
	return c.checkStorageCreditScopes(ctx, p.CustomerID, p.PriceID)
}

func (c *stripeHTTPClient) storageSubscriptionItems(ctx context.Context, subID string, wanted storagePrice) (int, error) {
	count := 0
	after := ""
	for page := 0; page < 10; page++ {
		query := url.Values{"subscription": {subID}, "limit": {"100"}}
		if after != "" {
			query.Set("starting_after", after)
		}
		var result struct {
			Data []struct {
				ID    string       `json:"id"`
				Price storagePrice `json:"price"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/subscription_items?"+query.Encode(), nil, &result, ""); err != nil {
			return 0, err
		}
		for _, item := range result.Data {
			if item.Price.Recurring.Interval != wanted.Recurring.Interval || item.Price.Recurring.IntervalCount != wanted.Recurring.IntervalCount {
				return 0, fmt.Errorf("subscription billing interval differs from storage price; operator review required")
			}
			if item.Price.ID == wanted.ID {
				count++
			} else if item.Price.Recurring.Meter == wanted.Recurring.Meter {
				return 0, fmt.Errorf("subscription has conflicting storage price %s; reconcile it before activation", item.Price.ID)
			}
		}
		if !result.HasMore {
			return count, nil
		}
		if len(result.Data) == 0 || result.Data[len(result.Data)-1].ID == after {
			return 0, fmt.Errorf("invalid subscription item pagination")
		}
		after = result.Data[len(result.Data)-1].ID
	}
	return 0, fmt.Errorf("subscription item inventory exceeds 1000 items; operator review required")
}

func (c *stripeHTTPClient) checkStorageCreditScopes(ctx context.Context, customer, price string) error {
	after := ""
	for page := 0; page < 10; page++ {
		query := url.Values{"customer": {customer}, "limit": {"100"}}
		if after != "" {
			query.Set("starting_after", after)
		}
		var result struct {
			Data []struct {
				ID            string `json:"id"`
				VoidedAt      int64  `json:"voided_at"`
				ExpiresAt     int64  `json:"expires_at"`
				Applicability struct {
					Scope struct {
						PriceType string `json:"price_type"`
						Prices    []struct {
							ID string `json:"id"`
						} `json:"prices"`
					} `json:"scope"`
				} `json:"applicability_config"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+query.Encode(), nil, &result, ""); err != nil {
			return err
		}
		for _, grant := range result.Data {
			if grant.VoidedAt != 0 || grant.ExpiresAt != 0 && grant.ExpiresAt <= time.Now().Unix() {
				continue
			}
			if grant.Applicability.Scope.PriceType == "metered" {
				continue
			}
			included := false
			for _, candidate := range grant.Applicability.Scope.Prices {
				included = included || candidate.ID == price
			}
			if !included {
				return fmt.Errorf("credit grant %s does not include storage price %s; reconcile its price scope", grant.ID, price)
			}
		}
		if !result.HasMore {
			return nil
		}
		if len(result.Data) == 0 || result.Data[len(result.Data)-1].ID == after {
			return fmt.Errorf("invalid credit grant pagination")
		}
		after = result.Data[len(result.Data)-1].ID
	}
	return fmt.Errorf("credit grant inventory exceeds 1000 grants; operator review required")
}

func (h *Handlers) storageResource() (config.BillingResourceConfig, error) {
	for _, r := range h.billingConfiguredResources() {
		if r.ResourceKey == "storage_gib" && r.SubscriptionIncluded() && strings.TrimSpace(r.StripePriceID) != "" && r.StripeEventName == "storage_gib_hours" {
			return r, nil
		}
	}
	return config.BillingResourceConfig{}, fmt.Errorf("configure subscription_enabled storage_gib with its metered Stripe price and storage_gib_hours event")
}

func (h *Handlers) storageSubscriptionParams(ctx context.Context, q *db.Queries, account db.GetTeamBillingAccountRow, reconcile bool) (StripeStorageSubscriptionParams, error) {
	r, err := h.storageResource()
	if err != nil {
		return StripeStorageSubscriptionParams{}, err
	}
	rates, err := q.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{TeamID: account.TeamID, EffectiveAt: h.nowUTC()})
	if err != nil {
		return StripeStorageSubscriptionParams{}, err
	}
	amount := ""
	for _, rate := range rates {
		if rate.Resource == "storage_gib" && rate.Unit == "second" {
			value, err := rate.PriceUsd.Value()
			if err != nil {
				return StripeStorageSubscriptionParams{}, err
			}
			exact, ok := new(big.Rat).SetString(fmt.Sprint(value))
			if !ok {
				return StripeStorageSubscriptionParams{}, fmt.Errorf("invalid storage price")
			}
			amount = new(big.Rat).Mul(exact, big.NewRat(360000, 1)).FloatString(12)
		}
	}
	if amount == "" {
		return StripeStorageSubscriptionParams{}, fmt.Errorf("canonical storage pricing unavailable")
	}
	return StripeStorageSubscriptionParams{SubscriptionID: derefString(account.StripeSubscriptionID), CustomerID: derefString(account.StripeCustomerID), PriceID: r.StripePriceID, EventName: r.StripeEventName, UnitAmountDecimal: amount, Reconcile: reconcile}, nil
}

// Storage operations lock the current account association across provider I/O.
// This is an operator/export path, never a sandbox lifecycle path.
func (h *Handlers) withStorageSubscription(ctx context.Context, team uuid.UUID, reconcile, allowInactive bool, action func(pgx.Tx, StripeStorageSubscriptionParams) error) error {
	if h.Pool == nil || h.DB == nil {
		return fmt.Errorf("billing transactions are not configured")
	}
	client, ok := h.Stripe.(storageSubscriptionClient)
	if !ok {
		return fmt.Errorf("Stripe storage subscription verification is not configured")
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team); err != nil {
		return err
	}
	var locked uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, team).Scan(&locked); err != nil {
		return err
	}
	q := h.DB.WithTx(tx)
	account, err := q.GetTeamBillingAccount(ctx, team)
	if err != nil {
		return err
	}
	if account.StripeSubscriptionID == nil && account.TrialEndedAt.Valid {
		return fmt.Errorf("paid team has no current subscription; reconcile billing account first")
	}
	request, err := h.storageSubscriptionParams(ctx, q, account, reconcile)
	if err != nil {
		return err
	}
	request.AllowInactive = allowInactive
	if err = client.EnsureStorageSubscription(ctx, request); err != nil {
		return err
	}
	if err = action(tx, request); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) ReconcileStorageBilling(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingWritePermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	var input struct {
		Mode           string    `json:"mode"`
		ApprovedCutoff time.Time `json:"approved_cutoff"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err = c.ShouldBindJSON(&input); err != nil || input.Mode != "reconcile" && input.Mode != "activate" && input.Mode != "verify" || input.Mode == "activate" && input.ApprovedCutoff.IsZero() {
		respondErrorMsg(c, "bad_request", "mode must be reconcile, verify, or activate; activate requires approved_cutoff", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	var effective pgtype.Timestamptz
	err = h.withStorageSubscription(ctx, team, input.Mode == "reconcile", false, func(tx pgx.Tx, p StripeStorageSubscriptionParams) error {
		if input.Mode == "activate" {
			var enabled bool
			if err := tx.QueryRow(ctx, `SELECT feature_enabled('billing_storage_billing_enabled',$1) OR storage_billing_activated($1)`, team).Scan(&enabled); err != nil {
				return err
			}
			if !enabled {
				return fmt.Errorf("enable the team's storage activation flag after rollout approval")
			}
			_, err := tx.Exec(ctx, `INSERT INTO team_storage_billing_activation(team_id,effective_at,approved_cutoff,verified_subscription_id,verified_price_id)
                VALUES($1,GREATEST(clock_timestamp(),$2),$2,NULLIF($3,''),$4) ON CONFLICT(team_id) DO NOTHING`, team, input.ApprovedCutoff, p.SubscriptionID, p.PriceID)
			if err != nil {
				return err
			}
			// Activation runs off the lifecycle path. Publish the cutoff-aware
			// verdict in the same transaction, including on an activation retry.
			if err := db.New(tx).RefreshTeamTrialEligibility(ctx, team); err != nil {
				return err
			}
			// Recompute only mutable export caches that overlap the one-time
			// boundary, and wake their hourly measurements. This closes the
			// activation race with mixed-version workers without touching frozen
			// history or reservation identities.
			_, err = tx.Exec(ctx, `
                UPDATE billing_export_measurement m SET storage_mib_seconds = billable_storage_mib_seconds(m.team_id,GREATEST(m.hour_start,m.period_start),LEAST(m.hour_start+interval '1 hour',m.period_end))
                WHERE m.team_id=$1 AND m.hour_start+interval '1 hour' > (SELECT effective_at FROM team_storage_billing_activation WHERE team_id=$1)
                  AND NOT EXISTS (SELECT 1 FROM team_billing_period bp WHERE bp.team_id=m.team_id AND bp.period_start=m.period_start AND bp.period_end=m.period_end
                    AND (bp.finalized_at IS NOT NULL OR bp.exported_at IS NOT NULL OR bp.status IN ('exporting','exported','finalized')))`, team)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `
                UPDATE billing_export_usage u SET storage_mib_seconds = u.storage_mib_seconds
                WHERE u.team_id=$1 AND u.period_end > (SELECT effective_at FROM team_storage_billing_activation WHERE team_id=$1)
                  AND NOT EXISTS (SELECT 1 FROM team_billing_period bp WHERE bp.team_id=u.team_id AND bp.period_start=u.period_start AND bp.period_end=u.period_end
                    AND (bp.finalized_at IS NOT NULL OR bp.exported_at IS NOT NULL OR bp.status IN ('exporting','exported','finalized')))`, team)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `
                UPDATE billing_export_measurement_queue q SET pending=true
                WHERE q.team_id=$1 AND q.hour_start+interval '1 hour' > (SELECT effective_at FROM team_storage_billing_activation WHERE team_id=$1)`, team)
			if err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT (SELECT effective_at FROM team_storage_billing_activation WHERE team_id=$1)`, team).Scan(&effective)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = fmt.Errorf("team has no billing account")
		}
		respondErrorMsg(c, "storage_billing_not_ready", err.Error(), http.StatusConflict)
		return
	}
	var at *time.Time
	if effective.Valid {
		at = &effective.Time
	}
	c.JSON(http.StatusOK, gin.H{"ready": true, "effective_at": at})
}

func (h *Handlers) reportBillingMeterEvent(ctx context.Context, team uuid.UUID, resource string, createdAt, measuredThrough time.Time, frozen bool, params StripeReportMeterEventParams) error {
	if resource != "storage" {
		return h.Stripe.ReportMeterEvent(ctx, params)
	}
	calledProvider := false
	err := h.withStorageSubscription(ctx, team, false, frozen, func(tx pgx.Tx, p StripeStorageSubscriptionParams) error {
		if p.SubscriptionID == "" || p.CustomerID != params.CustomerID || p.EventName != params.EventName {
			return fmt.Errorf("storage export does not match the current subscription/customer/meter; operator reconciliation required")
		}
		var eligible bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_storage_billing_activation WHERE team_id=$1 AND effective_at<=$2::timestamptz AND effective_at<$3::timestamptz AND effective_at<=clock_timestamp())`, team, createdAt, measuredThrough).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return fmt.Errorf("storage event predates prospective activation; preserve it for operator review")
		}
		calledProvider = true
		return h.Stripe.ReportMeterEvent(ctx, params)
	})
	if err != nil && !calledProvider {
		return &storageReadinessError{err: err}
	}
	return err
}

func (h *Handlers) billingStorageBillingEnabledForWindow(ctx context.Context, team uuid.UUID, end time.Time) (bool, error) {
	return h.DB.IsStorageBillingActivatedForWindow(ctx, db.IsStorageBillingActivatedForWindowParams{TeamID: team, PeriodEnd: end})
}
