package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	publicPricingPlanKey       = "payg"
	publicPricingCacheControl  = "public, max-age=300, s-maxage=300"
	privatePricingCacheControl = "private, max-age=60"
)

type billingPricingRateResponse struct {
	ResourceKey    string    `json:"resource_key"`
	Resource       string    `json:"resource"`
	DisplayName    string    `json:"display_name"`
	SortOrder      int       `json:"sort_order"`
	Unit           string    `json:"unit"`
	DisplayUnit    string    `json:"display_unit"`
	PriceUSD       float64   `json:"price_usd"`
	PriceUSDHourly float64   `json:"price_usd_hourly"`
	EffectiveFrom  time.Time `json:"effective_from"`
	Tracked        bool      `json:"tracked"`
	Billable       bool      `json:"billable"`
}

type billingPricingResponse struct {
	PlanKey  string                       `json:"plan_key"`
	PlanName string                       `json:"plan_name"`
	Currency string                       `json:"currency"`
	Rates    []billingPricingRateResponse `json:"rates"`
}

type billingSummaryResponse struct {
	Mode                     string                            `json:"mode"`
	BillingMode              string                            `json:"billing_mode"`
	Permissions              billingSummaryPermissions         `json:"permissions"`
	CheckoutAvailable        bool                              `json:"checkout_available"`
	PortalAvailable          bool                              `json:"portal_available"`
	PaymentSetupRequired     bool                              `json:"payment_setup_required"`
	CurrentChargesUSD        float64                           `json:"current_charges_usd"`
	CreditsAppliedUSD        float64                           `json:"credits_applied_usd"`
	CreditsRemainingUSD      float64                           `json:"credits_remaining_usd"`
	ExpectedInvoiceAmountUSD float64                           `json:"expected_invoice_amount_usd"`
	CostBreakdownUSD         billingSummaryCostBreakdown       `json:"cost_breakdown_usd"`
	Resources                []billingSummaryResource          `json:"resources"`
	ResourcesByKey           map[string]billingSummaryResource `json:"resources_by_key,omitempty"`
	BillingPeriod            billingSummaryPeriod              `json:"billing_period"`
	PricingTier              billingSummaryPricingTier         `json:"pricing_tier"`
	CalculatedAt             time.Time                         `json:"calculated_at"`
}

type billingSummaryCostBreakdown struct {
	Compute float64 `json:"compute"`
	Memory  float64 `json:"memory"`
	Storage float64 `json:"storage"`
}

type billingSummaryPermissions struct {
	CanView   bool `json:"can_view"`
	CanManage bool `json:"can_manage"`
}

type billingSummaryResource struct {
	ResourceKey string  `json:"resource_key"`
	Resource    string  `json:"resource"`
	DisplayName string  `json:"display_name"`
	SortOrder   int     `json:"sort_order"`
	Unit        string  `json:"unit"`
	DisplayUnit string  `json:"display_unit"`
	Usage       float64 `json:"usage"`
	Tracked     bool    `json:"tracked"`
	Billable    bool    `json:"billable"`
	ChargeUSD   float64 `json:"charge_usd"`
}

type billingUsageResource struct {
	ResourceKey string  `json:"resource_key"`
	Resource    string  `json:"resource"`
	DisplayName string  `json:"display_name"`
	SortOrder   int     `json:"sort_order"`
	Unit        string  `json:"unit"`
	DisplayUnit string  `json:"display_unit"`
	Usage       float64 `json:"usage"`
	Tracked     bool    `json:"tracked"`
	Billable    bool    `json:"billable"`
}

type billingSummaryPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type billingSummaryPricingTier struct {
	PlanKey  string `json:"plan_key"`
	PlanName string `json:"plan_name"`
	Currency string `json:"currency"`
}

func (h *Handlers) GetPublicBillingPricing(c *gin.Context) {
	h.writeBillingPricing(c, publicPricingPlanKey, "public", publicPricingCacheControl, h.billingResourceStates(false))
}

func (h *Handlers) GetBillingPricing(c *gin.Context) {
	teamID, ok := h.requireBillingRead(c)
	if !ok {
		return
	}

	rates, err := h.DB.ListActivePricingRatesForTeamCurrent(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB ListActivePricingRatesForTeamCurrent failed")
		respondError(c, ErrInternal)
		return
	}

	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}

	h.writeBillingPricingRates(c, pricingRatesFromTeamCurrentRows(rates), teamID.String(), privatePricingCacheControl, h.billingResourceStates(storageBillingEnabled))
}

func (h *Handlers) GetBillingSummary(c *gin.Context) {
	teamID, ok := h.requireBillingRead(c)
	if !ok {
		return
	}
	canManageBilling := false
	if actorID := actorIDFromContext(c); actorID != nil {
		authzSvc := h.authzService()
		if authzSvc != nil {
			allowed, err := authzSvc.CanTeam(c.Request.Context(), *actorID, teamID, "billing:write")
			if err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", actorID.String()).Msg("billing summary manage permission check failed")
				respondError(c, ErrInternal)
				return
			}
			canManageBilling = allowed
		}
	}

	now := time.Now().UTC()
	periodStart, periodEnd := billing.CurrentBillingPeriod(now)
	account, accountErr := h.DB.GetTeamBillingAccount(c.Request.Context(), teamID)
	if accountErr != nil && !errors.Is(accountErr, pgx.ErrNoRows) {
		log.Error().Err(accountErr).Str("team_id", teamID.String()).Msg("load billing account failed")
		respondError(c, ErrInternal)
		return
	}
	if accountErr == nil && account.CommercialBillingAnchor.Valid {
		if start, end, anchored := billing.AnniversaryPeriod(account.CommercialBillingAnchor.Time, now); anchored {
			periodStart, periodEnd = start, end
		}
	}
	period, err := h.DB.GetActiveTeamBillingPeriod(c.Request.Context(), teamID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetActiveTeamBillingPeriod failed")
			respondError(c, ErrInternal)
			return
		}
	} else if !(accountErr == nil && account.CommercialBillingAnchor.Valid) {
		periodStart = period.PeriodStart
		periodEnd = period.PeriodEnd
	}

	var (
		usage         db.GetTeamBillingUsageRow
		pricingRows   []db.ListActivePricingRatesForTeamCurrentRow
		creditBalance pgtype.Numeric
	)
	g, ctx := errgroup.WithContext(c.Request.Context())
	g.Go(func() error {
		var err error
		usage, err = h.DB.GetTeamBillingUsage(ctx, db.GetTeamBillingUsageParams{
			TeamID:      teamID,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		})
		if err != nil {
			return fmt.Errorf("get team billing usage: %w", err)
		}
		return nil
	})

	// Phase 1 applies the team's currently active pricing rates to the whole
	// current billing period. This assumes there are no mid-period pricing tier
	// or rate changes; period-aware pricing should replace this before invoices.
	g.Go(func() error {
		var err error
		pricingRows, err = h.DB.ListActivePricingRatesForTeamCurrent(ctx, teamID)
		if err != nil {
			return fmt.Errorf("list active pricing rates for team current: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		creditBalance, err = h.DB.GetTeamCreditBalance(ctx, teamID)
		if err != nil {
			return fmt.Errorf("get team credit balance: %w", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing summary dependency fetch failed")
		respondError(c, ErrInternal)
		return
	}

	storageBillingEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read storage billing feature flag failed")
		respondError(c, ErrInternal)
		return
	}
	mode, err := h.billingExportMode(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read billing mode failed")
		respondError(c, ErrInternal)
		return
	}

	resourceStates := h.billingResourceStates(storageBillingEnabled)
	pricingCatalog, ok := h.billingRateCatalog(pricingRatesFromTeamCurrentRows(pricingRows), teamID.String(), resourceStates)
	if !ok {
		respondPricingUnavailable(c)
		return
	}

	vcpuSeconds, err := numericFloat64(usage.VcpuSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert vcpu usage failed")
		respondError(c, ErrInternal)
		return
	}
	memoryGibSeconds, err := numericFloat64(usage.MemoryGibSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert memory usage failed")
		respondError(c, ErrInternal)
		return
	}
	storageGibSeconds, err := numericFloat64(usage.StorageGibSeconds)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert storage usage failed")
		respondError(c, ErrInternal)
		return
	}

	vcpuRate, err := numericFloat64(pricingCatalog.RateByResource["vcpu"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert vcpu price failed")
		respondError(c, ErrInternal)
		return
	}
	memoryRate, err := numericFloat64(pricingCatalog.RateByResource["memory_gib"].PriceUsd)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert memory price failed")
		respondError(c, ErrInternal)
		return
	}
	storageRate := 0.0
	if storageBillingEnabled {
		storageRate, err = numericFloat64(pricingCatalog.RateByResource["storage_gib"].PriceUsd)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert storage price failed")
			respondError(c, ErrInternal)
			return
		}
	}

	creditsAvailable, err := numericFloat64(creditBalance)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("convert credit balance failed")
		respondError(c, ErrInternal)
		return
	}
	hasEstablishedSubscription := billingAccountHasEstablishedSubscription(account)
	checkoutAvailable := false
	if canManageBilling && mode == billingModeLive && h.Stripe != nil && !hasEstablishedSubscription {
		if _, err := billingCheckoutPriceIDs(resourceStates); err == nil {
			checkoutAvailable = true
		}
	}
	charges := billing.CalculateSummaryCharges(
		vcpuSeconds,
		memoryGibSeconds,
		storageGibSeconds,
		vcpuRate,
		memoryRate,
		storageRate,
		creditsAvailable,
		storageBillingEnabled,
	)
	paymentSetupRequired := mode == billingModeLive &&
		!hasEstablishedSubscription &&
		charges.CreditsRemainingUSD <= 0
	summaryResources := billingSummaryResourcesFromState(resourceStates, vcpuSeconds, memoryGibSeconds, storageGibSeconds, charges)

	setPrivateBillingCacheHeaders(c)
	c.JSON(http.StatusOK, billingSummaryResponse{
		Mode:                     mode,
		BillingMode:              mode,
		Permissions:              billingSummaryPermissions{CanView: true, CanManage: canManageBilling},
		CheckoutAvailable:        checkoutAvailable,
		PortalAvailable:          canManageBilling && mode == billingModeLive && h.Stripe != nil && hasEstablishedSubscription,
		PaymentSetupRequired:     paymentSetupRequired,
		CurrentChargesUSD:        charges.CurrentChargesUSD,
		CreditsAppliedUSD:        charges.CreditsAppliedUSD,
		CreditsRemainingUSD:      charges.CreditsRemainingUSD,
		ExpectedInvoiceAmountUSD: charges.ExpectedInvoiceAmountUSD,
		CostBreakdownUSD: billingSummaryCostBreakdown{
			Compute: charges.Breakdown.ComputeUSD,
			Memory:  charges.Breakdown.MemoryUSD,
			Storage: charges.Breakdown.StorageUSD,
		},
		Resources:      summaryResources,
		ResourcesByKey: billingSummaryResourcesByKey(summaryResources),
		BillingPeriod:  billingSummaryPeriod{Start: periodStart, End: periodEnd},
		PricingTier: billingSummaryPricingTier{
			PlanKey:  pricingCatalog.PlanKey,
			PlanName: pricingCatalog.PlanName,
			Currency: pricingCatalog.Currency,
		},
		CalculatedAt: now,
	})
}

type billingUsageSeriesResource struct {
	Usage    float64 `json:"usage"`
	CostUSD  float64 `json:"cost_usd"`
	Tracked  bool    `json:"tracked"`
	Billable bool    `json:"billable"`
}
type billingUsageSeriesBucket struct {
	Start          time.Time                  `json:"start"`
	End            time.Time                  `json:"end"`
	CPU            billingUsageSeriesResource `json:"cpu"`
	Memory         billingUsageSeriesResource `json:"memory"`
	Storage        billingUsageSeriesResource `json:"storage"`
	BilledTotalUSD float64                    `json:"billed_total_usd"`
}

func (h *Handlers) GetBillingUsageSeries(c *gin.Context) {
	teamID, ok := h.requireBillingRead(c)
	if !ok {
		return
	}
	start, err := time.Parse(time.RFC3339Nano, c.Query("start"))
	if err != nil {
		respondErrorMsg(c, "invalid_request", "invalid start timestamp", http.StatusBadRequest)
		return
	}
	end, err := time.Parse(time.RFC3339Nano, c.Query("end"))
	if err != nil {
		respondErrorMsg(c, "invalid_request", "invalid end timestamp", http.StatusBadRequest)
		return
	}
	timezone, err := billingUsageSeriesTimezone(c.Query("timezone"))
	if err != nil {
		if strings.TrimSpace(c.Query("timezone")) == "" {
			respondErrorMsg(c, "invalid_request", "timezone is required", http.StatusBadRequest)
		} else {
			respondErrorMsg(c, "invalid_request", "invalid timezone", http.StatusBadRequest)
		}
		return
	}
	loc := timezone
	buckets, err := billing.UsageSeriesBuckets(start, end, c.Query("granularity"), loc)
	if err != nil {
		respondErrorMsg(c, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}
	rates, err := h.DB.ListActivePricingRatesForTeamCurrent(c.Request.Context(), teamID)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	storageEnabled, err := h.billingStorageBillingEnabled(c.Request.Context(), teamID)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	states := h.billingResourceStates(storageEnabled)
	catalog, ok := h.billingRateCatalog(pricingRatesFromTeamCurrentRows(rates), teamID.String(), states)
	if !ok {
		respondPricingUnavailable(c)
		return
	}
	rate := func(key string) float64 {
		v, e := numericFloat64(catalog.RateByResource[key].PriceUsd)
		if e != nil {
			return 0
		}
		return v
	}
	vcpuRate, memRate, storageRate := rate("vcpu"), rate("memory_gib"), rate("storage_gib")
	resourceState := make(map[string]billingResourceState, len(states))
	for _, state := range states {
		resourceState[state.ResourceKey] = state
	}
	result := make([]billingUsageSeriesBucket, 0, len(buckets))
	ctx := c.Request.Context()
	starts, ends := make([]time.Time, len(buckets)), make([]time.Time, len(buckets))
	for i, b := range buckets {
		starts[i], ends[i] = b.Start, b.End
	}
	// Aggregate all buckets in one bounded set-oriented query; do not invoke the
	// full-team usage scan independently for each bucket.
	usageRows, e := h.DB.GetTeamBillingUsageSeries(ctx, db.GetTeamBillingUsageSeriesParams{TeamID: teamID, PeriodStarts: starts, PeriodEnds: ends})
	if e != nil || len(usageRows) != len(buckets) {
		respondError(c, ErrInternal)
		return
	}
	for i, b := range buckets {
		u := usageRows[i]
		cpu, _ := numericFloat64(u.VcpuSeconds)
		mem, _ := numericFloat64(u.MemoryGibSeconds)
		storage, _ := numericFloat64(u.StorageGibSeconds)
		cpuState, cpuOK := resourceState["vcpu"]
		memoryState, memoryOK := resourceState["memory_gib"]
		storageState, storageOK := resourceState["storage_gib"]
		if !cpuOK || !memoryOK || !storageOK {
			respondError(c, ErrInternal)
			return
		}
		cc, mc, sc := cpu*vcpuRate, mem*memRate, storage*storageRate
		// Resource costs remain informational even when a resource is tracked but
		// excluded from billing. Apply billability only to the billed total.
		billedTotal := 0.0
		if cpuState.Billable {
			billedTotal += cc
		}
		if memoryState.Billable {
			billedTotal += mc
		}
		if storageState.Billable {
			billedTotal += sc
		}
		result = append(result, billingUsageSeriesBucket{Start: b.Start, End: b.End, CPU: billingUsageSeriesResource{cpu, cc, cpuState.Tracked, cpuState.Billable}, Memory: billingUsageSeriesResource{mem, mc, memoryState.Tracked, memoryState.Billable}, Storage: billingUsageSeriesResource{storage, sc, storageState.Tracked, storageState.Billable}, BilledTotalUSD: billedTotal})
	}
	setPrivateBillingCacheHeaders(c)
	c.JSON(http.StatusOK, gin.H{"start": start, "end": end, "granularity": c.Query("granularity"), "timezone": c.Query("timezone"), "buckets": result})
}

func billingUsageSeriesTimezone(raw string) (*time.Location, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("timezone is required")
	}
	// Local is a process-dependent alias, not an IANA timezone name. Accepting
	// it would make bucket boundaries vary with the server's TZ configuration.
	if raw == "Local" {
		return nil, errors.New("invalid timezone")
	}
	return time.LoadLocation(raw)
}

func (h *Handlers) requireBillingRead(c *gin.Context) (uuid.UUID, bool) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, false
	}
	actorID := actorIDFromContext(c)
	if actorID == nil {
		respondError(c, ErrUnauthorized)
		return uuid.Nil, false
	}
	authzSvc := h.authzService()
	if authzSvc == nil {
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	allowed, err := authzSvc.CanTeam(c.Request.Context(), *actorID, teamID, "billing:read")
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Str("user_id", actorID.String()).Msg("RBAC billing read check failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if !allowed {
		respondError(c, ErrForbidden)
		return uuid.Nil, false
	}
	enabled, err := h.DB.IsFeatureEnabledForTeam(c.Request.Context(), db.IsFeatureEnabledForTeamParams{
		Key:    "tenant_usage_dashboard",
		TeamID: pgtype.UUID{Bytes: teamID, Valid: true},
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB IsFeatureEnabledForTeam failed")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	if !enabled {
		respondErrorMsg(c, "not_found", "Billing is not available", http.StatusNotFound)
		return uuid.Nil, false
	}
	return teamID, true
}

type billingResourceState struct {
	config.BillingResourceConfig
	Billable bool
}

func (h *Handlers) billingConfiguredResources() []config.BillingResourceConfig {
	if h != nil && h.Config != nil && len(h.Config.BillingResources) > 0 {
		resources := make([]config.BillingResourceConfig, len(h.Config.BillingResources))
		copy(resources, h.Config.BillingResources)
		sort.SliceStable(resources, func(i, j int) bool {
			if resources[i].SortOrder == resources[j].SortOrder {
				return resources[i].ResourceKey < resources[j].ResourceKey
			}
			return resources[i].SortOrder < resources[j].SortOrder
		})
		return resources
	}
	return defaultBillingResourcesFromPriceIDs(h.configuredCheckoutPriceIDs())
}

func (h *Handlers) configuredCheckoutPriceIDs() []string {
	if h == nil || h.Config == nil {
		return nil
	}
	ids := make([]string, len(h.Config.StripeCheckoutPriceIDs))
	copy(ids, h.Config.StripeCheckoutPriceIDs)
	return ids
}

func defaultBillingResourcesFromPriceIDs(priceIDs []string) []config.BillingResourceConfig {
	resources := []config.BillingResourceConfig{
		{
			ResourceKey:     "vcpu",
			DisplayName:     "CPU",
			SortOrder:       10,
			UsageUnit:       "second",
			StripeEventName: "cpu_vcpu_hours",
			Tracked:         true,
			Billable:        true,
			CheckoutEnabled: true,
		},
		{
			ResourceKey:     "memory_gib",
			DisplayName:     "Memory",
			SortOrder:       20,
			UsageUnit:       "second",
			StripeEventName: "memory_gib_hours",
			Tracked:         true,
			Billable:        true,
			CheckoutEnabled: true,
		},
		{
			ResourceKey:     "storage_gib",
			DisplayName:     "Storage",
			SortOrder:       30,
			UsageUnit:       "second",
			StripeEventName: "storage_gib_hours",
			Tracked:         true,
			Billable:        false,
			CheckoutEnabled: true,
		},
	}
	for i := range resources {
		if i < len(priceIDs) {
			resources[i].StripePriceID = priceIDs[i]
		}
	}
	return resources
}

func (h *Handlers) billingResourceStates(storageBillingEnabled bool) []billingResourceState {
	resources := h.billingConfiguredResources()
	states := make([]billingResourceState, 0, len(resources))
	for _, resource := range resources {
		state := billingResourceState{BillingResourceConfig: resource, Billable: resource.Billable}
		if state.ResourceKey == "storage_gib" {
			state.Billable = storageBillingEnabled
		}
		states = append(states, state)
	}
	return states
}

func billingCheckoutPriceIDs(resources []billingResourceState) ([]string, error) {
	ids := make([]string, 0, len(resources))
	for _, resource := range resources {
		if !resource.Billable || !resource.CheckoutEnabled {
			continue
		}
		if strings.TrimSpace(resource.StripePriceID) == "" {
			return nil, fmt.Errorf("billing resource %s is missing a Stripe price id", resource.ResourceKey)
		}
		ids = append(ids, resource.StripePriceID)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("Stripe checkout price mapping is not configured")
	}
	return ids, nil
}

func billingSummaryResourcesFromState(resources []billingResourceState, vcpuSeconds, memoryGibSeconds, storageGibSeconds float64, charges billing.SummaryCharges) []billingSummaryResource {
	out := make([]billingSummaryResource, 0, len(resources))
	for _, resource := range resources {
		var usage, charge float64
		switch resource.ResourceKey {
		case "vcpu":
			usage = vcpuSeconds
			charge = charges.Breakdown.ComputeUSD
		case "memory_gib":
			usage = memoryGibSeconds
			charge = charges.Breakdown.MemoryUSD
		case "storage_gib":
			usage = storageGibSeconds
			charge = charges.Breakdown.StorageUSD
		}
		if !resource.Billable {
			charge = 0
		}
		out = append(out, billingSummaryResource{
			ResourceKey: resource.ResourceKey,
			Resource:    resource.ResourceKey,
			DisplayName: resource.DisplayName,
			SortOrder:   resource.SortOrder,
			Unit:        resource.UsageUnit,
			DisplayUnit: resource.DisplayUnit,
			Usage:       usage,
			Tracked:     resource.Tracked,
			Billable:    resource.Billable,
			ChargeUSD:   charge,
		})
	}
	return out
}

func billingSummaryResourcesByKey(resources []billingSummaryResource) map[string]billingSummaryResource {
	out := make(map[string]billingSummaryResource, len(resources))
	for _, resource := range resources {
		out[resource.ResourceKey] = resource
	}
	return out
}

func billingAccountHasEstablishedSubscription(account db.GetTeamBillingAccountRow) bool {
	if account.StripeSubscriptionID == nil || strings.TrimSpace(*account.StripeSubscriptionID) == "" {
		return false
	}
	if account.StripeSubscriptionStatus == nil {
		return false
	}
	// Only statuses that Stripe reports after a subscription is actually set up
	// should unlock portal actions and suppress checkout.
	switch strings.TrimSpace(strings.ToLower(*account.StripeSubscriptionStatus)) {
	case "active", "trialing", "past_due", "unpaid", "paused":
		return true
	default:
		return false
	}
}

func (h *Handlers) requireBillingEligible(c *gin.Context, teamID uuid.UUID) bool {
	// Lightweight handler tests use a query mock without the billing schema;
	// production handlers always have a pool-backed database.
	if h.Pool == nil {
		return true
	}
	started := time.Now()
	eligible, err := h.teamBillingEligibleCached(c.Request.Context(), teamID)
	log.Debug().Str("team_id", teamID.String()).Int64("billing_eligibility_ms", time.Since(started).Milliseconds()).Msg("billing eligibility check")
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("read sandbox billing eligibility failed")
		respondError(c, ErrInternal)
		return false
	}
	if !eligible {
		respondErrorMsg(c, "billing_ineligible", "Sandbox usage is unavailable until billing is active", http.StatusPaymentRequired)
		return false
	}
	return true
}

func currentBillingPeriod(now time.Time) (time.Time, time.Time) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

func (h *Handlers) writeBillingPricing(c *gin.Context, planKey string, subject string, cacheControl string, resources []billingResourceState) {
	rates, err := h.DB.ListActivePricingRates(c.Request.Context(), planKey)
	if err != nil {
		log.Error().Err(err).Str("subject", subject).Str("plan_key", planKey).Msg("DB ListActivePricingRates failed")
		respondError(c, ErrInternal)
		return
	}

	h.writeBillingPricingRates(c, pricingRatesFromActiveRows(rates), subject, cacheControl, resources)
}

type billingPricingRate struct {
	PlanKey       string
	PlanName      string
	Currency      string
	Resource      string
	Unit          string
	PriceUsd      pgtype.Numeric
	EffectiveFrom time.Time
}

func pricingRatesFromActiveRows(rows []db.ListActivePricingRatesRow) []billingPricingRate {
	out := make([]billingPricingRate, 0, len(rows))
	for _, row := range rows {
		out = append(out, billingPricingRate{
			PlanKey:       row.PlanKey,
			PlanName:      row.PlanName,
			Currency:      row.Currency,
			Resource:      row.Resource,
			Unit:          row.Unit,
			PriceUsd:      row.PriceUsd,
			EffectiveFrom: row.EffectiveFrom,
		})
	}
	return out
}

func pricingRatesFromTeamCurrentRows(rows []db.ListActivePricingRatesForTeamCurrentRow) []billingPricingRate {
	out := make([]billingPricingRate, 0, len(rows))
	for _, row := range rows {
		out = append(out, billingPricingRate{
			PlanKey:       row.PlanKey,
			PlanName:      row.PlanName,
			Currency:      row.Currency,
			Resource:      row.Resource,
			Unit:          row.Unit,
			PriceUsd:      row.PriceUsd,
			EffectiveFrom: row.EffectiveFrom,
		})
	}
	return out
}

type billingRateCatalog struct {
	PlanKey        string
	PlanName       string
	Currency       string
	OrderedRates   []billingResourceState
	RateByResource map[string]billingPricingRate
}

func (h *Handlers) billingRateCatalog(rates []billingPricingRate, subject string, resources []billingResourceState) (billingRateCatalog, bool) {
	if len(rates) == 0 {
		log.Error().Str("subject", subject).Msg("billing pricing plan has no active rates")
		return billingRateCatalog{}, false
	}
	resourceByKey := make(map[string]billingResourceState, len(resources))
	for _, resource := range resources {
		if _, ok := resourceByKey[resource.ResourceKey]; ok {
			log.Error().Str("subject", subject).Str("resource", resource.ResourceKey).Msg("billing pricing plan configured duplicate resource")
			return billingRateCatalog{}, false
		}
		resourceByKey[resource.ResourceKey] = resource
	}

	catalog := billingRateCatalog{
		PlanKey:        rates[0].PlanKey,
		PlanName:       rates[0].PlanName,
		Currency:       rates[0].Currency,
		OrderedRates:   make([]billingResourceState, 0, len(resources)),
		RateByResource: make(map[string]billingPricingRate, len(resources)),
	}
	for _, rate := range rates {
		resource, ok := resourceByKey[rate.Resource]
		if !ok {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan has an unsupported active rate")
			return billingRateCatalog{}, false
		}
		if rate.Unit != resource.UsageUnit {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan has an unsupported active required rate")
			return billingRateCatalog{}, false
		}
		if _, ok := catalog.RateByResource[rate.Resource]; ok {
			log.Error().
				Str("subject", subject).
				Str("plan_key", catalog.PlanKey).
				Str("resource", rate.Resource).
				Str("unit", rate.Unit).
				Msg("billing pricing plan returned duplicate active required rates")
			return billingRateCatalog{}, false
		}
		catalog.RateByResource[rate.Resource] = rate
	}
	for _, resource := range resources {
		if _, ok := catalog.RateByResource[resource.ResourceKey]; !ok {
			log.Error().Str("subject", subject).Str("plan_key", catalog.PlanKey).Str("resource", resource.ResourceKey).Msg("billing pricing plan is missing an active rate")
			return billingRateCatalog{}, false
		}
	}
	catalog.OrderedRates = append(catalog.OrderedRates, resources...)
	return catalog, true
}

func (h *Handlers) writeBillingPricingRates(c *gin.Context, rates []billingPricingRate, subject string, cacheControl string, resources []billingResourceState) {
	catalog, ok := h.billingRateCatalog(rates, subject, resources)
	if !ok {
		respondPricingUnavailable(c)
		return
	}

	out := billingPricingResponse{
		PlanKey:  catalog.PlanKey,
		PlanName: catalog.PlanName,
		Currency: catalog.Currency,
		Rates:    make([]billingPricingRateResponse, 0, len(catalog.OrderedRates)),
	}
	for _, resource := range catalog.OrderedRates {
		rate := catalog.RateByResource[resource.ResourceKey]
		price, err := numericFloat64(rate.PriceUsd)
		if err != nil {
			log.Error().Err(err).Str("subject", subject).Str("plan_key", catalog.PlanKey).Str("resource", rate.Resource).Msg("convert pricing rate failed")
			respondError(c, ErrInternal)
			return
		}
		out.Rates = append(out.Rates, billingPricingRateResponse{
			ResourceKey:    resource.ResourceKey,
			Resource:       rate.Resource,
			DisplayName:    resource.DisplayName,
			SortOrder:      resource.SortOrder,
			Unit:           rate.Unit,
			DisplayUnit:    resource.DisplayUnit,
			PriceUSD:       price,
			PriceUSDHourly: price * 3600,
			EffectiveFrom:  rate.EffectiveFrom,
			Tracked:        resource.Tracked,
			Billable:       resource.Billable,
		})
	}

	if cacheControl == privatePricingCacheControl {
		setPrivateBillingCacheHeaders(c)
	} else {
		c.Header("Cache-Control", cacheControl)
	}
	c.JSON(http.StatusOK, out)
}

func setPrivateBillingCacheHeaders(c *gin.Context) {
	c.Header("Cache-Control", privatePricingCacheControl)
	c.Header("Vary", "X-API-Key")
}

func respondPricingUnavailable(c *gin.Context) {
	respondErrorMsg(c, "pricing_unavailable", "Billing pricing is not available", http.StatusServiceUnavailable)
}

func numericFloat64(n pgtype.Numeric) (float64, error) {
	v, err := n.Float64Value()
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, fmt.Errorf("numeric value is null")
	}
	return v.Float64, nil
}
