package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const finalizedCreditLedgerReason = "billing period finalization credit application"
const billingMoneyScale = 6

const (
	defaultBillingFinalizationPollInterval = 1 * time.Minute
	defaultBillingFinalizationBatchSize    = 25
)

type FinalizeTeamBillingPeriodResult struct {
	Period  db.TeamBillingPeriod
	Usage   db.TeamBillingUsage
	Charges SummaryCharges
}

type BillingFinalizationConfig struct {
	PollInterval time.Duration
	BatchSize    int
}

func DefaultBillingFinalizationConfig() BillingFinalizationConfig {
	return BillingFinalizationConfig{
		PollInterval: defaultBillingFinalizationPollInterval,
		BatchSize:    defaultBillingFinalizationBatchSize,
	}
}

func StartBillingFinalizationService(ctx context.Context, pool *pgxpool.Pool, cfg BillingFinalizationConfig) {
	cfg = normalizeBillingFinalizationConfig(cfg)
	workerID := strconv.FormatInt(time.Now().UnixNano(), 36)
	log.Info().
		Str("worker_id", workerID).
		Dur("poll_interval", cfg.PollInterval).
		Int("batch_size", cfg.BatchSize).
		Msg("billing period finalization service starting")
	go runBillingFinalizationLoop(ctx, pool, cfg, workerID)
}

func FinalizeTeamBillingPeriodWithCredits(
	ctx context.Context,
	pool *pgxpool.Pool,
	teamID uuid.UUID,
	periodStart time.Time,
	periodEnd time.Time,
) (FinalizeTeamBillingPeriodResult, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := db.New(tx)
	period, err := lockBillingPeriodForFinalization(ctx, tx, teamID, periodStart, periodEnd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}
	if period.FinalizedAt.Valid {
		usage, err := lockBillingUsageForFinalization(ctx, tx, teamID, periodStart, periodEnd)
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return FinalizeTeamBillingPeriodResult{}, err
		}
		return FinalizeTeamBillingPeriodResult{
			Period: period,
			Usage:  usage,
			Charges: SummaryCharges{
				CurrentChargesUSD:        numericToFloat(period.GrossChargesUsd),
				CreditsAppliedUSD:        numericToFloat(period.CreditsAppliedUsd),
				ExpectedInvoiceAmountUSD: numericToFloat(period.NetInvoiceAmountUsd),
				CreditsRemainingUSD:      0,
			},
		}, nil
	}
	if period.Status != "exported" {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("billing period must be exported before finalization: status=%s", period.Status)
	}

	usage, err := lockBillingUsageForFinalization(ctx, tx, teamID, periodStart, periodEnd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}

	ratesAt, err := q.ListActivePricingRatesForTeam(ctx, db.ListActivePricingRatesForTeamParams{
		TeamID:      teamID,
		EffectiveAt: periodEnd.Add(-time.Nanosecond),
	})
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("list pricing rates for team at billing period: %w", err)
	}
	pricingRates, err := validateSummaryPricingRatesForFinalization(ratesAt)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}

	vcpuSeconds, err := exactDecimalFromNumeric(usage.VcpuSeconds)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert vcpu usage failed: %w", err)
	}
	memoryMibSeconds, err := exactDecimalFromNumeric(usage.MemoryMibSeconds)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert memory usage failed: %w", err)
	}
	storageMibSeconds, err := exactDecimalFromNumeric(usage.StorageMibSeconds)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert storage usage failed: %w", err)
	}
	memoryGibSeconds := memoryMibSeconds.DivInt64(1024)
	storageGibSeconds := storageMibSeconds.DivInt64(1024)

	vcpuRate, err := exactDecimalFromNumeric(pricingRates["vcpu"].PriceUsd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert vcpu price failed: %w", err)
	}
	memoryRate, err := exactDecimalFromNumeric(pricingRates["memory_gib"].PriceUsd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert memory price failed: %w", err)
	}
	storageRate, err := exactDecimalFromNumeric(pricingRates["storage_gib"].PriceUsd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert storage price failed: %w", err)
	}

	grantRows, err := lockActiveCreditGrants(ctx, tx, teamID, periodEnd)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}
	creditsAvailableExact := exactDecimalZero()
	for _, grant := range grantRows {
		grantRemaining, err := exactDecimalFromNumeric(grant.RemainingUsd)
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert grant balance failed: %w", err)
		}
		creditsAvailableExact = creditsAvailableExact.Add(grantRemaining)
	}

	currentCharges := vcpuSeconds.Mul(vcpuRate).
		Add(memoryGibSeconds.Mul(memoryRate)).
		Add(storageGibSeconds.Mul(storageRate))
	currentCharges, err = currentCharges.Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize current charges failed: %w", err)
	}
	creditsAvailableExact, err = creditsAvailableExact.Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize available credits failed: %w", err)
	}
	creditsApplied := currentCharges.Min(creditsAvailableExact)
	remainingToApply := creditsApplied

	for _, grant := range grantRows {
		if remainingToApply.IsZero() {
			break
		}
		grantRemaining, err := exactDecimalFromNumeric(grant.RemainingUsd)
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert grant balance failed: %w", err)
		}
		grantRemaining, err = grantRemaining.Quantize(billingMoneyScale)
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize grant balance failed: %w", err)
		}
		consume := remainingToApply.Min(grantRemaining)
		if consume.IsZero() {
			continue
		}
		grantRemainingAfter := grantRemaining.Sub(consume)
		grantRemainingAfter, err = grantRemainingAfter.Quantize(billingMoneyScale)
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize grant balance failed: %w", err)
		}
		remainingNumeric, err := grantRemainingAfter.Numeric()
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert grant balance failed: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE team_credit_grant
			SET remaining_usd = $1::numeric,
			    updated_at = now()
			WHERE id = $2
			  AND team_id = $3
		`, remainingNumeric, grant.ID, teamID); err != nil {
			return FinalizeTeamBillingPeriodResult{}, err
		}
		consumeNumeric, err := consume.Numeric()
		if err != nil {
			return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert grant consumption failed: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO team_credit_ledger (
				team_id, grant_id, billing_period_start, billing_period_end,
				amount_usd, reason, created_by
			)
			VALUES ($1, $2, $3, $4, $5::numeric, $6, NULL)
		`, teamID, grant.ID, periodStart, periodEnd, consumeNumeric, finalizedCreditLedgerReason); err != nil {
			return FinalizeTeamBillingPeriodResult{}, err
		}
		remainingToApply = remainingToApply.Sub(consume)
	}

	currentChargesNumeric, err := currentCharges.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert current charges failed: %w", err)
	}
	creditsAppliedNumeric, err := creditsApplied.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert credits applied failed: %w", err)
	}
	netInvoiceAmount := currentCharges.Sub(creditsApplied)
	netInvoiceAmount, err = netInvoiceAmount.Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize net invoice amount failed: %w", err)
	}
	netInvoiceAmountNumeric, err := netInvoiceAmount.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert net invoice amount failed: %w", err)
	}

	updatedPeriod, err := finalizeBillingPeriod(ctx, tx, teamID, periodStart, periodEnd, currentChargesNumeric, creditsAppliedNumeric, netInvoiceAmountNumeric)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE team_billing_usage
		SET finalized_at = now(),
		    updated_at = now()
		WHERE team_id = $1
		  AND period_start = $2
		  AND period_end = $3
		  AND finalized_at IS NULL
	`, teamID, periodStart, periodEnd); err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return FinalizeTeamBillingPeriodResult{}, err
	}

	updatedPeriod.GrossChargesUsd = currentChargesNumeric
	updatedPeriod.CreditsAppliedUsd = creditsAppliedNumeric
	updatedPeriod.NetInvoiceAmountUsd = netInvoiceAmountNumeric

	creditsRemaining := creditsAvailableExact.Sub(creditsApplied)
	creditsRemaining, err = creditsRemaining.Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("quantize remaining credits failed: %w", err)
	}
	creditsRemainingNumeric, err := creditsRemaining.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert remaining credits failed: %w", err)
	}
	computeUSD, err := vcpuSeconds.Mul(vcpuRate).Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert compute breakdown failed: %w", err)
	}
	computeUSDNumeric, err := computeUSD.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert compute breakdown failed: %w", err)
	}
	memoryUSD, err := memoryGibSeconds.Mul(memoryRate).Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert memory breakdown failed: %w", err)
	}
	memoryUSDNumeric, err := memoryUSD.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert memory breakdown failed: %w", err)
	}
	storageUSD, err := storageGibSeconds.Mul(storageRate).Quantize(billingMoneyScale)
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert storage breakdown failed: %w", err)
	}
	storageUSDNumeric, err := storageUSD.Numeric()
	if err != nil {
		return FinalizeTeamBillingPeriodResult{}, fmt.Errorf("convert storage breakdown failed: %w", err)
	}

	return FinalizeTeamBillingPeriodResult{
		Period: updatedPeriod,
		Usage:  usage,
		Charges: SummaryCharges{
			CurrentChargesUSD:        numericToFloat(currentChargesNumeric),
			CreditsAppliedUSD:        numericToFloat(creditsAppliedNumeric),
			CreditsRemainingUSD:      numericToFloat(creditsRemainingNumeric),
			ExpectedInvoiceAmountUSD: numericToFloat(netInvoiceAmountNumeric),
			Breakdown: SummaryBreakdown{
				ComputeUSD: numericToFloat(computeUSDNumeric),
				MemoryUSD:  numericToFloat(memoryUSDNumeric),
				StorageUSD: numericToFloat(storageUSDNumeric),
			},
		},
	}, nil
}

type exactDecimal struct {
	rat   *big.Rat
	scale int
}

func exactDecimalZero() exactDecimal {
	return exactDecimal{rat: new(big.Rat), scale: 0}
}

func exactDecimalFromNumeric(n pgtype.Numeric) (exactDecimal, error) {
	if !n.Valid {
		return exactDecimal{}, fmt.Errorf("numeric value is null")
	}
	if n.NaN {
		return exactDecimal{}, fmt.Errorf("numeric value is NaN")
	}
	if n.InfinityModifier != 0 {
		return exactDecimal{}, fmt.Errorf("numeric value is infinite")
	}

	rat := new(big.Rat)
	if n.Int == nil {
		rat.SetInt64(0)
	} else {
		rat.SetInt(n.Int)
	}

	scale := 0
	if n.Exp < 0 {
		scale = int(-n.Exp)
		denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
		rat.Quo(rat, new(big.Rat).SetInt(denom))
	} else if n.Exp > 0 {
		mul := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n.Exp)), nil)
		rat.Mul(rat, new(big.Rat).SetInt(mul))
	}

	return exactDecimal{rat: rat, scale: scale}, nil
}

func (d exactDecimal) Add(other exactDecimal) exactDecimal {
	return exactDecimal{
		rat:   new(big.Rat).Add(d.rat, other.rat),
		scale: maxInt(d.scale, other.scale),
	}
}

func (d exactDecimal) Sub(other exactDecimal) exactDecimal {
	return exactDecimal{
		rat:   new(big.Rat).Sub(d.rat, other.rat),
		scale: maxInt(d.scale, other.scale),
	}
}

func (d exactDecimal) Mul(other exactDecimal) exactDecimal {
	return exactDecimal{
		rat:   new(big.Rat).Mul(d.rat, other.rat),
		scale: d.scale + other.scale,
	}
}

func (d exactDecimal) DivInt64(v int64) exactDecimal {
	return exactDecimal{
		rat:   new(big.Rat).Quo(d.rat, new(big.Rat).SetInt64(v)),
		scale: d.scale + 10,
	}
}

func (d exactDecimal) Min(other exactDecimal) exactDecimal {
	if d.rat.Cmp(other.rat) <= 0 {
		return d
	}
	return other
}

func (d exactDecimal) IsZero() bool {
	return d.rat.Sign() == 0
}

func (d exactDecimal) Float64() float64 {
	f, _ := d.rat.Float64()
	return f
}

func (d exactDecimal) Numeric() (pgtype.Numeric, error) {
	var n pgtype.Numeric
	if err := n.Scan(d.rat.FloatString(d.scale)); err != nil {
		return pgtype.Numeric{}, err
	}
	return n, nil
}

func (d exactDecimal) Quantize(scale int) (exactDecimal, error) {
	if scale < 0 {
		scale = 0
	}
	var n pgtype.Numeric
	if err := n.Scan(d.rat.FloatString(scale)); err != nil {
		return exactDecimal{}, err
	}
	quantized, err := exactDecimalFromNumeric(n)
	if err != nil {
		return exactDecimal{}, err
	}
	quantized.scale = scale
	return quantized, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ValidateSummaryPricingRates(rows []db.ListActivePricingRatesForTeamCurrentRow) (map[string]db.ListActivePricingRatesForTeamCurrentRow, error) {
	return validateSummaryPricingRatesCurrent(rows)
}

func validateSummaryPricingRatesCurrent(rows []db.ListActivePricingRatesForTeamCurrentRow) (map[string]db.ListActivePricingRatesForTeamCurrentRow, error) {
	if len(rows) == 0 {
		return nil, errors.New("billing pricing plan has no active rates")
	}

	rates := make(map[string]db.ListActivePricingRatesForTeamCurrentRow, len(requiredSummaryResources))
	for _, row := range rows {
		if _, ok := requiredSummaryResources[row.Resource]; !ok {
			return nil, fmt.Errorf("billing pricing plan has an unsupported active rate: resource=%s", row.Resource)
		}
		if row.Unit != "second" {
			return nil, fmt.Errorf("billing pricing plan has an unsupported active rate: resource=%s unit=%s", row.Resource, row.Unit)
		}
		if _, ok := rates[row.Resource]; ok {
			return nil, fmt.Errorf("billing pricing plan returned duplicate active rates: resource=%s", row.Resource)
		}
		rates[row.Resource] = row
	}
	for resource := range requiredSummaryResources {
		if _, ok := rates[resource]; !ok {
			return nil, fmt.Errorf("billing summary pricing plan is missing an active rate: resource=%s", resource)
		}
	}
	return rates, nil
}

func validateSummaryPricingRatesForFinalization(rows []db.ListActivePricingRatesForTeamRow) (map[string]db.ListActivePricingRatesForTeamCurrentRow, error) {
	converted := make([]db.ListActivePricingRatesForTeamCurrentRow, 0, len(rows))
	for _, row := range rows {
		converted = append(converted, db.ListActivePricingRatesForTeamCurrentRow{
			PlanKey:       row.PlanKey,
			PlanName:      row.PlanName,
			Currency:      row.Currency,
			Resource:      row.Resource,
			Unit:          row.Unit,
			PriceUsd:      row.PriceUsd,
			EffectiveFrom: row.EffectiveFrom,
		})
	}
	return validateSummaryPricingRatesCurrent(converted)
}

func FinalizeExportedBillingPeriods(ctx context.Context, pool *pgxpool.Pool, batchSize int) (int, error) {
	q := db.New(pool)
	rows, err := q.ListExportedTeamBillingPeriods(ctx, int32(batchSize))
	if err != nil {
		return 0, err
	}

	finalized := 0
	var errs []error
	for _, period := range rows {
		if _, err := FinalizeTeamBillingPeriodWithCredits(ctx, pool, period.TeamID, period.PeriodStart, period.PeriodEnd); err != nil {
			errs = append(errs, fmt.Errorf("team %s period %s-%s: %w", period.TeamID, period.PeriodStart.Format(time.RFC3339), period.PeriodEnd.Format(time.RFC3339), err))
			continue
		}
		finalized++
	}
	return finalized, errors.Join(errs...)
}

func runBillingFinalizationLoop(ctx context.Context, pool *pgxpool.Pool, cfg BillingFinalizationConfig, workerID string) {
	runBillingFinalizationTick(ctx, pool, cfg, workerID)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("worker_id", workerID).Msg("billing period finalization service stopped")
			return
		case <-ticker.C:
			runBillingFinalizationTick(ctx, pool, cfg, workerID)
		}
	}
}

func runBillingFinalizationTick(ctx context.Context, pool *pgxpool.Pool, cfg BillingFinalizationConfig, workerID string) {
	finalized, err := FinalizeExportedBillingPeriods(ctx, pool, cfg.BatchSize)
	if err != nil {
		log.Warn().Err(err).Str("worker_id", workerID).Msg("billing period finalization tick failed")
		return
	}
	if finalized > 0 {
		log.Info().Str("worker_id", workerID).Int("finalized", finalized).Msg("billing period finalization tick completed")
	}
}

func normalizeBillingFinalizationConfig(cfg BillingFinalizationConfig) BillingFinalizationConfig {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultBillingFinalizationPollInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBillingFinalizationBatchSize
	}
	return cfg
}

func lockBillingPeriodForFinalization(ctx context.Context, tx pgx.Tx, teamID uuid.UUID, periodStart, periodEnd time.Time) (db.TeamBillingPeriod, error) {
	row := tx.QueryRow(ctx, `
		SELECT team_id, period_start, period_end, status, blocked_reason, blocked_at,
		       approved_by, approved_at, exported_at, finalized_at,
		       gross_charges_usd, credits_applied_usd, net_invoice_amount_usd,
		       created_at, updated_at
		FROM team_billing_period
		WHERE team_id = $1
		  AND period_start = $2
		  AND period_end = $3
		FOR UPDATE
	`, teamID, periodStart, periodEnd)
	var period db.TeamBillingPeriod
	if err := row.Scan(
		&period.TeamID,
		&period.PeriodStart,
		&period.PeriodEnd,
		&period.Status,
		&period.BlockedReason,
		&period.BlockedAt,
		&period.ApprovedBy,
		&period.ApprovedAt,
		&period.ExportedAt,
		&period.FinalizedAt,
		&period.GrossChargesUsd,
		&period.CreditsAppliedUsd,
		&period.NetInvoiceAmountUsd,
		&period.CreatedAt,
		&period.UpdatedAt,
	); err != nil {
		return db.TeamBillingPeriod{}, err
	}
	return period, nil
}

func lockBillingUsageForFinalization(ctx context.Context, tx pgx.Tx, teamID uuid.UUID, periodStart, periodEnd time.Time) (db.TeamBillingUsage, error) {
	row := tx.QueryRow(ctx, `
		SELECT team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds, finalized_at, exported_at, updated_at
		FROM team_billing_usage
		WHERE team_id = $1
		  AND period_start = $2
		  AND period_end = $3
		FOR UPDATE
	`, teamID, periodStart, periodEnd)
	var usage db.TeamBillingUsage
	if err := row.Scan(
		&usage.TeamID,
		&usage.PeriodStart,
		&usage.PeriodEnd,
		&usage.VcpuSeconds,
		&usage.MemoryMibSeconds,
		&usage.StorageMibSeconds,
		&usage.FinalizedAt,
		&usage.ExportedAt,
		&usage.UpdatedAt,
	); err != nil {
		return db.TeamBillingUsage{}, err
	}
	return usage, nil
}

type activeCreditGrant struct {
	ID           uuid.UUID
	RemainingUsd pgtype.Numeric
}

func lockActiveCreditGrants(ctx context.Context, tx pgx.Tx, teamID uuid.UUID, periodEnd time.Time) ([]activeCreditGrant, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, remaining_usd
		FROM team_credit_grant
		WHERE team_id = $1
		  AND remaining_usd > 0
		  AND created_at < $2
		  AND (expires_at IS NULL OR expires_at >= $2)
		ORDER BY expires_at ASC NULLS LAST, created_at ASC, id ASC
		FOR UPDATE
	`, teamID, periodEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []activeCreditGrant
	for rows.Next() {
		var grant activeCreditGrant
		if err := rows.Scan(&grant.ID, &grant.RemainingUsd); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

func finalizeBillingPeriod(
	ctx context.Context,
	tx pgx.Tx,
	teamID uuid.UUID,
	periodStart time.Time,
	periodEnd time.Time,
	grossChargesUSD pgtype.Numeric,
	creditsAppliedUSD pgtype.Numeric,
	netInvoiceAmountUSD pgtype.Numeric,
) (db.TeamBillingPeriod, error) {
	row := tx.QueryRow(ctx, `
		UPDATE team_billing_period
		SET status = 'finalized',
		    finalized_at = now(),
		    gross_charges_usd = $4::numeric,
		    credits_applied_usd = $5::numeric,
		    net_invoice_amount_usd = $6::numeric,
		    updated_at = now()
		WHERE team_id = $1
		  AND period_start = $2
		  AND period_end = $3
		  AND finalized_at IS NULL
		RETURNING team_id, period_start, period_end, status, blocked_reason, blocked_at,
		          approved_by, approved_at, exported_at, finalized_at,
		          gross_charges_usd, credits_applied_usd, net_invoice_amount_usd,
		          created_at, updated_at
	`, teamID, periodStart, periodEnd, grossChargesUSD, creditsAppliedUSD, netInvoiceAmountUSD)

	var period db.TeamBillingPeriod
	if err := row.Scan(
		&period.TeamID,
		&period.PeriodStart,
		&period.PeriodEnd,
		&period.Status,
		&period.BlockedReason,
		&period.BlockedAt,
		&period.ApprovedBy,
		&period.ApprovedAt,
		&period.ExportedAt,
		&period.FinalizedAt,
		&period.GrossChargesUsd,
		&period.CreditsAppliedUsd,
		&period.NetInvoiceAmountUsd,
		&period.CreatedAt,
		&period.UpdatedAt,
	); err != nil {
		return db.TeamBillingPeriod{}, err
	}
	return period, nil
}

func numericToFloat(n pgtype.Numeric) float64 {
	v, err := n.Float64Value()
	if err != nil || !v.Valid {
		return 0
	}
	return v.Float64
}

func floatToNumeric(v float64) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(strconv.FormatFloat(v, 'f', -1, 64))
	return n
}
