package billing

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	defaultHourlyRollupInterval      = 5 * time.Minute
	defaultHourlyRollupLookbackHours = 6
	defaultHourlyRollupTickTimeout   = 2 * time.Minute
)

type HourlyRollupConfig struct {
	Interval      time.Duration
	LookbackHours int
	TickTimeout   time.Duration
}

func DefaultHourlyRollupConfig() HourlyRollupConfig {
	return HourlyRollupConfig{
		Interval:      durationFromEnv("BILLING_HOURLY_ROLLUP_INTERVAL", defaultHourlyRollupInterval),
		LookbackHours: intFromEnv("BILLING_HOURLY_ROLLUP_LOOKBACK_HOURS", defaultHourlyRollupLookbackHours),
		TickTimeout:   durationFromEnv("BILLING_HOURLY_ROLLUP_TICK_TIMEOUT", defaultHourlyRollupTickTimeout),
	}
}

func HourlyRollupDisabledFromEnv() bool {
	return os.Getenv("BILLING_HOURLY_ROLLUP_DISABLED") == "1" ||
		os.Getenv("BILLING_HOURLY_ROLLUP_DISABLED") == "true"
}

func StartHourlyRollupWorker(ctx context.Context, q *db.Queries, cfg HourlyRollupConfig) {
	cfg = normalizeConfig(cfg)
	go func() {
		log.Info().
			Dur("interval", cfg.Interval).
			Int("lookback_hours", cfg.LookbackHours).
			Dur("tick_timeout", cfg.TickTimeout).
			Msg("billing hourly rollup worker started")

		runRollupTick(ctx, q, cfg)

		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("billing hourly rollup worker stopped")
				return
			case <-ticker.C:
				runRollupTick(ctx, q, cfg)
			}
		}
	}()
}

func RunHourlyRollup(ctx context.Context, q *db.Queries, cfg HourlyRollupConfig, now time.Time) error {
	cfg = normalizeConfig(cfg)

	var joined error
	totalTeams := 0
	totalHours := 0

	for _, hourStart := range rollupHours(now, cfg.LookbackHours) {
		hourEnd := hourStart.Add(time.Hour)
		teamIDs, err := q.ListTeamsForHourlyBillingRollup(ctx, db.ListTeamsForHourlyBillingRollupParams{
			HourStart: hourStart,
			HourEnd:   hourEnd,
		})
		if err != nil {
			joined = errors.Join(joined, err)
			log.Error().Err(err).Time("hour_start", hourStart).Msg("list teams for billing hourly rollup failed")
			continue
		}

		totalHours++
		totalTeams += len(teamIDs)
		for _, teamID := range teamIDs {
			_, err := q.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{
				TeamID:    teamID,
				HourStart: hourStart,
				HourEnd:   hourEnd,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				// The team flag may have changed between listing and upsert.
				continue
			}
			if err != nil {
				joined = errors.Join(joined, err)
				log.Error().
					Err(err).
					Str("team_id", teamID.String()).
					Time("hour_start", hourStart).
					Msg("billing hourly rollup upsert failed")
			}
		}
	}

	log.Info().
		Int("hours", totalHours).
		Int("team_hour_rollups", totalTeams).
		Msg("billing hourly rollup tick completed")
	return joined
}

func runRollupTick(ctx context.Context, q *db.Queries, cfg HourlyRollupConfig) {
	tickCtx, cancel := context.WithTimeout(ctx, cfg.TickTimeout)
	defer cancel()

	if err := RunHourlyRollup(tickCtx, q, cfg, time.Now().UTC()); err != nil {
		log.Warn().Err(err).Msg("billing hourly rollup tick completed with errors")
	}
}

func rollupHours(now time.Time, lookbackHours int) []time.Time {
	currentHour := now.UTC().Truncate(time.Hour)
	startHour := currentHour.Add(-time.Duration(lookbackHours-1) * time.Hour)

	hours := make([]time.Time, 0, lookbackHours)
	for hour := startHour; !hour.After(currentHour); hour = hour.Add(time.Hour) {
		hours = append(hours, hour)
	}
	return hours
}

func normalizeConfig(cfg HourlyRollupConfig) HourlyRollupConfig {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultHourlyRollupInterval
	}
	if cfg.LookbackHours <= 0 {
		cfg.LookbackHours = defaultHourlyRollupLookbackHours
	}
	if cfg.TickTimeout <= 0 {
		cfg.TickTimeout = defaultHourlyRollupTickTimeout
	}
	return cfg
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		log.Warn().Str("key", key).Str("value", raw).Msg("invalid duration env; using default")
		return fallback
	}
	return parsed
}

func intFromEnv(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		log.Warn().Str("key", key).Str("value", raw).Msg("invalid integer env; using default")
		return fallback
	}
	return parsed
}
