//go:build integration

package billing

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/db"
)

type RollupJobForTest struct {
	ID           uuid.UUID
	TeamID       uuid.UUID
	HourStart    time.Time
	HourEnd      time.Time
	AttemptCount int
}

func ClaimJobsForTest(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, workerID string) ([]RollupJobForTest, error) {
	cfg = normalizeConfig(cfg)
	jobs, err := claimJobs(ctx, pool, cfg, workerID, time.Now().UTC().Add(cfg.LockDuration))
	if err != nil {
		return nil, err
	}

	out := make([]RollupJobForTest, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, RollupJobForTest{
			ID:           job.ID,
			TeamID:       job.TeamID,
			HourStart:    job.HourStart,
			HourEnd:      job.HourEnd,
			AttemptCount: job.AttemptCount,
		})
	}
	return out, nil
}

func EnqueueHourForTest(ctx context.Context, pool *pgxpool.Pool, hourStart time.Time, hourEnd time.Time) (int64, error) {
	return enqueueHour(ctx, pool, hourStart, hourEnd, true)
}

func EnqueueBackfillForTest(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, now time.Time) (int64, error) {
	cfg = normalizeConfig(cfg)
	return enqueueBackfill(ctx, pool, cfg, now)
}

func NextBackfillHoursForTest(ctx context.Context, pool *pgxpool.Pool, startHour time.Time, endHour time.Time, batchHours int) ([]time.Time, error) {
	return nextBackfillHours(ctx, pool, startHour, endHour, batchHours)
}

func ProcessJobsForTest(ctx context.Context, pool *pgxpool.Pool, q *db.Queries, cfg HourlyRollupConfig, workerID string) {
	cfg = normalizeConfig(cfg)
	processJobs(ctx, pool, q, cfg, workerID)
}
