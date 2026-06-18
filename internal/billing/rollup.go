package billing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	defaultHourlyRollupSchedulerInterval     = 5 * time.Minute
	defaultHourlyRollupWorkerPoll            = 10 * time.Second
	defaultHourlyRollupLookbackHours         = 24
	defaultHourlyRollupBackfillLookbackHours = 90 * 24
	defaultHourlyRollupBackfillBatchHours    = 24
	defaultHourlyRollupLeaseDuration         = 2 * time.Minute
	defaultHourlyRollupLockDuration          = 5 * time.Minute
	defaultHourlyRollupBatchSize             = 100
	defaultHourlyRollupMaxAttempts           = 5
	defaultHourlyRollupWorkers               = 1
)

type HourlyRollupConfig struct {
	SchedulerInterval     time.Duration
	WorkerPoll            time.Duration
	LookbackHours         int
	BackfillLookbackHours int
	BackfillBatchHours    int
	LeaseDuration         time.Duration
	LockDuration          time.Duration
	BatchSize             int
	MaxAttempts           int
	Workers               int
}

type rollupJob struct {
	ID           uuid.UUID
	TeamID       uuid.UUID
	HourStart    time.Time
	HourEnd      time.Time
	AttemptCount int
}

func DefaultHourlyRollupConfig() HourlyRollupConfig {
	return HourlyRollupConfig{
		SchedulerInterval:     durationFromEnv("BILLING_HOURLY_ROLLUP_INTERVAL", defaultHourlyRollupSchedulerInterval),
		WorkerPoll:            durationFromEnv("BILLING_HOURLY_ROLLUP_WORKER_POLL", defaultHourlyRollupWorkerPoll),
		LookbackHours:         intFromEnv("BILLING_HOURLY_ROLLUP_LOOKBACK_HOURS", defaultHourlyRollupLookbackHours),
		BackfillLookbackHours: intFromEnv("BILLING_HOURLY_ROLLUP_BACKFILL_LOOKBACK_HOURS", defaultHourlyRollupBackfillLookbackHours),
		BackfillBatchHours:    intFromEnv("BILLING_HOURLY_ROLLUP_BACKFILL_BATCH_HOURS", defaultHourlyRollupBackfillBatchHours),
		LeaseDuration:         durationFromEnv("BILLING_HOURLY_ROLLUP_LEASE_DURATION", defaultHourlyRollupLeaseDuration),
		LockDuration:          durationFromEnv("BILLING_HOURLY_ROLLUP_LOCK_DURATION", defaultHourlyRollupLockDuration),
		BatchSize:             intFromEnv("BILLING_HOURLY_ROLLUP_BATCH_SIZE", defaultHourlyRollupBatchSize),
		MaxAttempts:           intFromEnv("BILLING_HOURLY_ROLLUP_MAX_ATTEMPTS", defaultHourlyRollupMaxAttempts),
		Workers:               intFromEnv("BILLING_HOURLY_ROLLUP_WORKERS", defaultHourlyRollupWorkers),
	}
}

func HourlyRollupDisabledFromEnv() bool {
	return os.Getenv("BILLING_HOURLY_ROLLUP_DISABLED") == "1" ||
		os.Getenv("BILLING_HOURLY_ROLLUP_DISABLED") == "true"
}

func StartHourlyRollupService(ctx context.Context, pool *pgxpool.Pool, q *db.Queries, cfg HourlyRollupConfig) {
	cfg = normalizeConfig(cfg)
	workerID := workerID()

	log.Info().
		Str("worker_id", workerID).
		Dur("scheduler_interval", cfg.SchedulerInterval).
		Dur("worker_poll", cfg.WorkerPoll).
		Int("lookback_hours", cfg.LookbackHours).
		Int("backfill_lookback_hours", cfg.BackfillLookbackHours).
		Int("backfill_batch_hours", cfg.BackfillBatchHours).
		Int("workers", cfg.Workers).
		Int("batch_size", cfg.BatchSize).
		Msg("billing hourly rollup service starting")

	go runScheduler(ctx, pool, cfg, workerID)
	for i := 0; i < cfg.Workers; i++ {
		go runWorker(ctx, pool, q, cfg, fmt.Sprintf("%s-%d", workerID, i))
	}
}

func runScheduler(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, workerID string) {
	runSchedulerTick(ctx, pool, cfg, workerID)

	ticker := time.NewTicker(cfg.SchedulerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("worker_id", workerID).Msg("billing hourly rollup scheduler stopped")
			return
		case <-ticker.C:
			runSchedulerTick(ctx, pool, cfg, workerID)
		}
	}
}

func runSchedulerTick(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, workerID string) {
	claimed, err := claimSchedulerLease(ctx, pool, workerID, time.Now().UTC().Add(cfg.LeaseDuration))
	if err != nil {
		log.Warn().Err(err).Str("worker_id", workerID).Msg("claim billing rollup scheduler lease failed")
		return
	}
	if !claimed {
		return
	}

	total := int64(0)
	now := time.Now().UTC()
	for _, hourStart := range rollupHours(now, cfg.LookbackHours) {
		enqueued, err := enqueueHour(ctx, pool, hourStart, hourStart.Add(time.Hour), true)
		if err != nil {
			log.Error().Err(err).Time("hour_start", hourStart).Msg("enqueue billing hourly rollup jobs failed")
			continue
		}
		total += enqueued
	}

	backfillTotal, err := enqueueBackfill(ctx, pool, cfg, now)
	if err != nil {
		log.Error().Err(err).Msg("enqueue billing hourly rollup backfill jobs failed")
	} else {
		total += backfillTotal
	}

	log.Info().
		Str("worker_id", workerID).
		Int64("jobs_enqueued_or_refreshed", total).
		Int64("backfill_jobs_enqueued", backfillTotal).
		Int("lookback_hours", cfg.LookbackHours).
		Int("backfill_lookback_hours", cfg.BackfillLookbackHours).
		Msg("billing hourly rollup scheduler tick completed")
}

func runWorker(ctx context.Context, pool *pgxpool.Pool, q *db.Queries, cfg HourlyRollupConfig, workerID string) {
	processJobs(ctx, pool, q, cfg, workerID)

	ticker := time.NewTicker(cfg.WorkerPoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("worker_id", workerID).Msg("billing hourly rollup worker stopped")
			return
		case <-ticker.C:
			processJobs(ctx, pool, q, cfg, workerID)
		}
	}
}

func processJobs(ctx context.Context, pool *pgxpool.Pool, q *db.Queries, cfg HourlyRollupConfig, workerID string) {
	jobs, err := claimJobs(ctx, pool, cfg, workerID, time.Now().UTC().Add(cfg.LockDuration))
	if err != nil {
		log.Warn().Err(err).Str("worker_id", workerID).Msg("claim billing hourly rollup jobs failed")
		return
	}
	if len(jobs) == 0 {
		return
	}

	for _, job := range jobs {
		if err := processJob(ctx, pool, q, cfg, workerID, job); err != nil {
			log.Warn().
				Err(err).
				Str("worker_id", workerID).
				Str("job_id", job.ID.String()).
				Str("team_id", job.TeamID.String()).
				Time("hour_start", job.HourStart).
				Msg("billing hourly rollup job failed")
		}
	}
}

func processJob(ctx context.Context, pool *pgxpool.Pool, q *db.Queries, cfg HourlyRollupConfig, workerID string, job rollupJob) error {
	_, err := q.UpsertTeamBillingUsageHour(ctx, db.UpsertTeamBillingUsageHourParams{
		TeamID:    job.TeamID,
		HourStart: timestamptz(job.HourStart),
		HourEnd:   timestamptz(job.HourEnd),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// The team flag may have been disabled after the scheduler enqueued the job.
		err = nil
	}
	if err != nil {
		nextAttemptAt := time.Now().UTC().Add(backoff(job.AttemptCount))
		if failErr := failJob(ctx, pool, job.ID, workerID, cfg.MaxAttempts, nextAttemptAt, err.Error()); failErr != nil {
			return errors.Join(err, failErr)
		}
		return err
	}

	if err := completeJob(ctx, pool, job.ID, workerID); err != nil {
		return err
	}
	return nil
}

func claimSchedulerLease(ctx context.Context, pool *pgxpool.Pool, workerID string, lockedUntil time.Time) (bool, error) {
	const query = `
INSERT INTO billing_rollup_scheduler_lease (name, locked_by, locked_until)
VALUES ('hourly', $1, $2)
ON CONFLICT (name) DO UPDATE
SET locked_by = EXCLUDED.locked_by,
    locked_until = EXCLUDED.locked_until,
    updated_at = now()
WHERE billing_rollup_scheduler_lease.locked_until <= now()
   OR billing_rollup_scheduler_lease.locked_by = EXCLUDED.locked_by
RETURNING true`

	var claimed bool
	err := pool.QueryRow(ctx, query, workerID, lockedUntil).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return claimed, err
}

func enqueueHour(ctx context.Context, pool *pgxpool.Pool, hourStart, hourEnd time.Time, refreshCompleted bool) (int64, error) {
	const query = `
WITH candidate_teams AS (
    SELECT DISTINCT team_id
    FROM (
        SELECT i.team_id
        FROM sandbox_compute_billing_interval i
        WHERE i.started_at < $2
          AND $1 < LEAST(now(), $2)
          AND COALESCE(i.ended_at, LEAST(now(), $2)) > $1

        UNION

        SELECT i.team_id
        FROM sandbox_storage_interval i
        WHERE i.started_at < $2
          AND $1 < LEAST(now(), $2)
          AND COALESCE(i.ended_at, LEAST(now(), $2)) > $1
    ) billing_teams
    WHERE feature_enabled('billing_hourly_rollups', billing_teams.team_id)
)
INSERT INTO billing_rollup_job (team_id, hour_start, hour_end, status, next_attempt_at)
SELECT team_id, $1, $2, 'pending', now()
FROM candidate_teams
ON CONFLICT (team_id, hour_start) DO UPDATE
SET hour_end = EXCLUDED.hour_end,
    status = 'pending',
    locked_by = NULL,
    locked_until = NULL,
    last_error = CASE
        WHEN billing_rollup_job.status = 'pending'
         AND billing_rollup_job.next_attempt_at > now()
            THEN billing_rollup_job.last_error
        ELSE NULL
    END,
    next_attempt_at = CASE
        WHEN billing_rollup_job.status = 'pending'
         AND billing_rollup_job.next_attempt_at > now()
            THEN billing_rollup_job.next_attempt_at
        ELSE now()
    END,
    attempt_count = CASE
        WHEN billing_rollup_job.status = 'completed' THEN 0
        ELSE billing_rollup_job.attempt_count
    END,
    completed_at = NULL,
    updated_at = now()
WHERE billing_rollup_job.status = 'pending'
   OR (
       $3::boolean
       AND billing_rollup_job.status = 'completed'
       AND (
           billing_rollup_job.hour_end > now()
           OR billing_rollup_job.completed_at < now() - interval '1 hour'
       )
   )`

	tag, err := pool.Exec(ctx, query, hourStart, hourEnd, refreshCompleted)
	return tag.RowsAffected(), err
}

func enqueueBackfill(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, now time.Time) (int64, error) {
	if cfg.BackfillLookbackHours <= cfg.LookbackHours || cfg.BackfillBatchHours <= 0 {
		return 0, nil
	}

	rollingStart := now.UTC().Truncate(time.Hour).Add(-time.Duration(cfg.LookbackHours-1) * time.Hour)
	backfillStart := now.UTC().Truncate(time.Hour).Add(-time.Duration(cfg.BackfillLookbackHours) * time.Hour)
	if !backfillStart.Before(rollingStart) {
		return 0, nil
	}

	hours, err := nextBackfillHours(ctx, pool, backfillStart, rollingStart, cfg.BackfillBatchHours)
	if err != nil {
		return 0, err
	}
	if len(hours) == 0 {
		return 0, nil
	}

	total := int64(0)
	for _, hourStart := range hours {
		enqueued, err := enqueueHour(ctx, pool, hourStart, hourStart.Add(time.Hour), false)
		if err != nil {
			return total, err
		}
		total += enqueued
	}

	if err := advanceBackfillCursor(ctx, pool, hours[0], hours[len(hours)-1].Add(time.Hour)); err != nil {
		log.Warn().
			Err(err).
			Int64("jobs_enqueued", total).
			Time("from_hour", hours[0]).
			Time("to_hour", hours[len(hours)-1].Add(time.Hour)).
			Msg("advance billing rollup backfill cursor failed after enqueue")
		return total, err
	}
	return total, nil
}

func nextBackfillHours(ctx context.Context, pool *pgxpool.Pool, startHour, endHour time.Time, batchHours int) ([]time.Time, error) {
	const query = `
INSERT INTO billing_rollup_backfill_state (name, next_hour_start)
VALUES ('hourly', $1)
ON CONFLICT (name) DO UPDATE
SET next_hour_start = CASE
        WHEN billing_rollup_backfill_state.next_hour_start < $1 THEN $1
        ELSE billing_rollup_backfill_state.next_hour_start
    END,
    updated_at = CASE
        WHEN billing_rollup_backfill_state.next_hour_start < $1 THEN now()
        ELSE billing_rollup_backfill_state.updated_at
    END
RETURNING next_hour_start`

	var cursor time.Time
	if err := pool.QueryRow(ctx, query, startHour).Scan(&cursor); err != nil {
		return nil, err
	}

	if !cursor.Before(endHour) {
		return nil, nil
	}
	batchEnd := cursor.Add(time.Duration(batchHours) * time.Hour)
	if batchEnd.After(endHour) {
		batchEnd = endHour
	}

	hours := make([]time.Time, 0, int(batchEnd.Sub(cursor)/time.Hour))
	for hour := cursor; hour.Before(batchEnd); hour = hour.Add(time.Hour) {
		hours = append(hours, hour)
	}
	return hours, nil
}

func advanceBackfillCursor(ctx context.Context, pool *pgxpool.Pool, fromHour, toHour time.Time) error {
	tag, err := pool.Exec(ctx, `
UPDATE billing_rollup_backfill_state
SET next_hour_start = $2,
    updated_at = now()
WHERE name = 'hourly'
  AND next_hour_start = $1
`, fromHour, toHour)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("billing rollup backfill cursor changed before advance from %s to %s", fromHour, toHour)
	}
	return nil
}

func claimJobs(ctx context.Context, pool *pgxpool.Pool, cfg HourlyRollupConfig, workerID string, lockedUntil time.Time) ([]rollupJob, error) {
	const query = `
WITH candidate AS (
    SELECT id
    FROM billing_rollup_job
    WHERE (
          (
              status IN ('pending', 'failed')
              AND next_attempt_at <= now()
              AND attempt_count < $1
          )
          OR (
              status = 'running'
              AND locked_until <= now()
          )
      )
    ORDER BY hour_start ASC, updated_at ASC
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
UPDATE billing_rollup_job j
SET status = 'running',
    attempt_count = CASE
        WHEN j.status = 'running' AND j.locked_until <= now() THEN j.attempt_count
        ELSE j.attempt_count + 1
    END,
    locked_by = $3,
    locked_until = $4,
    updated_at = now()
FROM candidate
WHERE j.id = candidate.id
RETURNING j.id, j.team_id, j.hour_start, j.hour_end, j.attempt_count`

	rows, err := pool.Query(ctx, query, cfg.MaxAttempts, cfg.BatchSize, workerID, lockedUntil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jobs := make([]rollupJob, 0, cfg.BatchSize)
	for rows.Next() {
		var job rollupJob
		if err := rows.Scan(&job.ID, &job.TeamID, &job.HourStart, &job.HourEnd, &job.AttemptCount); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func completeJob(ctx context.Context, pool *pgxpool.Pool, jobID uuid.UUID, workerID string) error {
	const query = `
UPDATE billing_rollup_job
SET status = 'completed',
    locked_by = NULL,
    locked_until = NULL,
    last_error = NULL,
    completed_at = now(),
    updated_at = now()
WHERE id = $1
  AND locked_by = $2`

	_, err := pool.Exec(ctx, query, jobID, workerID)
	return err
}

func failJob(ctx context.Context, pool *pgxpool.Pool, jobID uuid.UUID, workerID string, maxAttempts int, nextAttemptAt time.Time, message string) error {
	const query = `
UPDATE billing_rollup_job
SET status = CASE WHEN attempt_count >= $3 THEN 'failed' ELSE 'pending' END,
    locked_by = NULL,
    locked_until = NULL,
    next_attempt_at = $4,
    last_error = left($5, 2000),
    updated_at = now()
WHERE id = $1
  AND locked_by = $2`

	_, err := pool.Exec(ctx, query, jobID, workerID, maxAttempts, nextAttemptAt, message)
	return err
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
	if cfg.SchedulerInterval <= 0 {
		cfg.SchedulerInterval = defaultHourlyRollupSchedulerInterval
	}
	if cfg.WorkerPoll <= 0 {
		cfg.WorkerPoll = defaultHourlyRollupWorkerPoll
	}
	if cfg.LookbackHours <= 0 {
		cfg.LookbackHours = defaultHourlyRollupLookbackHours
	}
	if cfg.BackfillLookbackHours < 0 {
		cfg.BackfillLookbackHours = defaultHourlyRollupBackfillLookbackHours
	}
	if cfg.BackfillBatchHours < 0 {
		cfg.BackfillBatchHours = defaultHourlyRollupBackfillBatchHours
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = defaultHourlyRollupLeaseDuration
	}
	if cfg.LockDuration <= 0 {
		cfg.LockDuration = defaultHourlyRollupLockDuration
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultHourlyRollupBatchSize
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultHourlyRollupMaxAttempts
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultHourlyRollupWorkers
	}
	return cfg
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func backoff(attemptCount int) time.Duration {
	if attemptCount <= 0 {
		return 30 * time.Second
	}
	delay := time.Duration(attemptCount*attemptCount) * 30 * time.Second
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

func workerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
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
	if err != nil || parsed < 0 {
		log.Warn().Str("key", key).Str("value", raw).Msg("invalid integer env; using default")
		return fallback
	}
	return parsed
}
