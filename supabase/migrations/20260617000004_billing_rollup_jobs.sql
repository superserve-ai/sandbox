-- Durable hourly billing rollup work queue.
--
-- The hourly usage table is recomputable from raw interval rows. This queue
-- makes catch-up durable and horizontally scalable: one scheduler enqueues
-- team-hour jobs, and any number of workers can claim jobs with SKIP LOCKED.

CREATE TABLE billing_rollup_scheduler_lease (
    name          text PRIMARY KEY,
    locked_by     text NOT NULL,
    locked_until  timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT billing_rollup_scheduler_lease_name_nonempty CHECK (name <> ''),
    CONSTRAINT billing_rollup_scheduler_lease_locked_by_nonempty CHECK (locked_by <> '')
);

CREATE TABLE billing_rollup_job (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id        uuid NOT NULL REFERENCES team(id),
    hour_start     timestamptz NOT NULL,
    hour_end       timestamptz NOT NULL,
    status         text NOT NULL DEFAULT 'pending',
    attempt_count  int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_by      text,
    locked_until   timestamptz,
    last_error     text,
    enqueued_at    timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT billing_rollup_job_unique_team_hour UNIQUE (team_id, hour_start),
    CONSTRAINT billing_rollup_job_hour_valid CHECK (hour_end = hour_start + interval '1 hour'),
    CONSTRAINT billing_rollup_job_status_valid
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    CONSTRAINT billing_rollup_job_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT billing_rollup_job_lock_fields CHECK (
        (status = 'running' AND locked_by IS NOT NULL AND locked_until IS NOT NULL)
        OR (status <> 'running' AND locked_by IS NULL AND locked_until IS NULL)
    ),
    CONSTRAINT billing_rollup_job_completed_fields CHECK (
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status <> 'completed')
    )
);

CREATE INDEX idx_billing_rollup_job_claim
    ON billing_rollup_job(status, next_attempt_at, hour_start, updated_at)
    WHERE status IN ('pending', 'failed', 'running');

CREATE INDEX idx_billing_rollup_job_team_hour
    ON billing_rollup_job(team_id, hour_start DESC);

CREATE INDEX idx_billing_rollup_job_lag
    ON billing_rollup_job(hour_start)
    WHERE status IN ('pending', 'failed');

ALTER TABLE public.billing_rollup_scheduler_lease ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_rollup_job ENABLE ROW LEVEL SECURITY;
