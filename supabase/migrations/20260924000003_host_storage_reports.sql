-- Durable storage telemetry accepted independently from host liveness.
-- Reports are immutable inputs; sandbox_storage_interval remains derived state.
CREATE TABLE host_storage_report (
    host_id        text NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    incarnation_id uuid NOT NULL,
    report_id      uuid NOT NULL,
    ingest_seq     bigint NOT NULL,
    received_at    timestamptz NOT NULL DEFAULT now(),
    payload        jsonb NOT NULL,
    state          text NOT NULL DEFAULT 'pending',
    attempts       int NOT NULL DEFAULT 0,
    next_measurement_index int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error     text,
    processed_at   timestamptz,
    PRIMARY KEY (host_id, incarnation_id, report_id),
    UNIQUE (host_id, incarnation_id, ingest_seq),
    CONSTRAINT host_storage_report_state_valid
        CHECK (state IN ('pending', 'processing', 'processed', 'terminal')),
    CONSTRAINT host_storage_report_attempts_nonnegative CHECK (attempts >= 0),
    CONSTRAINT host_storage_report_progress_nonnegative CHECK (next_measurement_index >= 0)
);

CREATE INDEX host_storage_report_pending_idx
    ON host_storage_report (next_attempt_at, received_at)
    WHERE state IN ('pending', 'processing');

ALTER TABLE public.host_storage_report ENABLE ROW LEVEL SECURITY;
