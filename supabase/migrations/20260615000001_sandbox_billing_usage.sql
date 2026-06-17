-- Allocated-resource metering for team billing.
--
-- Compute is metered only while a sandbox is active. Each compute billing
-- interval snapshots the resource shape so later changes cannot rewrite
-- history.
--
-- Storage is metered while a sandbox's disk is retained, including while the
-- sandbox is paused. A storage interval opens on first successful activation
-- and closes when the sandbox is deleted.

-- Feature flags provide explicit rollout controls for shadow writes,
-- dashboard visibility, export, and operational telemetry. Defaults keep
-- billing metric writes enabled for this migration branch while keeping
-- invoice export and tenant dashboard exposure disabled until deliberately
-- enabled.
CREATE TABLE feature_flag (
    key          text PRIMARY KEY,
    enabled      boolean NOT NULL DEFAULT false,
    description  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT feature_flag_key_nonempty CHECK (key <> '')
);

CREATE TABLE team_feature_flag (
    team_id     uuid NOT NULL REFERENCES team(id),
    key         text NOT NULL REFERENCES feature_flag(key),
    enabled     boolean NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (team_id, key)
);

ALTER TABLE public.feature_flag ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_feature_flag ENABLE ROW LEVEL SECURITY;

INSERT INTO feature_flag (key, enabled, description) VALUES
    ('billing_metrics_write', true, 'Write raw billing interval rows from trusted lifecycle transitions.'),
    ('billing_hourly_rollups', true, 'Persist hourly usage rollups for dashboards.'),
    ('tenant_usage_dashboard', false, 'Expose provisional usage to tenant dashboards.'),
    ('billing_export_enabled', false, 'Allow approved billing periods to be marked exported.'),
    ('otel_operational_metrics', false, 'Emit operational metrics to the telemetry pipeline.')
ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE FUNCTION feature_enabled(flag_key text, flag_team_id uuid DEFAULT NULL)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        (
            SELECT tff.enabled
            FROM team_feature_flag tff
            WHERE tff.key = flag_key
              AND tff.team_id = flag_team_id
        ),
        (
            SELECT ff.enabled
            FROM feature_flag ff
            WHERE ff.key = flag_key
        ),
        false
    );
$$;

ALTER TABLE sandbox
    ADD COLUMN disk_mib int NOT NULL DEFAULT 4096
        CONSTRAINT sandbox_disk_positive CHECK (disk_mib > 0);

UPDATE sandbox s
SET disk_mib = t.disk_mib
FROM template t
WHERE t.id = s.template_id;

-- Billing rows duplicate team_id for efficient tenant-scoped rollups. Enforce
-- that the duplicated tenant always matches the owning sandbox so a bug or
-- compromised internal writer cannot attribute usage to another team.
ALTER TABLE sandbox
    ADD CONSTRAINT sandbox_id_team_unique UNIQUE (id, team_id);

CREATE TABLE sandbox_compute_billing_interval (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id  uuid NOT NULL,
    team_id     uuid NOT NULL,
    vcpu_count  int NOT NULL,
    memory_mib  int NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    end_reason  text,

    CONSTRAINT sandbox_compute_billing_interval_vcpu_positive
        CHECK (vcpu_count > 0),
    CONSTRAINT sandbox_compute_billing_interval_memory_positive
        CHECK (memory_mib > 0),
    CONSTRAINT sandbox_compute_billing_interval_end_after_start
        CHECK (ended_at IS NULL OR ended_at >= started_at),
    CONSTRAINT sandbox_compute_billing_interval_reason_with_end
        CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CONSTRAINT sandbox_compute_billing_interval_reason_valid
        CHECK (end_reason IS NULL
               OR end_reason IN ('paused', 'timeout_paused', 'deleted', 'failed')),
    CONSTRAINT sandbox_compute_billing_interval_sandbox_team_fk
        FOREIGN KEY (sandbox_id, team_id)
        REFERENCES sandbox(id, team_id)
);

-- Internal billing tables: RLS on, no policies, so anon/authenticated roles get
-- no direct access. Customer billing access goes through backend/service-role APIs.
ALTER TABLE public.sandbox_compute_billing_interval ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_scbi_team_started
    ON sandbox_compute_billing_interval(team_id, started_at DESC);
CREATE UNIQUE INDEX idx_scbi_one_open_per_sandbox
    ON sandbox_compute_billing_interval(sandbox_id)
    WHERE ended_at IS NULL;
CREATE INDEX idx_scbi_team_ended
    ON sandbox_compute_billing_interval(team_id, ended_at DESC);
CREATE INDEX idx_scbi_team_open
    ON sandbox_compute_billing_interval(team_id, sandbox_id)
    WHERE ended_at IS NULL;

-- Backfill billing compute from existing lifecycle active intervals. For
-- historical closed intervals, the current sandbox shape is the best available
-- pre-ledger approximation; new rows snapshot the exact shape at activation.
INSERT INTO sandbox_compute_billing_interval (
    sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason
)
SELECT
    i.sandbox_id,
    i.team_id,
    s.vcpu_count,
    s.memory_mib,
    i.started_at,
    i.ended_at,
    i.end_reason
FROM sandbox_active_interval i
JOIN sandbox s ON s.id = i.sandbox_id;

CREATE TABLE sandbox_storage_interval (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id  uuid NOT NULL,
    team_id     uuid NOT NULL,
    disk_mib    int NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,
    end_reason  text,

    CONSTRAINT sandbox_storage_interval_disk_positive
        CHECK (disk_mib > 0),
    CONSTRAINT sandbox_storage_interval_end_after_start
        CHECK (ended_at IS NULL OR ended_at >= started_at),
    CONSTRAINT sandbox_storage_interval_reason_with_end
        CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CONSTRAINT sandbox_storage_interval_reason_valid
        CHECK (end_reason IS NULL OR end_reason = 'deleted'),
    CONSTRAINT sandbox_storage_interval_sandbox_team_fk
        FOREIGN KEY (sandbox_id, team_id)
        REFERENCES sandbox(id, team_id)
);

-- Internal billing tables: RLS on, no policies, so anon/authenticated roles get
-- no direct access. Customer billing access goes through backend/service-role APIs.
ALTER TABLE public.sandbox_storage_interval ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_ssi_team_started
    ON sandbox_storage_interval(team_id, started_at DESC);
CREATE UNIQUE INDEX idx_ssi_one_open_per_sandbox
    ON sandbox_storage_interval(sandbox_id)
    WHERE ended_at IS NULL;
CREATE INDEX idx_ssi_team_ended
    ON sandbox_storage_interval(team_id, ended_at DESC);
CREATE INDEX idx_ssi_team_open
    ON sandbox_storage_interval(team_id, sandbox_id)
    WHERE ended_at IS NULL;

-- Existing successfully activated sandboxes have retained their disk
-- since creation. Deleted sandboxes receive a closed interval; live sandboxes
-- receive an open interval. Starting and failed sandboxes are omitted because
-- artifact retention is not guaranteed until first successful activation.
INSERT INTO sandbox_storage_interval (
    sandbox_id, team_id, disk_mib, started_at, ended_at, end_reason
)
SELECT
    id,
    team_id,
    disk_mib,
    created_at,
    destroyed_at,
    CASE WHEN destroyed_at IS NOT NULL THEN 'deleted' END
FROM sandbox
WHERE status IN ('active', 'pausing', 'paused', 'resuming', 'deleted');

-- Durable period rollups. Raw interval data remains the source of truth;
-- these rows are suitable for finalized invoice/export bookkeeping.
CREATE TABLE team_billing_usage (
    team_id              uuid NOT NULL REFERENCES team(id),
    period_start         timestamptz NOT NULL,
    period_end           timestamptz NOT NULL,
    vcpu_seconds         numeric NOT NULL DEFAULT 0,
    memory_mib_seconds   numeric NOT NULL DEFAULT 0,
    storage_mib_seconds  numeric NOT NULL DEFAULT 0,
    finalized_at         timestamptz,
    exported_at          timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (team_id, period_start, period_end),
    CONSTRAINT team_billing_usage_period_valid CHECK (period_end > period_start),
    CONSTRAINT team_billing_usage_non_negative CHECK (
        vcpu_seconds >= 0
        AND memory_mib_seconds >= 0
        AND storage_mib_seconds >= 0
    )
);

-- Internal billing tables: RLS on, no policies, so anon/authenticated roles get
-- no direct access. Customer billing access goes through backend/service-role APIs.
ALTER TABLE public.team_billing_usage ENABLE ROW LEVEL SECURITY;

-- Hourly usage rollups for dashboards. These are provisional and can be
-- recomputed from raw intervals; invoice-grade export remains gated by
-- team_billing_period.
CREATE TABLE team_billing_usage_hourly (
    team_id              uuid NOT NULL REFERENCES team(id),
    hour_start           timestamptz NOT NULL,
    hour_end             timestamptz NOT NULL,
    vcpu_seconds         numeric NOT NULL DEFAULT 0,
    memory_mib_seconds   numeric NOT NULL DEFAULT 0,
    storage_mib_seconds  numeric NOT NULL DEFAULT 0,
    updated_at           timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (team_id, hour_start),
    CONSTRAINT team_billing_usage_hourly_period_valid
        CHECK (hour_end = hour_start + interval '1 hour'),
    CONSTRAINT team_billing_usage_hourly_non_negative CHECK (
        vcpu_seconds >= 0
        AND memory_mib_seconds >= 0
        AND storage_mib_seconds >= 0
    )
);

ALTER TABLE public.team_billing_usage_hourly ENABLE ROW LEVEL SECURITY;

-- Billing period state gates export/finalization. A period can be shown as
-- provisional to tenants while blocked from billing-system export.
CREATE TABLE team_billing_period (
    team_id       uuid NOT NULL REFERENCES team(id),
    period_start  timestamptz NOT NULL,
    period_end    timestamptz NOT NULL,
    status        text NOT NULL DEFAULT 'open',
    blocked_reason text,
    blocked_at    timestamptz,
    approved_by   uuid REFERENCES profile(id),
    approved_at   timestamptz,
    exported_at   timestamptz,
    finalized_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (team_id, period_start, period_end),
    CONSTRAINT team_billing_period_valid CHECK (period_end > period_start),
    CONSTRAINT team_billing_period_status_valid CHECK (
        status IN ('open', 'validating', 'blocked', 'approved', 'exported', 'finalized')
    ),
    CONSTRAINT team_billing_period_block_fields CHECK (
        (status = 'blocked') = (
            blocked_at IS NOT NULL
            AND blocked_reason IS NOT NULL
        )
    ),
    CONSTRAINT team_billing_period_approval_fields CHECK (
        (approved_at IS NULL AND approved_by IS NULL)
        OR (approved_at IS NOT NULL AND approved_by IS NOT NULL)
    )
);

ALTER TABLE public.team_billing_period ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_tbp_status_period
    ON team_billing_period(status, period_end DESC);

CREATE TABLE billing_period_anomaly (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id       uuid NOT NULL,
    period_start  timestamptz NOT NULL,
    period_end    timestamptz NOT NULL,
    severity      text NOT NULL,
    kind          text NOT NULL,
    sandbox_id    uuid REFERENCES sandbox(id),
    details       jsonb NOT NULL DEFAULT '{}',
    detected_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    resolved_by   uuid REFERENCES profile(id),

    CONSTRAINT billing_period_anomaly_period_fk
        FOREIGN KEY (team_id, period_start, period_end)
        REFERENCES team_billing_period(team_id, period_start, period_end),
    CONSTRAINT billing_period_anomaly_severity_valid
        CHECK (severity IN ('warning', 'error', 'critical')),
    CONSTRAINT billing_period_anomaly_kind_nonempty
        CHECK (kind <> ''),
    CONSTRAINT billing_period_anomaly_resolved_fields CHECK (
        (resolved_at IS NULL AND resolved_by IS NULL)
        OR (resolved_at IS NOT NULL AND resolved_by IS NOT NULL)
    )
);

ALTER TABLE public.billing_period_anomaly ENABLE ROW LEVEL SECURITY;

CREATE INDEX idx_bpa_unresolved
    ON billing_period_anomaly(team_id, period_start, period_end, severity)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_bpa_sandbox
    ON billing_period_anomaly(sandbox_id)
    WHERE sandbox_id IS NOT NULL;
