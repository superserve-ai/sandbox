-- Activation is independent of delivery flags and survives subscription replacement.
CREATE TABLE team_storage_billing_activation (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    effective_at timestamptz NOT NULL CHECK (isfinite(effective_at)),
    approved_cutoff timestamptz NOT NULL CHECK (isfinite(approved_cutoff)),
    verified_subscription_id text,
    verified_price_id text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (effective_at >= approved_cutoff)
);
ALTER TABLE team_storage_billing_activation ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION protect_storage_billing_activation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Preserve normal team deletion; an existing team's cutoff cannot be removed.
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM team WHERE id = OLD.team_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'storage billing activation is immutable';
END;
$$;
CREATE TRIGGER immutable_storage_billing_activation
BEFORE UPDATE OR DELETE ON team_storage_billing_activation
FOR EACH ROW EXECUTE FUNCTION protect_storage_billing_activation();

CREATE FUNCTION storage_billing_activated(p_team_id uuid, p_end timestamptz DEFAULT 'infinity') RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM team_storage_billing_activation WHERE team_id = p_team_id AND effective_at < p_end);
$$;

-- All payable readers share the same interval intersection. Raw hourly rollups
-- remain observational and must not be used across the activation boundary.
CREATE FUNCTION billable_storage_mib_seconds(p_team_id uuid, p_start timestamptz, p_end timestamptz, p_round_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_start timestamptz;
    v_end timestamptz := LEAST(p_end, now());
    result numeric;
BEGIN
    SELECT GREATEST(p_start, effective_at) INTO v_start
    FROM team_storage_billing_activation WHERE team_id = p_team_id;
    IF v_start IS NULL OR v_start >= v_end THEN
        RETURN 0;
    END IF;
    WITH artifact_bounds AS (
    SELECT
        s.id,
        s.team_id,
        s.snapshot_id,
        s.template_id,
        s.base_path,
        s.delta_path,
        s.destroyed_at,
        first_interval.started_at AS billing_started_at
    FROM sandbox s
    LEFT JOIN LATERAL (
        SELECT MIN(i.started_at) AS started_at
        FROM sandbox_storage_interval i
        WHERE i.sandbox_id = s.id
          AND i.team_id = s.team_id
    ) first_interval ON true
    WHERE s.team_id = p_team_id
      AND first_interval.started_at IS NOT NULL
      AND first_interval.started_at < LEAST(now(), v_end)
      AND s.created_at < LEAST(now(), v_end)
      AND COALESCE(s.destroyed_at, LEAST(now(), v_end)) > v_start
),
artifact_ranges AS (
    SELECT p.path,
           MAX(COALESCE(NULLIF(am.allocated_bytes, 0), 0))::numeric / 1048576.0 AS artifact_mib,
           range_agg(tstzrange(
               GREATEST(s.billing_started_at, v_start),
               LEAST(COALESCE(s.destroyed_at, now()), v_end), '[)'
           )) AS retained_ranges
    FROM artifact_bounds s
    LEFT JOIN template t ON t.id = s.template_id
    CROSS JOIN LATERAL unnest(ARRAY[
        s.base_path,
        s.delta_path,
        CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END
    ]) AS p(path)
    LEFT JOIN artifact_manifest am ON (am.snapshot_id = s.snapshot_id OR am.template_id = t.id)
      AND am.path = p.path
    WHERE p.path IS NOT NULL
    GROUP BY p.path
),
artifact_storage AS (
    SELECT CASE WHEN p_round_artifacts THEN FLOOR(COALESCE(SUM(artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0)) ELSE COALESCE(SUM(artifact_mib * EXTRACT(EPOCH FROM (upper(r) - lower(r)))), 0) END::numeric AS mib_seconds
    FROM artifact_ranges ar
    CROSS JOIN LATERAL unnest(ar.retained_ranges) AS ranges(r)
),
storage AS (
    -- Overlay intervals are per sandbox; template artifacts are a separate
    -- distinct-path set so shared bases and deltas are never multiplied by
    -- the number of sandboxes that pin them.
    SELECT COALESCE(SUM(
        EXTRACT(EPOCH FROM (
            LEAST(COALESCE(i.ended_at, now()), v_end)
            - GREATEST(i.started_at, v_start)
        )) * i.disk_mib
    ), 0)::numeric + COALESCE(MAX(artifact_storage.mib_seconds), 0) AS storage_mib_seconds
    FROM artifact_storage
    LEFT JOIN sandbox_storage_interval i ON
      i.team_id = p_team_id
      AND v_start < LEAST(now(), v_end)
      AND i.started_at < LEAST(now(), v_end)
      AND COALESCE(i.ended_at, LEAST(now(), v_end)) > v_start
)
    SELECT storage_mib_seconds INTO result FROM storage;
    RETURN result;
END;
$$;

-- Expose the authoritative, raw-interval trial balance to billing consumers.
-- Keeping this calculation in Postgres ensures enforcement and the API agree.
CREATE OR REPLACE FUNCTION get_team_trial_balance(p_team_id uuid)
RETURNS TABLE(grant_usd numeric, consumed_usd numeric, remaining_usd numeric, state text, eligible boolean)
LANGUAGE sql STABLE AS $$
WITH account AS (
  SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status FROM team_billing_account WHERE team_id = p_team_id
), historical_grants AS (
  SELECT COUNT(*)::int AS count
  FROM team_credit_grant
  WHERE team_id = p_team_id AND reason = 'signup trial credit'
), grants AS (
  SELECT COALESCE(SUM(amount_usd) FILTER (WHERE expires_at IS NULL OR expires_at > now()), 0)::numeric AS amount, COUNT(*)::int AS count,
         COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > now())::int AS active_count,
         COALESCE(MIN(created_at) FILTER (WHERE expires_at IS NULL OR expires_at > now()), now()) AS started,
         MAX(expires_at) FILTER (WHERE expires_at IS NOT NULL) AS expires_end
  FROM team_credit_grant WHERE team_id = p_team_id AND reason = 'signup trial credit'
), bounds AS (
  SELECT COALESCE((SELECT trial_ended_at FROM account),
                  CASE WHEN grants.count > 0 AND grants.active_count = 0
                       THEN COALESCE(grants.expires_end, now()) ELSE now() END) AS period_end
  FROM grants
), compute_usage AS (
  SELECT COALESCE(SUM(GREATEST(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, bounds.period_end), bounds.period_end) - GREATEST(i.started_at, grants.started))), 0) * i.vcpu_count), 0)::numeric AS cpu,
         COALESCE(SUM(GREATEST(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, bounds.period_end), bounds.period_end) - GREATEST(i.started_at, grants.started))), 0) * i.memory_mib / 1024.0), 0)::numeric AS memory
  FROM sandbox_compute_billing_interval i, bounds, grants
  WHERE i.team_id = p_team_id AND i.started_at < bounds.period_end AND COALESCE(i.ended_at, bounds.period_end) > grants.started
), usage AS (
  SELECT compute_usage.cpu,
         compute_usage.memory,
         (SELECT billable_storage_mib_seconds(p_team_id, grants.started, bounds.period_end) / 1024.0 FROM bounds) AS storage
  FROM compute_usage, grants
), ranked_rates AS (
  SELECT r.*, row_number() OVER (PARTITION BY r.resource, r.unit ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC) AS rate_rank
  FROM pricing_rate r JOIN pricing_plan pp ON pp.key = r.plan_key AND pp.active
  WHERE r.plan_key = COALESCE((SELECT plan_key FROM team_pricing_plan tpp JOIN pricing_plan tppp ON tppp.key = tpp.plan_key AND tppp.active WHERE tpp.team_id = p_team_id AND tpp.effective_from <= now() AND (tpp.effective_to IS NULL OR tpp.effective_to > now()) ORDER BY tpp.effective_from DESC LIMIT 1), 'payg')
    AND r.unit = 'second' AND r.effective_from <= now() AND (r.effective_to IS NULL OR r.effective_to > now())
), rates AS (
  SELECT COALESCE(MAX(price_usd) FILTER (WHERE resource = 'vcpu'), 0)::numeric cpu,
         COALESCE(MAX(price_usd) FILTER (WHERE resource = 'memory_gib'), 0)::numeric memory,
         COALESCE(MAX(price_usd) FILTER (WHERE resource = 'storage_gib'), 0)::numeric storage
  FROM ranked_rates WHERE rate_rank = 1
), calc AS (
  SELECT grants.amount, round((usage.cpu * rates.cpu + usage.memory * rates.memory + CASE WHEN storage_billing_activated(p_team_id) THEN usage.storage * rates.storage ELSE 0 END)::numeric, 6) consumed,
         grants.count, grants.active_count, historical_grants.count AS historical_count,
         account.trial_ended_at, account.stripe_subscription_id, account.stripe_subscription_status
  FROM grants, historical_grants, usage, rates LEFT JOIN account ON true
)
SELECT amount, consumed,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') OR (historical_count > 0 AND active_count = 0)
       THEN 0::numeric ELSE round(GREATEST(amount - consumed, 0)::numeric, 6) END,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') THEN 'ended_by_billing_activation'
       WHEN historical_count = 0 THEN 'no_grant'
       WHEN active_count = 0 THEN 'expired'
       WHEN amount - consumed <= 0 THEN 'exhausted' ELSE 'active' END,
  CASE WHEN trial_ended_at IS NOT NULL OR stripe_subscription_status IS NOT NULL AND lower(stripe_subscription_status) IN ('active','trialing','past_due') THEN lower(COALESCE(stripe_subscription_status, '')) IN ('active','trialing','past_due')
       WHEN historical_count = 0 THEN false
       WHEN active_count = 0 THEN false
       -- Eligibility describes whether active credit may still be consumed;
       -- the warning path separately requires a meaningful usage sample.
       ELSE amount - consumed > 0 END
FROM calc;
$$;

CREATE OR REPLACE FUNCTION refresh_team_trial_eligibility(p_team_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT eligible FROM get_team_trial_balance(p_team_id); $$;

-- Enforcement must use the same cutoff-aware balance as the API. The cache is
-- advisory and may be absent or stale during a refresh, so it cannot grant
-- eligibility after prospective storage has exhausted the remaining credit.
CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
WITH account AS (
    SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status
    FROM team_billing_account WHERE team_id = p_team_id
), balance AS (
    SELECT * FROM get_team_trial_balance(p_team_id)
), grant_balance AS (
    SELECT COALESCE(SUM(remaining_usd) FILTER (WHERE expires_at IS NULL OR expires_at > now()), 0)::numeric AS remaining_usd
    FROM team_credit_grant
    WHERE team_id = p_team_id AND reason = 'signup trial credit'
), denial AS (
    SELECT EXISTS (SELECT 1 FROM team_signup_trial_denial WHERE team_id = p_team_id) AS denied
), pending AS (
    SELECT EXISTS (SELECT 1 FROM team_signup_trial_provenance WHERE team_id = p_team_id AND completed_at IS NULL) AS pending
)
SELECT CASE
    WHEN lower(coalesce(account.stripe_subscription_status, '')) IN ('active','trialing','past_due') THEN true
    WHEN account.trial_ended_at IS NOT NULL THEN false
    WHEN denial.denied OR pending.pending THEN false
    WHEN balance.state = 'no_grant' AND account.stripe_subscription_id IS NULL THEN true
    ELSE grant_balance.remaining_usd > 0 AND COALESCE(balance.eligible, false)
END
FROM balance CROSS JOIN grant_balance CROSS JOIN denial CROSS JOIN pending LEFT JOIN account ON true;
$$;

-- Mixed-version workers may continue writing mutable export caches while a
-- deployment rolls. Clip every such write at the durable cutoff, rather than
-- relying on a one-time cleanup that an old writer can undo.
CREATE OR REPLACE FUNCTION clip_storage_export_cache() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    frozen boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM team_billing_period p
        WHERE p.team_id = NEW.team_id AND p.period_start = NEW.period_start AND p.period_end = NEW.period_end
          AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL OR p.status IN ('exporting','exported','finalized'))
    ) INTO frozen;
    IF frozen THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'billing_export_measurement' THEN
        NEW.storage_mib_seconds := billable_storage_mib_seconds(NEW.team_id, GREATEST(NEW.hour_start, NEW.period_start), LEAST(NEW.hour_start + interval '1 hour', NEW.period_end), false);
    ELSE
        -- Only consumed hour contributions belong in the accumulator. Recomputing
        -- raw usage through now() would exceed its completed-hour coverage.
        SELECT COALESCE(SUM(m.storage_mib_seconds), 0) INTO NEW.storage_mib_seconds
        FROM billing_export_measurement m
        WHERE m.team_id=NEW.team_id AND m.period_start=NEW.period_start AND m.period_end=NEW.period_end;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS clip_billing_export_measurement_storage ON billing_export_measurement;
CREATE TRIGGER clip_billing_export_measurement_storage
BEFORE INSERT OR UPDATE ON billing_export_measurement
FOR EACH ROW EXECUTE FUNCTION clip_storage_export_cache();
DROP TRIGGER IF EXISTS clip_billing_export_usage_storage ON billing_export_usage;
CREATE TRIGGER clip_billing_export_usage_storage
BEFORE INSERT OR UPDATE ON billing_export_usage
FOR EACH ROW EXECUTE FUNCTION clip_storage_export_cache();


-- Mutable cached export contributions predate activation and are not payable.
-- Frozen history and the reservation/event ledgers remain untouched.
UPDATE billing_export_measurement m SET storage_mib_seconds=0
WHERE storage_mib_seconds<>0 AND NOT EXISTS (
    SELECT 1 FROM team_billing_period p WHERE p.team_id=m.team_id
    AND p.period_start=m.period_start AND p.period_end=m.period_end
    AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL OR p.status IN ('exporting','exported','finalized'))
);
UPDATE billing_export_usage u SET storage_mib_seconds=0
WHERE storage_mib_seconds<>0 AND NOT EXISTS (
    SELECT 1 FROM team_billing_period p WHERE p.team_id=u.team_id
    AND p.period_start=u.period_start AND p.period_end=u.period_end
    AND (p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL OR p.status IN ('exporting','exported','finalized'))
);
