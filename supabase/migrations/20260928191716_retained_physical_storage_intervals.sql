SET LOCAL lock_timeout = '250ms';

-- Physical ranges are scoped to a host and a receipt-time inventory epoch.
-- Owner intervals preserve shared references after source deletion.
CREATE TABLE retained_storage_cutover (
 host_id text NOT NULL,
 team_id uuid NOT NULL REFERENCES team(id),
 started_at timestamptz NOT NULL,
 PRIMARY KEY(host_id,team_id)
);
CREATE TABLE retained_storage_interval (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 host_id text NOT NULL,
 team_id uuid NOT NULL REFERENCES team(id),
 owner_kind text NOT NULL CHECK(owner_kind IN ('sandbox','snapshot')),
 owner_id uuid NOT NULL,
 generation text NOT NULL,
 extents jsonb NOT NULL CHECK(jsonb_typeof(extents)='array'),
 started_at timestamptz NOT NULL,
 ended_at timestamptz,
 CHECK(ended_at IS NULL OR ended_at >= started_at),
 UNIQUE(host_id,owner_kind,owner_id,started_at)
);
CREATE UNIQUE INDEX retained_storage_current ON retained_storage_interval(host_id,owner_kind,owner_id) WHERE ended_at IS NULL;
CREATE INDEX retained_storage_team_time ON retained_storage_interval(team_id,started_at);
CREATE INDEX retained_storage_host_time ON retained_storage_interval(host_id,started_at);
-- Billing reads constrain both interval edges before expanding extents. Keep
-- the candidate set indexable so bucketed reads do not repeatedly scan every
-- historical row for a team or host.
CREATE INDEX retained_storage_team_window ON retained_storage_interval(team_id,started_at,ended_at);
CREATE INDEX retained_storage_host_window ON retained_storage_interval(host_id,started_at,ended_at);
CREATE INDEX retained_storage_owner_close ON retained_storage_interval(owner_kind,owner_id) WHERE ended_at IS NULL;
ALTER TABLE retained_storage_cutover ENABLE ROW LEVEL SECURITY;
ALTER TABLE retained_storage_interval ENABLE ROW LEVEL SECURITY;

-- Snapshot the sandbox host at the beginning of each legacy storage interval.
-- Billing must not consult sandbox.host_id later: reassignment is a lifecycle
-- operation and must not move an already-finalized legacy cutover boundary.
ALTER TABLE sandbox_storage_interval ADD COLUMN host_id text;
UPDATE sandbox_storage_interval i SET host_id=s.host_id
FROM sandbox s WHERE s.id=i.sandbox_id AND i.host_id IS NULL;
CREATE FUNCTION stamp_sandbox_storage_interval_host() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.host_id IS NULL THEN
  SELECT host_id INTO NEW.host_id FROM sandbox WHERE id=NEW.sandbox_id;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER stamp_sandbox_storage_interval_host
 BEFORE INSERT ON sandbox_storage_interval FOR EACH ROW
 EXECUTE FUNCTION stamp_sandbox_storage_interval_host();
CREATE INDEX sandbox_storage_interval_host_window ON sandbox_storage_interval(host_id,started_at,ended_at);

-- These triggers do no discovery or aggregation. The lifecycle row lock also
-- fences the asynchronous report writer; only confirmed deletion ends retention.
CREATE FUNCTION close_retained_storage_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE boundary timestamptz;
BEGIN
 IF TG_TABLE_NAME='sandbox' THEN boundary := NEW.destroyed_at;
 ELSE boundary := NEW.deleted_at; END IF;
 IF boundary IS NOT NULL THEN
  UPDATE retained_storage_interval SET ended_at=GREATEST(started_at,boundary)
  WHERE owner_id=NEW.id AND owner_kind=CASE WHEN TG_TABLE_NAME='sandbox' THEN 'sandbox' ELSE 'snapshot' END
    AND ended_at IS NULL;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER close_sandbox_retained_storage AFTER UPDATE OF destroyed_at ON sandbox
 FOR EACH ROW WHEN (OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL) EXECUTE FUNCTION close_retained_storage_owner();
CREATE TRIGGER close_snapshot_retained_storage AFTER UPDATE OF deleted_at ON sandbox_snapshot
 FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION close_retained_storage_owner();

CREATE FUNCTION retained_storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz)
RETURNS numeric LANGUAGE sql STABLE AS $$
 WITH intervals AS MATERIALIZED (
  SELECT host_id,extents,GREATEST(started_at,p_start) lo,LEAST(COALESCE(ended_at,billing_request_now()),p_end,billing_request_now()) hi
  FROM retained_storage_interval
  WHERE team_id=p_team AND p_start<LEAST(p_end,billing_request_now()) AND started_at<LEAST(p_end,billing_request_now()) AND COALESCE(ended_at,billing_request_now())>p_start
 ), boundaries AS (
  SELECT host_id,lo at FROM intervals UNION SELECT host_id,hi FROM intervals
 ), slices AS (
  SELECT host_id,at lo,lead(at) OVER(PARTITION BY host_id ORDER BY at) hi FROM boundaries
 ), allocations AS (
  SELECT s.host_id,s.lo,s.hi,e.device,
   range_agg(int8range(e.start,e.start+e.length,'[)')) blocks
  FROM slices s JOIN intervals i ON i.host_id=s.host_id AND i.lo<=s.lo AND i.hi>=s.hi
  CROSS JOIN LATERAL jsonb_to_recordset(i.extents) AS e(device text,start bigint,length bigint)
  WHERE s.hi>s.lo GROUP BY s.host_id,s.lo,s.hi,e.device
 ) SELECT COALESCE(sum((upper(r)-lower(r))::numeric*EXTRACT(epoch FROM(hi-lo))/1048576.0),0)
 FROM allocations CROSS JOIN LATERAL unnest(blocks) AS ranges(r)
$$;

-- Legacy accounting is clipped prospectively, as one complete host/team group.
-- Existing pre-cutover quantities and rounding remain unchanged.
-- Series buckets preserve fractional legacy artifact usage until aggregation.
CREATE FUNCTION storage_mib_seconds(p_team uuid,p_start timestamptz,p_end timestamptz,p_floor_legacy_artifacts boolean DEFAULT true)
RETURNS numeric LANGUAGE sql STABLE AS $$
WITH legacy_intervals AS MATERIALIZED (
  SELECT i.sandbox_id,i.team_id,i.host_id,i.disk_mib,i.started_at,LEAST(i.ended_at,c.started_at) ended_at,
   LEAST(s.destroyed_at,c.started_at) artifact_retention_end
  FROM sandbox_storage_interval i
  JOIN sandbox s ON s.id=i.sandbox_id
  LEFT JOIN retained_storage_cutover c ON c.host_id=i.host_id AND c.team_id=i.team_id
  WHERE i.team_id=p_team AND p_start<LEAST(p_end,billing_request_now()) AND i.started_at<COALESCE(c.started_at,'infinity')
 ), artifact_bounds AS (
  SELECT s.*,f.retention_end,f.started_at billing_started_at
  FROM sandbox s
  JOIN LATERAL (
   -- Closing an overlay measurement does not release its referenced artifacts.
   -- An unbounded retention interval must survive aggregation with closed ones.
   SELECT min(started_at) started_at,
    NULLIF(max(COALESCE(artifact_retention_end,'infinity'::timestamptz)),'infinity'::timestamptz) retention_end
   FROM legacy_intervals i WHERE i.sandbox_id=s.id
  ) f ON f.started_at IS NOT NULL
  WHERE s.team_id=p_team AND f.started_at<LEAST(billing_request_now(),p_end)
    AND COALESCE(f.retention_end,billing_request_now())>p_start
 ), artifact_ranges AS (
  SELECT p.path,MAX(COALESCE(am.allocated_bytes,0))::numeric/1048576.0 artifact_mib,
   range_agg(tstzrange(GREATEST(s.billing_started_at,p_start),LEAST(COALESCE(s.retention_end,billing_request_now()),p_end),'[)')) retained_ranges
  FROM artifact_bounds s LEFT JOIN template t ON t.id=s.template_id
  CROSS JOIN LATERAL unnest(ARRAY[s.base_path,s.delta_path,CASE WHEN s.base_path IS NULL AND s.delta_path IS NULL THEN t.rootfs_path END]) p(path)
  LEFT JOIN artifact_manifest am ON (am.snapshot_id=s.snapshot_id OR am.template_id=t.id) AND am.path=p.path
  WHERE p.path IS NOT NULL GROUP BY p.path
 ), artifacts AS (
  SELECT COALESCE(sum(artifact_mib*EXTRACT(epoch FROM(upper(r)-lower(r)))),0) amount
  FROM artifact_ranges CROSS JOIN LATERAL unnest(retained_ranges) ranges(r)
 ), overlays AS (
  SELECT COALESCE(sum(EXTRACT(epoch FROM(LEAST(COALESCE(ended_at,billing_request_now()),p_end)-GREATEST(started_at,p_start)))*disk_mib),0) amount
  FROM legacy_intervals WHERE started_at<LEAST(billing_request_now(),p_end) AND COALESCE(ended_at,billing_request_now())>p_start
 ) SELECT CASE WHEN p_start>=LEAST(p_end,billing_request_now()) THEN 0 ELSE
  (CASE WHEN p_floor_legacy_artifacts THEN FLOOR(artifacts.amount) ELSE artifacts.amount END)
  +overlays.amount+retained_storage_mib_seconds(p_team,p_start,p_end) END
 FROM artifacts,overlays
$$;

CREATE OR REPLACE FUNCTION storage_reports_complete_through(
    p_team_id uuid,
    p_boundary timestamptz
) RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM host_storage_report r
        WHERE r.received_at < p_boundary
          AND (
              r.state IN ('pending', 'processing', 'retry_exhausted')
              OR (
                  r.state = 'processed'
                  AND r.payload IS NOT NULL
                  AND (
                      jsonb_typeof(r.payload) <> 'array'
                      OR r.next_measurement_index <> CASE
                          WHEN jsonb_typeof(r.payload) = 'array' THEN jsonb_array_length(r.payload)
                          ELSE -1
                      END
                  )
              )
          )
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = r.host_id
                AND s.created_at <= r.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > r.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=r.host_id
                AND s.ready_at<=r.received_at
                AND (s.deleted_at IS NULL OR s.deleted_at>r.received_at)
          )
        UNION ALL
        SELECT 1
        FROM legacy_host_storage_report legacy
        WHERE legacy.received_at < p_boundary
          AND EXISTS (
              SELECT 1
              FROM sandbox s
              WHERE s.team_id = p_team_id
                AND s.host_id = legacy.host_id
                AND s.created_at <= legacy.received_at
                AND (s.destroyed_at IS NULL OR s.destroyed_at > legacy.received_at)
              UNION ALL SELECT 1 FROM sandbox_snapshot s
              WHERE s.team_id=p_team_id AND s.host_id=legacy.host_id
                AND s.ready_at<=legacy.received_at
                AND (s.deleted_at IS NULL OR s.deleted_at>legacy.received_at)
          )
    )
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
         (SELECT storage_mib_seconds(p_team_id,grants.started,bounds.period_end)/1024.0 FROM bounds)::numeric AS storage
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
  SELECT grants.amount, round((usage.cpu * rates.cpu + usage.memory * rates.memory + CASE WHEN feature_enabled('billing_storage_billing_enabled', p_team_id) THEN usage.storage * rates.storage ELSE 0 END)::numeric, 6) consumed,
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


DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE ON retained_storage_cutover,retained_storage_interval TO service_role;
  GRANT USAGE,SELECT ON SEQUENCE retained_storage_interval_id_seq TO service_role;
 END IF;
END $$;
