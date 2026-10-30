-- A team on its trial may build templates and keep snapshots up to caps set on
-- the trial policy. Unset caps keep today's trial: no templates, and the
-- team's own snapshot cap. A team awaiting its plan whose trial is used up or
-- was never granted may not build, since every build spends compute. The caps are read, never written to the team, so a
-- plan bought later starts from its own caps.
ALTER TABLE billing_trial_policy
 ADD COLUMN max_templates integer CHECK(max_templates>=0),
 ADD COLUMN max_snapshots integer CHECK(max_snapshots>0);

CREATE OR REPLACE FUNCTION team_effective_limits(p_team uuid)
RETURNS TABLE(max_concurrent integer, max_vcpu integer, max_memory_mib integer, max_disk_mib integer, max_templates integer)
LANGUAGE sql STABLE AS $$
    WITH base AS (
        SELECT max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates
        FROM billing_plan_version WHERE family = 'payg' AND pricing_version = 'legacy' AND kind = 'legacy_payg' AND state <> 'draft'
        ORDER BY state = 'published' DESC, version DESC LIMIT 1
    ), assigned AS (
        SELECT (limits->>'max_templates')::integer AS max_templates FROM team_plan_assignment
        WHERE team_id=p_team AND effective_to IS NULL
    ), frozen AS (
        SELECT l.max_templates FROM billing_commercial_contract c JOIN billing_contract_limits l ON l.contract_id = c.id
        WHERE c.team_id = p_team AND c.status = 'active' ORDER BY c.starts_at DESC LIMIT 1
    ), pending AS (
        SELECT billing_team_awaiting_plan(p_team) AS pending
    )
    SELECT t.max_sandboxes,
        COALESCE(t.max_template_vcpu, b.max_template_vcpu),
        COALESCE(t.max_template_memory_mib, b.max_template_memory_mib),
        COALESCE(t.max_template_disk_mib, b.max_template_disk_mib),
        CASE WHEN p.pending AND NOT billing_team_trial_active(p_team) THEN 0
            WHEN p.pending THEN COALESCE((SELECT tp.max_templates FROM billing_trial_policy tp WHERE tp.singleton), 0)
            ELSE COALESCE(t.max_templates, (SELECT max_templates FROM assigned), (SELECT max_templates FROM frozen), b.max_templates) END
    FROM team t LEFT JOIN base b ON true CROSS JOIN pending p WHERE t.id = p_team;
$$;

CREATE OR REPLACE FUNCTION sandbox_snapshot_quota_on_insert() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    team_limit      int;
    sandbox_limit   int;
    in_flight_limit int;
    trial_limit     int;
    n               bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('sandbox_snapshot_quota'), hashtext(NEW.team_id::text));
    SELECT max_snapshots, max_snapshots_per_sandbox, max_snapshots_in_flight
    INTO team_limit, sandbox_limit, in_flight_limit
    FROM team
    WHERE id = NEW.team_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'team % does not exist', NEW.team_id;
    END IF;

    SELECT tp.max_snapshots INTO trial_limit FROM billing_trial_policy tp WHERE tp.singleton;
    IF trial_limit IS NOT NULL AND billing_team_awaiting_plan(NEW.team_id) THEN
        team_limit := LEAST(team_limit, trial_limit);
    END IF;

    IF NEW.idempotency_key IS NOT NULL AND EXISTS (
        SELECT 1 FROM sandbox_snapshot
        WHERE team_id = NEW.team_id
          AND sandbox_id = NEW.sandbox_id
          AND idempotency_key = NEW.idempotency_key
    ) THEN
        RETURN NEW;
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status = 'creating'
      AND created_at > now() - interval '1 hour';
    IF n >= in_flight_limit THEN
        RAISE EXCEPTION 'snapshots in flight limit reached for team (count=%, max=%)', n, in_flight_limit
            USING ERRCODE = 'SS003';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE team_id = NEW.team_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= team_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for team (count=%, max=%)', n, team_limit
            USING ERRCODE = 'SS002';
    END IF;

    SELECT count(*) INTO n FROM sandbox_snapshot
    WHERE sandbox_id = NEW.sandbox_id AND deleted_at IS NULL AND status IN ('creating', 'ready');
    IF n >= sandbox_limit THEN
        RAISE EXCEPTION 'snapshot quota exceeded for sandbox (count=%, max=%)', n, sandbox_limit
            USING ERRCODE = 'SS002';
    END IF;

    RETURN NEW;
END;
$$;
