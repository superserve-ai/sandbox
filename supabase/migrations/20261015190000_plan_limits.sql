-- A team's sandbox and template limits follow its commercial plan. They are
-- rewritten only when a contract activates or ends, so admission and template
-- validation keep reading the team row as before.
CREATE TABLE plan_limits (
    offer_key text PRIMARY KEY,
    max_sandboxes integer NOT NULL CHECK (max_sandboxes > 0),
    -- NULL template caps fall back to the API's per-team defaults.
    max_template_vcpu integer CHECK (max_template_vcpu > 0),
    max_template_memory_mib integer CHECK (max_template_memory_mib > 0),
    max_template_disk_mib integer CHECK (max_template_disk_mib > 0)
);
ALTER TABLE plan_limits ENABLE ROW LEVEL SECURITY;

INSERT INTO plan_limits VALUES
    ('free', 20, NULL, NULL, NULL),
    ('pro_monthly', 1000, 16, 65536, 65536),
    ('pro_annual', 1000, 16, 65536, 65536);

-- Teams whose limits were set by hand keep them through every plan change.
ALTER TABLE team ADD COLUMN limits_customized boolean NOT NULL DEFAULT false;
UPDATE team SET limits_customized = true
WHERE max_sandboxes <> 20 OR max_template_vcpu IS NOT NULL
    OR max_template_memory_mib IS NOT NULL OR max_template_disk_mib IS NOT NULL;

CREATE FUNCTION apply_plan_limits(p_team uuid, p_offer text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('superserve.applying_plan_limits', 'on', true);
    UPDATE team t SET
        max_sandboxes = l.max_sandboxes,
        max_template_vcpu = l.max_template_vcpu,
        max_template_memory_mib = l.max_template_memory_mib,
        max_template_disk_mib = l.max_template_disk_mib
    FROM plan_limits l
    WHERE t.id = p_team AND l.offer_key = p_offer AND NOT t.limits_customized;
    PERFORM set_config('superserve.applying_plan_limits', 'off', true);
END;
$$;

-- Any other write to these columns is a manual override.
CREATE FUNCTION team_mark_limits_customized() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('superserve.applying_plan_limits', true) IS DISTINCT FROM 'on'
        AND (OLD.max_sandboxes, OLD.max_template_vcpu, OLD.max_template_memory_mib, OLD.max_template_disk_mib)
            IS DISTINCT FROM (NEW.max_sandboxes, NEW.max_template_vcpu, NEW.max_template_memory_mib, NEW.max_template_disk_mib) THEN
        NEW.limits_customized := true;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER team_limits_customized
    BEFORE UPDATE OF max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib ON team
    FOR EACH ROW EXECUTE FUNCTION team_mark_limits_customized();

-- Ending a contract returns the team to Free limits. Running sandboxes are
-- untouched; the quota only blocks new admissions while the team is over.
CREATE FUNCTION billing_contract_apply_plan_limits() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM apply_plan_limits(NEW.team_id, CASE NEW.status WHEN 'active' THEN NEW.offer_key ELSE 'free' END);
    RETURN NULL;
END;
$$;
CREATE TRIGGER billing_contract_plan_limits
    AFTER UPDATE OF status ON billing_commercial_contract
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status IN ('active', 'ended'))
    EXECUTE FUNCTION billing_contract_apply_plan_limits();

SELECT apply_plan_limits(team_id, offer_key) FROM billing_commercial_contract
WHERE status = 'active' AND (ends_at IS NULL OR ends_at > clock_timestamp());

DO $$
DECLARE r text;
BEGIN
    REVOKE ALL ON FUNCTION apply_plan_limits(uuid, text) FROM PUBLIC;
    REVOKE ALL ON FUNCTION team_mark_limits_customized() FROM PUBLIC;
    REVOKE ALL ON FUNCTION billing_contract_apply_plan_limits() FROM PUBLIC;
    FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('REVOKE ALL ON TABLE plan_limits FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION apply_plan_limits(uuid, text) FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION team_mark_limits_customized() FROM %I', r);
            EXECUTE format('REVOKE ALL ON FUNCTION billing_contract_apply_plan_limits() FROM %I', r);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION apply_plan_limits(uuid, text) TO service_role;
    END IF;
END;
$$;
