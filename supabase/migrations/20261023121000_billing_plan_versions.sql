-- Versioned plan catalog and the pricing switch.
--
-- Plans are versions of a family (pro, free, starter, enterprise, payg, or a
-- customer-specific family). A version belongs to one pricing model: legacy
-- (what customers buy today) or v2. Each model has at most one published
-- version per family, and the one switch chooses which model is live, so the
-- v2 catalog is published but neither shown nor sold until the switch flips.
-- Published and retired versions are immutable apart from retirement, so
-- contracts that froze a version's terms can always be traced back to it.
-- Credit schedules use the timed-grant vocabulary: each grant starts at a
-- month offset from the contract anchor, repeats (NULL means indefinitely)
-- every N months and expires N months after it is issued.
CREATE FUNCTION billing_credit_schedule_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE g jsonb; k text;
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'array' OR jsonb_array_length(p) > 24 THEN RETURN false; END IF;
    FOR g IN SELECT value FROM jsonb_array_elements(p) LOOP
        IF jsonb_typeof(g) <> 'object' THEN RETURN false; END IF;
        FOR k IN SELECT jsonb_object_keys(g) LOOP
            IF k NOT IN ('start_months', 'repeat', 'every_months', 'amount_cents', 'expires_after_months') THEN RETURN false; END IF;
        END LOOP;
        IF jsonb_typeof(g->'start_months') IS DISTINCT FROM 'number' OR jsonb_typeof(g->'every_months') IS DISTINCT FROM 'number'
            OR jsonb_typeof(g->'amount_cents') IS DISTINCT FROM 'number' OR jsonb_typeof(g->'expires_after_months') IS DISTINCT FROM 'number'
            OR jsonb_typeof(COALESCE(g->'repeat', 'null'::jsonb)) NOT IN ('number', 'null') THEN
            RETURN false;
        END IF;
        -- Digits only: jsonb keeps 1.0 as written, which Go cannot read as an integer.
        IF (g->>'start_months') !~ '^[0-9]{1,9}$' OR (g->>'every_months') !~ '^[0-9]{1,9}$'
            OR (g->>'expires_after_months') !~ '^[0-9]{1,9}$' OR (g->>'amount_cents') !~ '^[0-9]{1,12}$'
            OR (jsonb_typeof(g->'repeat') = 'number' AND (g->>'repeat') !~ '^[0-9]{1,9}$') THEN
            RETURN false;
        END IF;
        IF (g->>'start_months')::bigint NOT BETWEEN 0 AND 120
            OR (g->>'every_months')::bigint NOT BETWEEN 1 AND 12
            OR (g->>'expires_after_months')::bigint NOT BETWEEN 1 AND 12
            OR (g->>'amount_cents')::bigint NOT BETWEEN 1 AND 100000000
            OR (jsonb_typeof(g->'repeat') = 'number' AND (g->>'repeat')::bigint NOT BETWEEN 1 AND 120) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END $$;

-- One row per region. Staff flip it through the API, which records who and
-- why in the audit below.
CREATE TABLE billing_pricing_switch (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    pricing_version text NOT NULL CHECK (pricing_version IN ('legacy', 'v2')),
    changed_by uuid,
    reason text,
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO billing_pricing_switch(pricing_version) VALUES ('legacy');

CREATE TABLE billing_pricing_switch_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id uuid NOT NULL,
    from_version text NOT NULL,
    to_version text NOT NULL,
    reason text NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 500),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION billing_pricing_version() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT pricing_version FROM billing_pricing_switch), 'legacy');
$$;

CREATE TABLE billing_plan_version (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pricing_version text NOT NULL DEFAULT 'legacy' CHECK (pricing_version IN ('legacy', 'v2')),
    family text NOT NULL CHECK (family ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$' AND length(family) <= 63
        AND family !~ '_(monthly|annual)$'),
    version integer NOT NULL CHECK (version > 0),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'retired')),
    kind text NOT NULL CHECK (kind IN ('free', 'prepaid', 'subscription', 'legacy_payg', 'custom')),
    display_name text NOT NULL CHECK (btrim(display_name) <> '' AND length(display_name) <= 80),
    price_label text NOT NULL DEFAULT '' CHECK (length(price_label) <= 80),
    tagline text NOT NULL DEFAULT '' CHECK (length(tagline) <= 200),
    features text[] NOT NULL DEFAULT '{}' CHECK (cardinality(features) <= 20),
    sort_order integer NOT NULL DEFAULT 0 CHECK (sort_order BETWEEN 0 AND 1000),
    -- Display-only families (Enterprise) are shown as a card but never sold.
    display_only boolean NOT NULL DEFAULT false,
    self_serve boolean NOT NULL DEFAULT false,
    -- Public families are the cards shown at signup; customer-specific deals
    -- are their own non-public families.
    public boolean NOT NULL DEFAULT false,
    monthly_fee_cents bigint CHECK (monthly_fee_cents > 0),
    annual_fee_cents bigint CHECK (annual_fee_cents > 0),
    credit_schedule jsonb NOT NULL DEFAULT '[]' CHECK (billing_credit_schedule_valid(credit_schedule)),
    matching_bps integer CHECK (matching_bps BETWEEN 1 AND 10000),
    cap_cents bigint CHECK (cap_cents > 0),
    -- Usage included in each period. A fixed amount, or for Free a compute
    -- basis priced at the current rate card when read.
    allowance_period text CHECK (allowance_period IN ('day_window', 'month')),
    allowance_on_exhausted text CHECK (allowance_on_exhausted IN ('pause', 'payg')),
    allowance_cents bigint CHECK (allowance_cents > 0),
    allowance_compute_seconds integer CHECK (allowance_compute_seconds > 0),
    allowance_compute_vcpu integer CHECK (allowance_compute_vcpu > 0),
    allowance_compute_memory_gib integer CHECK (allowance_compute_memory_gib > 0),
    max_sandboxes integer CHECK (max_sandboxes > 0),
    max_template_vcpu integer CHECK (max_template_vcpu > 0),
    max_template_memory_mib integer CHECK (max_template_memory_mib > 0),
    max_template_disk_mib integer CHECK (max_template_disk_mib > 0),
    max_templates integer CHECK (max_templates > 0),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_by uuid,
    published_at timestamptz,
    retired_by uuid,
    retired_at timestamptz,
    UNIQUE (family, version),
    CHECK ((matching_bps IS NULL) = (cap_cents IS NULL)),
    CHECK ((allowance_period IS NULL) = (allowance_on_exhausted IS NULL)),
    CHECK ((allowance_compute_seconds IS NULL) = (allowance_compute_vcpu IS NULL)
        AND (allowance_compute_seconds IS NULL) = (allowance_compute_memory_gib IS NULL)),
    CHECK (allowance_period IS NULL OR ((allowance_cents IS NULL) <> (allowance_compute_seconds IS NULL))),
    CHECK (allowance_period IS NOT NULL OR (allowance_cents IS NULL AND allowance_compute_seconds IS NULL)),
    CHECK (NOT display_only OR (monthly_fee_cents IS NULL AND annual_fee_cents IS NULL AND NOT self_serve
        AND credit_schedule = '[]'::jsonb AND matching_bps IS NULL AND allowance_period IS NULL)),
    -- Subscriptions charge a fee; their offer keys have no underscore in the
    -- family. No other kind charges a recurring fee.
    CHECK ((kind = 'subscription') = (monthly_fee_cents IS NOT NULL OR annual_fee_cents IS NOT NULL) OR kind = 'custom'),
    CHECK ((monthly_fee_cents IS NULL AND annual_fee_cents IS NULL) OR (max_sandboxes IS NOT NULL AND family ~ '^[a-z][a-z0-9]*$')),
    CHECK (NOT self_serve OR kind = 'subscription'),
    CHECK (display_only OR max_sandboxes IS NOT NULL OR kind = 'custom'),
    -- Every team without its own limits falls back to the pay-as-you-go caps.
    CHECK (kind <> 'legacy_payg' OR (max_template_vcpu IS NOT NULL AND max_template_memory_mib IS NOT NULL
        AND max_template_disk_mib IS NOT NULL AND max_templates IS NOT NULL)),
    CHECK ((state = 'draft') = (published_at IS NULL)),
    CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX billing_plan_version_current ON billing_plan_version(family, pricing_version) WHERE state = 'published';

CREATE FUNCTION guard_billing_catalog_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state <> 'draft' THEN RAISE EXCEPTION 'published catalog versions are immutable'; END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'draft' THEN RAISE EXCEPTION 'catalog versions start as drafts'; END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'draft' THEN
        IF NEW.state = 'retired' THEN RAISE EXCEPTION 'only published versions can be retired'; END IF;
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    IF OLD.state = 'published' AND NEW.state = 'retired'
        AND (to_jsonb(NEW) - ARRAY['updated_at', 'state', 'retired_by', 'retired_at'])
            = (to_jsonb(OLD) - ARRAY['updated_at', 'state', 'retired_by', 'retired_at']) THEN
        NEW.updated_at := clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'published catalog versions are immutable';
END $$;
CREATE TRIGGER billing_plan_version_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_plan_version
    FOR EACH ROW EXECUTE FUNCTION guard_billing_catalog_version();
CREATE FUNCTION guard_billing_catalog_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER billing_plan_version_truncate_guard BEFORE TRUNCATE ON billing_plan_version
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_pricing_switch_audit_guard BEFORE UPDATE OR DELETE ON billing_pricing_switch_audit
    FOR EACH ROW EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_pricing_switch_audit_truncate_guard BEFORE TRUNCATE ON billing_pricing_switch_audit
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_pricing_switch_truncate_guard BEFORE TRUNCATE OR DELETE ON billing_pricing_switch
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();

-- A schedule subscription contracts can represent: one indefinite monthly
-- grant from the anchor, expiring after a month. Returns its amount, or NULL.
CREATE FUNCTION billing_plan_version_monthly_credit(p billing_plan_version) RETURNS bigint
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN jsonb_array_length(p.credit_schedule) = 1
        AND (p.credit_schedule->0->>'start_months')::int = 0
        AND jsonb_typeof(COALESCE(p.credit_schedule->0->'repeat', 'null'::jsonb)) = 'null'
        AND (p.credit_schedule->0->>'every_months')::int = 1
        AND (p.credit_schedule->0->>'expires_after_months')::int = 1
        THEN (p.credit_schedule->0->>'amount_cents')::bigint END;
$$;

ALTER TABLE plan_limits ADD COLUMN max_templates integer CHECK (max_templates > 0);

-- Keeps the offer rows that contract guards, plan limits and older binaries
-- read in step with the family's live version.
CREATE FUNCTION sync_billing_plan_offers(p_family text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE v billing_plan_version; i integer; fee bigint; credit bigint; k text;
BEGIN
    SELECT * INTO v FROM billing_plan_version
    WHERE family = p_family AND state = 'published' AND pricing_version = billing_pricing_version();
    IF NOT FOUND OR v.kind <> 'subscription' THEN
        UPDATE billing_plan SET available = false WHERE family = p_family;
        RETURN;
    END IF;
    credit := billing_plan_version_monthly_credit(v);
    FOREACH i IN ARRAY ARRAY[1, 12] LOOP
        k := p_family || CASE i WHEN 1 THEN '_monthly' ELSE '_annual' END;
        fee := CASE i WHEN 1 THEN v.monthly_fee_cents ELSE v.annual_fee_cents END;
        IF fee IS NULL THEN
            UPDATE billing_plan SET available = false WHERE offer_key = k;
            CONTINUE;
        END IF;
        INSERT INTO plan_limits(offer_key, max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
        VALUES (k, v.max_sandboxes, v.max_template_vcpu, v.max_template_memory_mib, v.max_template_disk_mib, v.max_templates)
        -- Contracts without frozen limits activate on their offer's
        -- plan_limits, so v2 never rewrites the limits legacy offers sold.
        ON CONFLICT (offer_key) DO UPDATE SET max_sandboxes = EXCLUDED.max_sandboxes, max_template_vcpu = EXCLUDED.max_template_vcpu,
            max_template_memory_mib = EXCLUDED.max_template_memory_mib, max_template_disk_mib = EXCLUDED.max_template_disk_mib,
            max_templates = EXCLUDED.max_templates
        WHERE v.pricing_version = 'legacy';
        INSERT INTO billing_plan(offer_key, family, display_name, charge_interval_months, charge_amount_cents, monthly_credit_cents, available, sort_order)
        VALUES (k, p_family, v.display_name, i, fee, COALESCE(credit, 1), v.self_serve AND v.public AND credit IS NOT NULL AND v.matching_bps IS NULL,
            v.sort_order * 10 + CASE i WHEN 1 THEN 0 ELSE 1 END)
        ON CONFLICT (offer_key) DO UPDATE SET display_name = EXCLUDED.display_name, charge_amount_cents = EXCLUDED.charge_amount_cents,
            monthly_credit_cents = CASE WHEN credit IS NULL THEN billing_plan.monthly_credit_cents ELSE EXCLUDED.monthly_credit_cents END,
            available = EXCLUDED.available, sort_order = EXCLUDED.sort_order;
    END LOOP;
END $$;

-- Both take the family lock before any row lock, so a concurrent publish and
-- retire of one family serialize instead of deadlocking.
CREATE FUNCTION publish_billing_plan_version(p_id uuid, p_actor uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE d billing_plan_version;
BEGIN
    SELECT * INTO d FROM billing_plan_version WHERE id = p_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'catalog version not found' USING ERRCODE = 'no_data_found'; END IF;
    -- A pricing switch flip resyncs every family; holding the switch row
    -- keeps this sync from interleaving with it.
    PERFORM 1 FROM billing_pricing_switch FOR SHARE;
    PERFORM pg_advisory_xact_lock(hashtext('billing-catalog:' || d.family || ':' || d.pricing_version)::bigint);
    SELECT * INTO d FROM billing_plan_version WHERE id = p_id FOR UPDATE;
    IF d.state IS DISTINCT FROM 'draft' THEN
        RAISE EXCEPTION 'only drafts can be published' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    -- A retried or stale publish of an older version must never replace a
    -- newer one that was published since.
    IF EXISTS (SELECT 1 FROM billing_plan_version n WHERE n.family = d.family AND n.pricing_version = d.pricing_version
        AND n.state = 'published' AND n.version > d.version) THEN
        RAISE EXCEPTION 'a newer version is already published' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE billing_plan_version SET state = 'retired', retired_by = p_actor, retired_at = clock_timestamp()
    WHERE family = d.family AND pricing_version = d.pricing_version AND state = 'published';
    UPDATE billing_plan_version SET state = 'published', published_by = p_actor, published_at = clock_timestamp() WHERE id = p_id;
END $$;

CREATE FUNCTION retire_billing_plan_version(p_id uuid, p_actor uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE d billing_plan_version;
BEGIN
    SELECT * INTO d FROM billing_plan_version WHERE id = p_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'catalog version not found' USING ERRCODE = 'no_data_found'; END IF;
    -- A pricing switch flip resyncs every family; holding the switch row
    -- keeps this sync from interleaving with it.
    PERFORM 1 FROM billing_pricing_switch FOR SHARE;
    PERFORM pg_advisory_xact_lock(hashtext('billing-catalog:' || d.family || ':' || d.pricing_version)::bigint);
    SELECT * INTO d FROM billing_plan_version WHERE id = p_id FOR UPDATE;
    IF d.state IS DISTINCT FROM 'published' THEN
        RAISE EXCEPTION 'only the published version can be retired' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE billing_plan_version SET state = 'retired', retired_by = p_actor, retired_at = clock_timestamp() WHERE id = p_id;
END $$;

-- Every state change, however it is made, resyncs the family's offer rows,
-- and flipping the switch resyncs every family.
CREATE FUNCTION sync_billing_plan_version_offers() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM sync_billing_plan_offers(NEW.family);
    RETURN NULL;
END $$;
CREATE TRIGGER billing_plan_version_sync AFTER UPDATE OF state ON billing_plan_version
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state) EXECUTE FUNCTION sync_billing_plan_version_offers();
CREATE FUNCTION sync_all_billing_plan_offers() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE f text;
BEGIN
    FOR f IN SELECT DISTINCT family FROM billing_plan_version UNION SELECT DISTINCT family FROM billing_plan LOOP
        PERFORM sync_billing_plan_offers(f);
    END LOOP;
    RETURN NULL;
END $$;
CREATE TRIGGER billing_pricing_switch_sync AFTER UPDATE OF pricing_version ON billing_pricing_switch
    FOR EACH ROW WHEN (OLD.pricing_version IS DISTINCT FROM NEW.pricing_version) EXECUTE FUNCTION sync_all_billing_plan_offers();

-- Every staff change to the catalog, with who made it and why. The terms
-- column snapshots the version as the change left it.
CREATE TABLE billing_catalog_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('create_draft', 'update_draft', 'delete_draft', 'publish', 'retire')),
    version_id uuid NOT NULL,
    reason text NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 500),
    terms jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX billing_catalog_audit_version ON billing_catalog_audit(version_id, created_at);
CREATE TRIGGER billing_catalog_audit_guard BEFORE UPDATE OR DELETE ON billing_catalog_audit
    FOR EACH ROW EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_catalog_audit_truncate_guard BEFORE TRUNCATE ON billing_catalog_audit
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();

-- Limits a contract was sold with. Contracts with a row keep these limits
-- whatever later catalog versions say; older contracts fall back to the
-- offer's current plan_limits. Manually customised teams keep their limits.
CREATE TABLE billing_contract_limits (
    contract_id uuid PRIMARY KEY REFERENCES billing_commercial_contract(id),
    max_sandboxes integer NOT NULL CHECK (max_sandboxes > 0),
    max_template_vcpu integer CHECK (max_template_vcpu > 0),
    max_template_memory_mib integer CHECK (max_template_memory_mib > 0),
    max_template_disk_mib integer CHECK (max_template_disk_mib > 0),
    max_templates integer CHECK (max_templates > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER billing_contract_limits_guard BEFORE UPDATE OR DELETE ON billing_contract_limits
    FOR EACH ROW EXECUTE FUNCTION guard_billing_catalog_append_only();
CREATE TRIGGER billing_contract_limits_truncate_guard BEFORE TRUNCATE ON billing_contract_limits
    FOR EACH STATEMENT EXECUTE FUNCTION guard_billing_catalog_append_only();

CREATE FUNCTION apply_contract_limits(p_contract uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; l billing_contract_limits;
BEGIN
    SELECT * INTO c FROM billing_commercial_contract WHERE id = p_contract;
    IF NOT FOUND OR c.status <> 'active' OR c.charge_kind = 'sponsored_entitlement' THEN RETURN; END IF;
    SELECT * INTO l FROM billing_contract_limits WHERE contract_id = p_contract;
    IF NOT FOUND THEN
        PERFORM apply_plan_limits(c.team_id, c.offer_key);
        RETURN;
    END IF;
    PERFORM set_config('superserve.applying_plan_limits', 'on', true);
    UPDATE team SET max_sandboxes = l.max_sandboxes, max_template_vcpu = l.max_template_vcpu,
        max_template_memory_mib = l.max_template_memory_mib, max_template_disk_mib = l.max_template_disk_mib
    WHERE id = c.team_id AND NOT limits_customized;
    PERFORM set_config('superserve.applying_plan_limits', 'off', true);
END $$;

-- Unchanged apart from preferring the contract's frozen limits.
CREATE OR REPLACE FUNCTION billing_contract_apply_plan_limits() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.charge_kind<>'sponsored_entitlement' THEN
  IF NEW.status='active' THEN
   PERFORM apply_contract_limits(NEW.id);
  ELSE
   PERFORM apply_plan_limits(NEW.team_id,'free');
  END IF;
 END IF;
 RETURN NULL;
END $$;

-- Limits frozen after the contract activated take effect immediately.
CREATE FUNCTION billing_contract_limits_apply() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM apply_contract_limits(NEW.contract_id);
    RETURN NULL;
END $$;
CREATE TRIGGER billing_contract_limits_apply AFTER INSERT ON billing_contract_limits
    FOR EACH ROW EXECUTE FUNCTION billing_contract_limits_apply();

-- The limits a team works within. Manual overrides and applied plan limits
-- live on the team row; template caps and the template count the row leaves
-- open come from the team's frozen contract limits, then the legacy
-- pay-as-you-go plan, which carries the values the API used to hardcode.
CREATE FUNCTION team_effective_limits(p_team uuid)
RETURNS TABLE(max_concurrent integer, max_vcpu integer, max_memory_mib integer, max_disk_mib integer, max_templates integer)
LANGUAGE sql STABLE AS $$
    WITH base AS (
        SELECT max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates
        FROM billing_plan_version WHERE family = 'payg' AND pricing_version = 'legacy' AND kind = 'legacy_payg' AND state <> 'draft'
        ORDER BY state = 'published' DESC, version DESC LIMIT 1
    ), frozen AS (
        SELECT l.max_templates FROM billing_commercial_contract c JOIN billing_contract_limits l ON l.contract_id = c.id
        WHERE c.team_id = p_team AND c.status = 'active' ORDER BY c.starts_at DESC LIMIT 1
    )
    SELECT t.max_sandboxes,
        COALESCE(t.max_template_vcpu, b.max_template_vcpu),
        COALESCE(t.max_template_memory_mib, b.max_template_memory_mib),
        COALESCE(t.max_template_disk_mib, b.max_template_disk_mib),
        COALESCE(t.max_templates, (SELECT max_templates FROM frozen), b.max_templates)
    FROM team t LEFT JOIN base b ON true WHERE t.id = p_team;
$$;

-- Today's catalog, as the legacy model: Pro monthly and annual, Enterprise,
-- and the pay-as-you-go plan existing teams are on. Seeded ids are derived
-- from the family so every region holds the same version under the same id.
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order, self_serve,
    monthly_fee_cents, annual_fee_cents, credit_schedule, max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
SELECT md5('billing-plan-version:legacy:pro:1')::uuid, 'legacy', 'pro', 1, 'subscription', true, m.display_name, '$1,200/month',
    'For teams running agents in production at scale.', ARRAY['Priority support'], 2, m.available OR a.available,
    -- An interval that is not sold today keeps no fee, so it stays unsold.
    CASE WHEN m.available OR NOT a.available THEN m.charge_amount_cents END,
    CASE WHEN a.available OR NOT m.available THEN a.charge_amount_cents END,
    jsonb_build_array(jsonb_build_object('start_months', 0, 'repeat', NULL, 'every_months', 1, 'amount_cents', m.monthly_credit_cents, 'expires_after_months', 1)),
    l.max_sandboxes, l.max_template_vcpu, l.max_template_memory_mib, l.max_template_disk_mib, 10
FROM billing_plan m JOIN billing_plan a ON a.offer_key = 'pro_annual' JOIN plan_limits l ON l.offer_key = m.offer_key
WHERE m.offer_key = 'pro_monthly';
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, sort_order,
    max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
SELECT md5('billing-plan-version:legacy:payg:1')::uuid, 'legacy', 'payg', 1, 'legacy_payg', false, 'Pay as you go', '$0', '', 1,
    l.max_sandboxes, COALESCE(l.max_template_vcpu, 2), COALESCE(l.max_template_memory_mib, 2048), COALESCE(l.max_template_disk_mib, 8192), 10
FROM plan_limits l WHERE l.offer_key = 'free';
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order, display_only)
VALUES (md5('billing-plan-version:legacy:enterprise:1')::uuid, 'legacy', 'enterprise', 1, 'custom', true, 'Enterprise', 'Custom',
    'For teams that need self-hosting and dedicated support.',
    ARRAY['Self-host in your AWS, GCP, or Azure account', 'Custom concurrency and sandbox sizes', 'Dedicated support'], 3, true);

-- The v2 catalog. Published in its own model, so it is shown and sold only
-- once the switch flips to v2.
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order,
    allowance_period, allowance_on_exhausted, allowance_compute_seconds, allowance_compute_vcpu, allowance_compute_memory_gib,
    max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
VALUES (md5('billing-plan-version:v2:free:1')::uuid, 'v2', 'free', 1, 'free', true, 'Free', '$0', 'No card needed.',
    ARRAY['1 running sandbox', '2 hours of compute every day'], 0,
    'day_window', 'pause', 7200, 1, 1, 1, 1, 1024, 4096, 10);
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order,
    max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
VALUES (md5('billing-plan-version:v2:starter:1')::uuid, 'v2', 'starter', 1, 'prepaid', true, 'Starter', 'Prepaid credit from $5',
    'Pay for what you use with credit that never expires.', ARRAY['Up to 100 running sandboxes', 'Optional auto-recharge'], 1,
    100, 2, 4096, 51200, 10);
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order, self_serve,
    monthly_fee_cents, credit_schedule, allowance_period, allowance_on_exhausted, allowance_cents,
    max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
VALUES (md5('billing-plan-version:v2:pro:2')::uuid, 'v2', 'pro', 2, 'subscription', true, 'Pro', '$250/month',
    'For teams running agents in production.', ARRAY['$250 of usage included every month', 'Priority support'], 2, true,
    25000, '[{"start_months":0,"repeat":null,"every_months":1,"amount_cents":25000,"expires_after_months":1}]', 'month', 'payg', 25000,
    1000, 8, 32768, 102400, 10);
INSERT INTO billing_plan_version(id, pricing_version, family, version, kind, public, display_name, price_label, tagline, features, sort_order, display_only)
VALUES (md5('billing-plan-version:v2:enterprise:2')::uuid, 'v2', 'enterprise', 2, 'custom', true, 'Enterprise', 'Book a meeting',
    'Custom pricing, limits and support.',
    ARRAY['Self-host in your AWS, GCP, or Azure account', 'Custom concurrency and sandbox sizes', 'Dedicated support'], 3, true);
SELECT publish_billing_plan_version(id, NULL) FROM billing_plan_version ORDER BY version;

DO $$ DECLARE r text; t text; f text; BEGIN
    FOREACH t IN ARRAY ARRAY['billing_plan_version', 'billing_pricing_switch', 'billing_pricing_switch_audit', 'billing_catalog_audit', 'billing_contract_limits'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
        FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                EXECUTE format('REVOKE ALL ON %I FROM %I', t, r);
                IF r = 'service_role' THEN
                    EXECUTE format('GRANT SELECT ON %I TO service_role', t);
                    EXECUTE format('CREATE POLICY %I ON %I FOR SELECT TO service_role USING (true)', t || '_backend', t);
                END IF;
            END IF;
        END LOOP;
    END LOOP;
    FOREACH f IN ARRAY ARRAY['billing_credit_schedule_valid(jsonb)', 'billing_pricing_version()', 'guard_billing_catalog_version()',
        'guard_billing_catalog_append_only()', 'billing_plan_version_monthly_credit(billing_plan_version)', 'sync_billing_plan_offers(text)',
        'publish_billing_plan_version(uuid,uuid)', 'retire_billing_plan_version(uuid,uuid)', 'sync_billing_plan_version_offers()',
        'sync_all_billing_plan_offers()', 'apply_contract_limits(uuid)', 'billing_contract_limits_apply()', 'team_effective_limits(uuid)'] LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || f || ' FROM PUBLIC';
        FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f, r);
            END IF;
        END LOOP;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT INSERT, DELETE ON billing_plan_version TO service_role;
        GRANT UPDATE (kind, public, display_name, price_label, tagline, features, sort_order, display_only, self_serve,
            monthly_fee_cents, annual_fee_cents, credit_schedule, matching_bps, cap_cents, allowance_period,
            allowance_on_exhausted, allowance_cents, allowance_compute_seconds, allowance_compute_vcpu,
            allowance_compute_memory_gib, max_sandboxes, max_template_vcpu, max_template_memory_mib,
            max_template_disk_mib, max_templates) ON billing_plan_version TO service_role;
        CREATE POLICY billing_plan_version_insert ON billing_plan_version FOR INSERT TO service_role WITH CHECK (state = 'draft');
        CREATE POLICY billing_plan_version_update ON billing_plan_version FOR UPDATE TO service_role USING (state = 'draft') WITH CHECK (state = 'draft');
        CREATE POLICY billing_plan_version_delete ON billing_plan_version FOR DELETE TO service_role USING (state = 'draft');
        GRANT INSERT (actor_id, action, version_id, reason, terms) ON billing_catalog_audit TO service_role;
        CREATE POLICY billing_catalog_audit_insert ON billing_catalog_audit FOR INSERT TO service_role WITH CHECK (true);
        GRANT INSERT (contract_id, max_sandboxes, max_template_vcpu, max_template_memory_mib, max_template_disk_mib, max_templates)
            ON billing_contract_limits TO service_role;
        CREATE POLICY billing_contract_limits_insert ON billing_contract_limits FOR INSERT TO service_role WITH CHECK (true);
        GRANT EXECUTE ON FUNCTION publish_billing_plan_version(uuid,uuid), retire_billing_plan_version(uuid,uuid) TO service_role;
    END IF;
    -- Triggers and functions run as the writing role, which can be
    -- service_role, so the helpers they call stay executable for it.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        FOREACH f IN ARRAY ARRAY['billing_credit_schedule_valid(jsonb)', 'billing_pricing_version()',
            'billing_plan_version_monthly_credit(billing_plan_version)', 'sync_billing_plan_offers(text)',
            'apply_contract_limits(uuid)', 'team_effective_limits(uuid)'] LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f);
        END LOOP;
    END IF;
END $$;
