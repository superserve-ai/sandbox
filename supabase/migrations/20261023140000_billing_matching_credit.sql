-- Matching credit: a contract earns credit worth a percentage of the usage its
-- customer actually paid for, up to a lifetime cap. The rule is frozen on the
-- contract; catalog changes never reach an existing rule.
CREATE TABLE billing_contract_matching_rule (
    contract_id uuid PRIMARY KEY,
    team_id uuid NOT NULL,
    matching_bps integer NOT NULL CHECK (matching_bps BETWEEN 1 AND 10000),
    cap_cents bigint NOT NULL CHECK (cap_cents > 0),
    -- Cap already consumed by matches issued by hand before the rule existed.
    prior_matched_cents bigint NOT NULL DEFAULT 0 CHECK (prior_matched_cents BETWEEN 0 AND cap_cents),
    eligible_source text NOT NULL DEFAULT 'customer_paid_usage' CHECK (eligible_source = 'customer_paid_usage'),
    effective_from timestamptz NOT NULL CHECK (isfinite(effective_from)),
    source text NOT NULL CHECK (source IN ('plan', 'staff')),
    created_by uuid,
    reason text CHECK (btrim(reason) <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz CHECK (isfinite(revoked_at)),
    revoked_by uuid,
    revoke_reason text CHECK (btrim(revoke_reason) <> ''),
    UNIQUE (team_id, contract_id),
    FOREIGN KEY (team_id, contract_id) REFERENCES billing_commercial_contract(team_id, id),
    CHECK (source = 'plan' OR (created_by IS NOT NULL AND reason IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL) AND (revoked_at IS NULL) = (revoke_reason IS NULL))
);

-- One row per paid usage invoice, including invoices that earned nothing, so a
-- replayed or late invoice can never be matched twice.
CREATE TABLE billing_matching_credit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    invoice_id text NOT NULL UNIQUE REFERENCES billing_invoice_close(invoice_id),
    customer_id text NOT NULL CHECK (btrim(customer_id) <> ''),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end > period_start),
    usage_cents bigint NOT NULL CHECK (usage_cents >= 0),
    credit_applied_cents bigint NOT NULL CHECK (credit_applied_cents >= 0),
    discount_cents bigint NOT NULL CHECK (discount_cents >= 0),
    -- Usage left unpaid after cash is attributed to the fee first.
    unpaid_cents bigint NOT NULL CHECK (unpaid_cents >= 0),
    matchable_cents bigint NOT NULL CHECK (matchable_cents >= 0),
    amount_cents bigint NOT NULL CHECK (amount_cents >= 0),
    skip_reason text CHECK (btrim(skip_reason) <> ''),
    invoice_evidence jsonb NOT NULL CHECK (jsonb_typeof(invoice_evidence) = 'object'),
    -- withheld: staff declined a match held for a reversed payment. It keeps its
    -- cap reservation so the running total never shrinks behind recorded skips.
    state text NOT NULL CHECK (state IN ('pending', 'uncertain', 'issued', 'skipped', 'withheld')),
    idempotency_key text NOT NULL UNIQUE,
    request_payload jsonb,
    first_attempt_at timestamptz,
    stripe_credit_grant_id text UNIQUE CHECK (btrim(stripe_credit_grant_id) <> ''),
    issuance_evidence jsonb,
    issued_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    failures integer NOT NULL DEFAULT 0,
    last_error text,
    review_checked_at timestamptz,
    flagged_at timestamptz,
    flag_reason text,
    flag_evidence jsonb,
    acknowledged_at timestamptz,
    acknowledged_by uuid,
    acknowledgement_reason text CHECK (btrim(acknowledgement_reason) <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (team_id, contract_id) REFERENCES billing_contract_matching_rule(team_id, contract_id),
    CHECK ((state = 'skipped') = (amount_cents = 0)),
    CHECK (skip_reason IS NULL OR state = 'skipped'),
    CHECK ((state = 'skipped') = (request_payload IS NULL)),
    CHECK ((state IN ('pending', 'skipped', 'withheld')) = (first_attempt_at IS NULL)),
    CHECK (state <> 'withheld' OR acknowledged_at IS NOT NULL),
    CHECK ((state = 'issued') = (stripe_credit_grant_id IS NOT NULL AND issuance_evidence IS NOT NULL AND issued_at IS NOT NULL)),
    CHECK ((flagged_at IS NULL) = (flag_reason IS NULL)),
    CHECK (acknowledged_at IS NULL OR flagged_at IS NOT NULL),
    CHECK ((acknowledged_at IS NULL) = (acknowledged_by IS NULL) AND (acknowledged_at IS NULL) = (acknowledgement_reason IS NULL))
);
CREATE INDEX billing_matching_credit_contract ON billing_matching_credit(contract_id, created_at);
CREATE INDEX billing_matching_credit_due ON billing_matching_credit(next_attempt_at) WHERE state IN ('pending', 'uncertain');
CREATE INDEX billing_matching_credit_review ON billing_matching_credit((COALESCE(review_checked_at, '-infinity'::timestamptz)))
    WHERE amount_cents > 0 AND flagged_at IS NULL AND review_checked_at IS DISTINCT FROM 'infinity'::timestamptz;
CREATE INDEX billing_matching_credit_flagged ON billing_matching_credit(flagged_at) WHERE acknowledged_at IS NULL;

CREATE FUNCTION guard_billing_contract_matching_rule() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'matching rules are immutable'; END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR (to_jsonb(NEW) - ARRAY['revoked_at','revoked_by','revoke_reason']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['revoked_at','revoked_by','revoke_reason']) THEN
            RAISE EXCEPTION 'matching rule terms are immutable; only an unrevoked rule can be revoked';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_contract_matching_rule_guard BEFORE UPDATE OR DELETE ON billing_contract_matching_rule
    FOR EACH ROW EXECUTE FUNCTION guard_billing_contract_matching_rule();

-- The amount is derived here, under the rule's row lock, so concurrent and
-- out-of-order invoices share one running total and cannot overshoot the cap.
CREATE FUNCTION guard_billing_matching_credit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r billing_contract_matching_rule; c billing_commercial_contract; used bigint; earned bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'matching credit history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO r FROM billing_contract_matching_rule WHERE contract_id = NEW.contract_id AND team_id = NEW.team_id FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'matching credit lacks a matching rule'; END IF;
        SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id = NEW.contract_id;
        IF NEW.period_start < r.effective_from OR (r.revoked_at IS NOT NULL AND NEW.period_start >= r.revoked_at)
            OR NEW.period_start < c.starts_at OR (c.ends_at IS NOT NULL AND NEW.period_start >= c.ends_at)
            OR NEW.customer_id IS DISTINCT FROM c.customer_id
            OR EXISTS (SELECT 1 FROM billing_commercial_contract n WHERE n.subscription_id = c.subscription_id AND n.id <> c.id
                AND n.starts_at > c.starts_at AND n.starts_at <= NEW.period_start) THEN
            RAISE EXCEPTION 'invoice period is outside the matching rule';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM billing_invoice_close j JOIN billing_invoice_collection k USING (invoice_id)
            WHERE j.invoice_id = NEW.invoice_id AND j.team_id = NEW.team_id AND j.period_start = NEW.period_start
                AND j.period_end = NEW.period_end AND j.state = 'released' AND j.plan->>'customer' = NEW.customer_id
                AND j.plan->>'subscription' = c.subscription_id
                AND k.customer_id = NEW.customer_id AND k.state = 'paid') THEN
            RAISE EXCEPTION 'matching requires a released and fully paid usage invoice';
        END IF;
        SELECT COALESCE(sum(amount_cents), 0) INTO used FROM billing_matching_credit WHERE contract_id = NEW.contract_id;
        NEW.matchable_cents := greatest(NEW.usage_cents - NEW.credit_applied_cents - NEW.discount_cents - NEW.unpaid_cents, 0);
        earned := floor(NEW.matchable_cents::numeric * r.matching_bps / 10000)::bigint;
        NEW.amount_cents := CASE WHEN NEW.skip_reason IS NOT NULL THEN 0
            ELSE greatest(least(earned, r.cap_cents - r.prior_matched_cents - used), 0) END;
        NEW.idempotency_key := 'matching-credit:v1:' || NEW.invoice_id;
        NEW.first_attempt_at := NULL;
        NEW.stripe_credit_grant_id := NULL;
        NEW.issuance_evidence := NULL;
        NEW.issued_at := NULL;
        NEW.flagged_at := NULL;
        NEW.flag_reason := NULL;
        NEW.acknowledged_at := NULL;
        NEW.acknowledged_by := NULL;
        NEW.acknowledgement_reason := NULL;
        IF NEW.amount_cents = 0 THEN
            NEW.state := 'skipped';
            NEW.request_payload := NULL;
        ELSE
            NEW.state := 'pending';
            NEW.request_payload := jsonb_build_object(
                'customer', NEW.customer_id, 'category', 'promotional',
                'name', 'Matching credit',
                'amount', jsonb_build_object('type', 'monetary', 'monetary', jsonb_build_object('currency', 'usd', 'value', NEW.amount_cents)),
                'priority', 50,
                'applicability_config', jsonb_build_object('scope', jsonb_build_object('price_type', 'metered')),
                'metadata', jsonb_build_object('matching_credit_id', NEW.id::text, 'invoice_id', NEW.invoice_id));
        END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - ARRAY['state','first_attempt_at','stripe_credit_grant_id','issuance_evidence','issued_at','next_attempt_at','failures','last_error','review_checked_at','flagged_at','flag_reason','flag_evidence','acknowledged_at','acknowledged_by','acknowledgement_reason'])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','first_attempt_at','stripe_credit_grant_id','issuance_evidence','issued_at','next_attempt_at','failures','last_error','review_checked_at','flagged_at','flag_reason','flag_evidence','acknowledged_at','acknowledged_by','acknowledgement_reason']) THEN
        RAISE EXCEPTION 'matching credit terms and identity are immutable';
    END IF;
    IF OLD.flagged_at IS NOT NULL AND (NEW.flagged_at, NEW.flag_reason, NEW.flag_evidence) IS DISTINCT FROM (OLD.flagged_at, OLD.flag_reason, OLD.flag_evidence) THEN
        RAISE EXCEPTION 'a staff flag cannot be replaced';
    END IF;
    IF OLD.acknowledged_at IS NOT NULL AND (NEW.acknowledged_at, NEW.acknowledged_by, NEW.acknowledgement_reason) IS DISTINCT FROM (OLD.acknowledged_at, OLD.acknowledged_by, OLD.acknowledgement_reason) THEN
        RAISE EXCEPTION 'a staff acknowledgement cannot be replaced';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state OR NEW.first_attempt_at IS DISTINCT FROM OLD.first_attempt_at
        OR (NEW.stripe_credit_grant_id, NEW.issuance_evidence, NEW.issued_at) IS DISTINCT FROM (OLD.stripe_credit_grant_id, OLD.issuance_evidence, OLD.issued_at) THEN
        IF OLD.state = 'pending' AND NEW.state = 'uncertain' THEN
            IF OLD.flagged_at IS NOT NULL AND OLD.acknowledged_at IS NULL THEN
                RAISE EXCEPTION 'a flagged match is held for staff and cannot be issued';
            END IF;
            IF NEW.first_attempt_at IS NULL OR NEW.first_attempt_at > clock_timestamp() OR NEW.first_attempt_at < clock_timestamp() - interval '1 minute' THEN
                RAISE EXCEPTION 'issuance intent must be recorded at dispatch';
            END IF;
        ELSIF OLD.state = 'pending' AND NEW.state = 'withheld' THEN
            IF OLD.flagged_at IS NULL OR OLD.acknowledged_at IS NOT NULL OR NEW.acknowledged_at IS NULL OR NEW.first_attempt_at IS NOT NULL THEN
                RAISE EXCEPTION 'only staff acknowledging a held match can withhold it';
            END IF;
        ELSIF OLD.state = 'uncertain' AND NEW.state = 'issued' AND NEW.first_attempt_at = OLD.first_attempt_at THEN
            IF NEW.issuance_evidence->>'id' IS DISTINCT FROM NEW.stripe_credit_grant_id
                OR COALESCE((NEW.issuance_evidence->>'voided_at')::bigint, 0) <> 0
                OR COALESCE((NEW.issuance_evidence->>'expires_at')::bigint, 0) <> 0
                OR NEW.issuance_evidence->'customer' IS DISTINCT FROM NEW.request_payload->'customer'
                OR NEW.issuance_evidence->'amount' IS DISTINCT FROM NEW.request_payload->'amount'
                OR NEW.issuance_evidence->'category' IS DISTINCT FROM NEW.request_payload->'category'
                OR NEW.issuance_evidence->'priority' IS DISTINCT FROM NEW.request_payload->'priority'
                OR NEW.issuance_evidence #> '{applicability_config,scope,price_type}' IS DISTINCT FROM NEW.request_payload #> '{applicability_config,scope,price_type}'
                OR jsonb_array_length(COALESCE(NEW.issuance_evidence #> '{applicability_config,scope,prices}', '[]'::jsonb)) <> 0
                OR NEW.issuance_evidence #>> '{metadata,matching_credit_id}' IS DISTINCT FROM NEW.id::text
                OR NEW.issued_at > clock_timestamp() OR NEW.issued_at < NEW.first_attempt_at THEN
                RAISE EXCEPTION 'grant confirmation does not match the frozen request';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid matching credit transition';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_matching_credit_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_matching_credit
    FOR EACH ROW EXECUTE FUNCTION guard_billing_matching_credit();

DO $$ DECLARE t text; r text; BEGIN
    FOREACH t IN ARRAY ARRAY['billing_contract_matching_rule', 'billing_matching_credit'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
        FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN EXECUTE format('REVOKE ALL ON %I FROM %I', t, r); END IF;
        END LOOP;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO service_role', t);
            EXECUTE format('CREATE POLICY backend_access ON %I TO service_role USING (true) WITH CHECK (true)', t);
        END IF;
    END LOOP;
END $$;
REVOKE ALL ON FUNCTION guard_billing_contract_matching_rule(), guard_billing_matching_credit() FROM PUBLIC;
