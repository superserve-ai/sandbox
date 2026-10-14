-- Commercial terms are independent of the PAYG resource rate card.
CREATE TABLE billing_commercial_contract (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL REFERENCES team(id),
    offer_key text NOT NULL CHECK (btrim(offer_key) <> ''),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'ended')),
    starts_at timestamptz NOT NULL CHECK (isfinite(starts_at)),
    ends_at timestamptz CHECK (isfinite(ends_at) AND ends_at > starts_at),
    customer_id text NOT NULL CHECK (btrim(customer_id) <> ''),
    subscription_id text NOT NULL CHECK (btrim(subscription_id) <> ''),
    base_price_id text NOT NULL CHECK (btrim(base_price_id) <> ''),
    charge_kind text NOT NULL DEFAULT 'subscription' CHECK (charge_kind IN ('subscription', 'upfront')),
    charge_amount_cents bigint NOT NULL CHECK (charge_amount_cents > 0),
    charge_interval_months integer NOT NULL CHECK (charge_interval_months > 0),
    currency text NOT NULL DEFAULT 'usd' CHECK (currency = 'usd'),
    entitlement_kind text NOT NULL DEFAULT 'metered_usage' CHECK (btrim(entitlement_kind) <> ''),
    entitlement_amount_cents bigint NOT NULL CHECK (entitlement_amount_cents > 0),
    entitlement_cadence text NOT NULL DEFAULT 'monthly' CHECK (entitlement_cadence IN ('monthly', 'scheduled')),
    entitlement_anchor timestamptz NOT NULL CHECK (isfinite(entitlement_anchor)),
    collection_has_overdue_balance boolean,
    collection_checked_at timestamptz CHECK (isfinite(collection_checked_at)),
    collection_valid_until timestamptz CHECK (isfinite(collection_valid_until)),
    collection_evidence jsonb,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (team_id, id),
    CHECK (entitlement_anchor <= starts_at),
    CHECK ((collection_has_overdue_balance IS NULL AND collection_checked_at IS NULL AND collection_valid_until IS NULL AND collection_evidence IS NULL)
        OR (collection_has_overdue_balance IS NOT NULL AND collection_checked_at IS NOT NULL
            AND collection_valid_until IS NOT NULL AND collection_valid_until > collection_checked_at
            AND collection_valid_until <= collection_checked_at + interval '5 minutes'
            AND collection_evidence IS NOT NULL AND jsonb_typeof(collection_evidence) = 'object' AND collection_evidence <> '{}'::jsonb)),
    CHECK (offer_key NOT IN ('pro_monthly', 'pro_annual') OR
        (charge_kind = 'subscription' AND entitlement_kind = 'metered_usage' AND entitlement_amount_cents = 100000 AND entitlement_cadence = 'monthly'
         AND charge_interval_months = CASE offer_key WHEN 'pro_monthly' THEN 1 ELSE 12 END
         AND charge_amount_cents = CASE offer_key WHEN 'pro_monthly' THEN 120000 ELSE 1200000 END))
);
CREATE UNIQUE INDEX billing_commercial_contract_current ON billing_commercial_contract(team_id) WHERE status <> 'ended';
CREATE UNIQUE INDEX billing_commercial_subscription_current ON billing_commercial_contract(subscription_id) WHERE status <> 'ended';

-- Explicit monthly amounts keep phased offers independent of the cash cadence.
CREATE TABLE billing_contract_entitlement_schedule (
    team_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    month_offset integer NOT NULL CHECK (month_offset >= 0),
    amount_cents bigint NOT NULL CHECK (amount_cents > 0),
    PRIMARY KEY (contract_id, month_offset),
    FOREIGN KEY (team_id, contract_id) REFERENCES billing_commercial_contract(team_id, id)
);

-- These are verified base-fee receipts, not arbitrary invoice-paid events.
-- The payment handler must retrieve and validate provider payment evidence
-- before writing a receipt; SQL cannot verify a Stripe payment over the network.
CREATE TABLE billing_contract_payment (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    invoice_id text NOT NULL UNIQUE CHECK (btrim(invoice_id) <> ''),
    payment_reference text NOT NULL CHECK (btrim(payment_reference) <> ''),
    customer_id text NOT NULL,
    subscription_id text,
    base_price_id text NOT NULL,
    service_period_start timestamptz NOT NULL CHECK (isfinite(service_period_start)),
    service_period_end timestamptz NOT NULL CHECK (isfinite(service_period_end) AND service_period_end > service_period_start),
    base_amount_paid_cents bigint NOT NULL CHECK (base_amount_paid_cents > 0),
    invoice_amount_paid_cents bigint NOT NULL CHECK (invoice_amount_paid_cents >= base_amount_paid_cents),
    invoice_amount_remaining_cents bigint NOT NULL CHECK (invoice_amount_remaining_cents = 0),
    currency text NOT NULL CHECK (currency = 'usd'),
    paid_at timestamptz NOT NULL CHECK (isfinite(paid_at)),
    verified_at timestamptz NOT NULL CHECK (isfinite(verified_at) AND verified_at >= paid_at),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object' AND evidence <> '{}'::jsonb),
    FOREIGN KEY (team_id, contract_id) REFERENCES billing_commercial_contract(team_id, id),
    UNIQUE (team_id, contract_id, id),
    EXCLUDE USING gist (contract_id WITH =, tstzrange(service_period_start, service_period_end, '[)') WITH &&)
);

CREATE TABLE billing_usage_entitlement (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    payment_id uuid NOT NULL,
    kind text NOT NULL CHECK (btrim(kind) <> ''),
    period_start timestamptz NOT NULL CHECK (isfinite(period_start)),
    period_end timestamptz NOT NULL CHECK (isfinite(period_end) AND period_end > period_start),
    amount_cents bigint NOT NULL CHECK (amount_cents > 0),
    currency text NOT NULL CHECK (currency = 'usd'),
    issuance_source text NOT NULL DEFAULT 'created' CHECK (issuance_source IN ('created', 'adopted')),
    provider_created_at timestamptz,
    adopted_at timestamptz,
    adopted_available_balance_cents bigint CHECK (adopted_available_balance_cents >= 0 AND adopted_available_balance_cents <= amount_cents),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'uncertain', 'issued')),
    idempotency_key text NOT NULL UNIQUE DEFAULT ('usage-entitlement-' || gen_random_uuid()::text),
    first_attempt_at timestamptz,
    request_payload jsonb,
    provider_invoice_start timestamptz,
    provider_invoice_end timestamptz,
    stripe_credit_grant_id text UNIQUE CHECK (btrim(stripe_credit_grant_id) <> ''),
    issuance_evidence jsonb,
    issued_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (team_id, contract_id, payment_id) REFERENCES billing_contract_payment(team_id, contract_id, id),
    UNIQUE (team_id, kind, period_start),
    EXCLUDE USING gist (team_id WITH =, kind WITH =, tstzrange(period_start, period_end, '[)') WITH &&),
    CHECK (length(idempotency_key) BETWEEN 1 AND 255),
    CHECK ((state = 'pending' AND first_attempt_at IS NULL AND request_payload IS NULL
            AND provider_invoice_start IS NULL AND provider_invoice_end IS NULL)
        OR (issuance_source = 'created' AND state IN ('uncertain', 'issued') AND first_attempt_at IS NOT NULL AND isfinite(first_attempt_at)
            AND request_payload IS NOT NULL AND jsonb_typeof(request_payload) = 'object'
            AND provider_invoice_start IS NOT NULL AND isfinite(provider_invoice_start)
            AND provider_invoice_end IS NOT NULL AND isfinite(provider_invoice_end) AND provider_invoice_end > provider_invoice_start)
        OR (issuance_source = 'adopted' AND state = 'issued' AND first_attempt_at IS NULL AND request_payload IS NULL
            AND provider_invoice_start IS NOT NULL AND provider_invoice_end > provider_invoice_start)),
    CHECK ((issuance_source = 'created' AND provider_created_at IS NULL AND adopted_at IS NULL AND adopted_available_balance_cents IS NULL)
        OR (issuance_source = 'adopted' AND state = 'issued' AND provider_created_at IS NOT NULL AND isfinite(provider_created_at)
            AND adopted_at IS NOT NULL AND isfinite(adopted_at) AND adopted_available_balance_cents IS NOT NULL)),
    CHECK ((state <> 'issued' AND stripe_credit_grant_id IS NULL AND issuance_evidence IS NULL AND issued_at IS NULL)
        OR (state = 'issued' AND stripe_credit_grant_id IS NOT NULL AND issued_at IS NOT NULL
            AND issuance_evidence IS NOT NULL AND jsonb_typeof(issuance_evidence) = 'object' AND issuance_evidence <> '{}'::jsonb))
);

-- Calculate each boundary from the original anchor so February never shifts March.
CREATE FUNCTION billing_anniversary_boundary(anchor timestamptz, month_offset integer)
RETURNS timestamptz LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT ((anchor AT TIME ZONE 'UTC') + make_interval(months => month_offset)) AT TIME ZONE 'UTC';
$$;

CREATE FUNCTION billing_entitlement_period(anchor timestamptz, at_time timestamptz)
RETURNS TABLE(period_start timestamptz, period_end timestamptz) LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE m integer; s timestamptz;
BEGIN
    IF NOT isfinite(anchor) OR NOT isfinite(at_time) OR at_time < anchor THEN RETURN; END IF;
    m := (extract(year FROM at_time AT TIME ZONE 'UTC')::integer - extract(year FROM anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM at_time AT TIME ZONE 'UTC')::integer - extract(month FROM anchor AT TIME ZONE 'UTC')::integer;
    s := billing_anniversary_boundary(anchor, m);
    IF s > at_time THEN m := m - 1; END IF;
    RETURN QUERY SELECT billing_anniversary_boundary(anchor, m), billing_anniversary_boundary(anchor, m + 1);
END;
$$;

CREATE FUNCTION guard_billing_commercial_contract() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE months integer;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'commercial contract history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM 1 FROM team_billing_account WHERE team_id = NEW.team_id
            AND stripe_customer_id = NEW.customer_id AND stripe_subscription_id = NEW.subscription_id
            AND commercial_billing_anchor = NEW.entitlement_anchor FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION 'commercial contract billing association or anniversary differs'; END IF;
        IF NEW.starts_at IS DISTINCT FROM
            (SELECT period_start FROM billing_entitlement_period(NEW.entitlement_anchor, NEW.starts_at)) THEN
            RAISE EXCEPTION 'contract must start on its billing anniversary';
        END IF;
        IF EXISTS (SELECT 1 FROM billing_commercial_contract previous WHERE previous.subscription_id = NEW.subscription_id
            AND (previous.team_id, previous.customer_id) IS DISTINCT FROM (NEW.team_id, NEW.customer_id)) THEN
            RAISE EXCEPTION 'subscription history belongs to another billing account';
        END IF;
        IF NEW.charge_kind = 'upfront' AND (NEW.ends_at IS NULL OR NEW.ends_at IS DISTINCT FROM
            billing_anniversary_boundary(NEW.entitlement_anchor, NEW.charge_interval_months +
                (extract(year FROM NEW.starts_at AT TIME ZONE 'UTC')::integer - extract(year FROM NEW.entitlement_anchor AT TIME ZONE 'UTC')::integer) * 12
                + extract(month FROM NEW.starts_at AT TIME ZONE 'UTC')::integer - extract(month FROM NEW.entitlement_anchor AT TIME ZONE 'UTC')::integer)) THEN
            RAISE EXCEPTION 'upfront payment requires a bounded service term';
        END IF;
        IF NEW.status <> 'pending' OR NEW.revision <> 0 OR NEW.collection_checked_at IS NOT NULL THEN
            RAISE EXCEPTION 'commercial contracts must begin pending';
        END IF;
    ELSE
        IF (to_jsonb(NEW) - ARRAY['status','ends_at','collection_has_overdue_balance','collection_checked_at','collection_valid_until','collection_evidence','revision'])
            IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status','ends_at','collection_has_overdue_balance','collection_checked_at','collection_valid_until','collection_evidence','revision']) THEN
            RAISE EXCEPTION 'commercial terms are immutable';
        END IF;
        IF NEW.revision <> OLD.revision + 1 OR OLD.status = 'ended'
            OR (OLD.status = 'active' AND NEW.status = 'pending') THEN
            RAISE EXCEPTION 'invalid commercial contract transition';
        END IF;
        IF (NEW.collection_has_overdue_balance, NEW.collection_checked_at, NEW.collection_valid_until, NEW.collection_evidence)
            IS DISTINCT FROM (OLD.collection_has_overdue_balance, OLD.collection_checked_at, OLD.collection_valid_until, OLD.collection_evidence)
            AND (NEW.collection_checked_at IS NULL OR NEW.collection_checked_at > clock_timestamp()
                OR NEW.collection_checked_at <= COALESCE(OLD.collection_checked_at, '-infinity'::timestamptz)) THEN
            RAISE EXCEPTION 'collection observation must advance';
        END IF;
        IF OLD.ends_at IS NOT NULL AND (NEW.ends_at IS NULL OR NEW.ends_at > OLD.ends_at) THEN
            RAISE EXCEPTION 'contract end cannot be extended';
        END IF;
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NEW.entitlement_cadence = 'scheduled' THEN
            months := (extract(year FROM NEW.ends_at AT TIME ZONE 'UTC')::integer - extract(year FROM NEW.starts_at AT TIME ZONE 'UTC')::integer) * 12
                + extract(month FROM NEW.ends_at AT TIME ZONE 'UTC')::integer - extract(month FROM NEW.starts_at AT TIME ZONE 'UTC')::integer;
            IF NEW.ends_at IS NULL OR months <= 0 OR (SELECT count(*) FROM billing_contract_entitlement_schedule WHERE contract_id = NEW.id) <> months
                OR EXISTS (SELECT 1 FROM billing_contract_entitlement_schedule WHERE contract_id = NEW.id AND month_offset >= months) THEN
                RAISE EXCEPTION 'scheduled contract requires every monthly amount before activation';
            END IF;
        END IF;
        IF OLD.status = 'pending' AND NEW.status = 'active' AND NOT EXISTS (
            SELECT 1 FROM billing_contract_payment p WHERE p.contract_id = NEW.id
                AND p.service_period_start <= clock_timestamp() AND p.service_period_end > clock_timestamp()) THEN
            RAISE EXCEPTION 'activation requires verified base payment coverage';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_commercial_contract_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_commercial_contract
    FOR EACH ROW EXECUTE FUNCTION guard_billing_commercial_contract();

CREATE FUNCTION guard_billing_contract_schedule() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; first_month integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'entitlement schedule is immutable'; END IF;
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR UPDATE;
    first_month := (extract(year FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(year FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(month FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer;
    IF c.status <> 'pending' OR c.entitlement_cadence <> 'scheduled' OR c.ends_at IS NULL
        OR billing_anniversary_boundary(c.entitlement_anchor, first_month + NEW.month_offset + 1) > c.ends_at
        OR c.ends_at IS DISTINCT FROM (SELECT period_start FROM billing_entitlement_period(c.entitlement_anchor, c.ends_at)) THEN
        RAISE EXCEPTION 'schedule must be defined within the pending contract term';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_contract_schedule_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_contract_entitlement_schedule
    FOR EACH ROW EXECUTE FUNCTION guard_billing_contract_schedule();

CREATE FUNCTION billing_contract_entitlement(c billing_commercial_contract, at_time timestamptz)
RETURNS TABLE(period_start timestamptz, period_end timestamptz, amount_cents bigint) LANGUAGE sql STABLE AS $$
    SELECT p.period_start, p.period_end, CASE c.entitlement_cadence WHEN 'monthly' THEN c.entitlement_amount_cents ELSE s.amount_cents END
    FROM billing_entitlement_period(c.entitlement_anchor, at_time) p
    LEFT JOIN billing_contract_entitlement_schedule s ON s.contract_id = c.id AND s.month_offset =
        (extract(year FROM p.period_start AT TIME ZONE 'UTC')::integer - extract(year FROM c.starts_at AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM p.period_start AT TIME ZONE 'UTC')::integer - extract(month FROM c.starts_at AT TIME ZONE 'UTC')::integer
    WHERE p.period_start >= c.starts_at AND (c.ends_at IS NULL OR p.period_end <= c.ends_at)
        AND (c.entitlement_cadence = 'monthly' OR s.amount_cents IS NOT NULL);
$$;

CREATE FUNCTION guard_billing_contract_payment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; m integer; first_month integer;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'base payment evidence is immutable'; END IF;
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR SHARE;
    IF (NEW.customer_id, NEW.subscription_id, NEW.base_price_id, NEW.currency, NEW.base_amount_paid_cents)
        IS DISTINCT FROM (c.customer_id, CASE c.charge_kind WHEN 'subscription' THEN c.subscription_id ELSE NULL END, c.base_price_id, c.currency, c.charge_amount_cents) THEN
        RAISE EXCEPTION 'base payment does not match commercial terms';
    END IF;
    IF c.charge_kind = 'upfront' AND ((NEW.service_period_start, NEW.service_period_end) IS DISTINCT FROM (c.starts_at, c.ends_at)
        OR NEW.evidence->'parent' IS DISTINCT FROM 'null'::jsonb) THEN
        RAISE EXCEPTION 'upfront receipt requires standalone invoice and exact contract term';
    END IF;
    IF c.status = 'ended' OR NEW.service_period_start < c.starts_at OR NEW.paid_at > clock_timestamp()
        OR NEW.verified_at > clock_timestamp() THEN RAISE EXCEPTION 'invalid base payment period or verification time'; END IF;
    m := (extract(year FROM NEW.service_period_start AT TIME ZONE 'UTC')::integer - extract(year FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM NEW.service_period_start AT TIME ZONE 'UTC')::integer - extract(month FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer;
    first_month := (extract(year FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(year FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer) * 12
        + extract(month FROM c.starts_at AT TIME ZONE 'UTC')::integer - extract(month FROM c.entitlement_anchor AT TIME ZONE 'UTC')::integer;
    IF (m - first_month) % c.charge_interval_months <> 0
        OR NEW.service_period_start <> billing_anniversary_boundary(c.entitlement_anchor, m)
        OR NEW.service_period_end <> billing_anniversary_boundary(c.entitlement_anchor, m + c.charge_interval_months) THEN
        RAISE EXCEPTION 'base payment service period differs from contract cadence';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_contract_payment_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_contract_payment
    FOR EACH ROW EXECUTE FUNCTION guard_billing_contract_payment();

-- The observer must refresh this snapshot after retrieving all open invoices.
-- Its revision is captured before the provider read, then compared on update.
-- Validity must end at the earliest upcoming payment deadline or in five minutes,
-- whichever comes first; this is evidence freshness, not a payment grace period.
CREATE FUNCTION billing_contract_eligible(c billing_commercial_contract, s timestamptz, e timestamptz)
RETURNS boolean LANGUAGE sql VOLATILE AS $$
    SELECT c.status = 'active' AND c.collection_has_overdue_balance IS FALSE
        AND c.collection_checked_at IS NOT NULL AND c.collection_valid_until > clock_timestamp() AND c.starts_at <= s
        AND (c.ends_at IS NULL OR c.ends_at >= e)
        AND EXISTS (SELECT 1 FROM billing_contract_payment p WHERE p.contract_id = c.id
            AND p.service_period_start <= s AND p.service_period_end >= e)
        AND EXISTS (SELECT 1 FROM team_billing_account a WHERE a.team_id = c.team_id
            AND a.stripe_customer_id = c.customer_id AND a.stripe_subscription_id = c.subscription_id);
$$;

-- Adopt before activation, atomically reserving the period so workers cannot
-- race an existing provider grant with a new create/replay path.
-- The caller must retrieve the grant and its available balance before this write.
CREATE FUNCTION billing_validate_entitlement_adoption(v billing_usage_entitlement) RETURNS void LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; evidence jsonb := v.issuance_evidence;
BEGIN
    SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id = v.contract_id FOR UPDATE;
    IF c.status <> 'pending'
        OR NOT EXISTS (SELECT 1 FROM billing_contract_payment p WHERE p.id = v.payment_id AND p.contract_id = c.id
            AND p.service_period_start <= v.period_start AND p.service_period_end >= v.period_end)
        OR NOT EXISTS (SELECT 1 FROM team_billing_account a WHERE a.team_id = c.team_id
            AND a.stripe_customer_id = c.customer_id AND a.stripe_subscription_id = c.subscription_id)
        OR v.period_start > clock_timestamp() OR v.period_end <= clock_timestamp()
        OR v.adopted_at > clock_timestamp() OR v.adopted_at < clock_timestamp() - interval '1 minute'
        OR v.provider_created_at <> date_trunc('second', v.provider_created_at)
        OR v.provider_created_at > v.adopted_at OR v.provider_created_at < c.starts_at
        OR v.issued_at IS DISTINCT FROM v.provider_created_at
        OR (evidence->>'created')::bigint IS DISTINCT FROM extract(epoch FROM v.provider_created_at)::bigint
        OR evidence->>'id' IS DISTINCT FROM v.stripe_credit_grant_id
        OR evidence->>'customer' IS DISTINCT FROM c.customer_id
        OR evidence->>'category' IS DISTINCT FROM 'promotional'
        OR evidence #>> '{amount,type}' IS DISTINCT FROM 'monetary'
        OR evidence #>> '{amount,monetary,currency}' IS DISTINCT FROM v.currency
        OR (evidence #>> '{amount,monetary,value}')::bigint IS DISTINCT FROM v.amount_cents
        OR (evidence->>'available_balance_cents')::bigint IS DISTINCT FROM v.adopted_available_balance_cents
        OR evidence #>> '{metadata,superserve_offer}' IS DISTINCT FROM c.offer_key
        OR evidence #>> '{metadata,superserve_contract_version}' IS DISTINCT FROM '1'
        OR evidence #>> '{metadata,superserve_object_role}' IS DISTINCT FROM 'monthly_usage_entitlement'
        OR evidence #>> '{metadata,superserve_team_id}' IS DISTINCT FROM v.team_id::text
        OR evidence #>> '{metadata,superserve_contract_id}' IS DISTINCT FROM v.contract_id::text
        OR evidence #>> '{metadata,superserve_entitlement}' IS DISTINCT FROM
            v.contract_id::text || ':usage:' || extract(epoch FROM v.period_start)::bigint::text || ':' || extract(epoch FROM v.period_end)::bigint::text
        OR (evidence #>> '{metadata,superserve_period_start}')::bigint IS DISTINCT FROM extract(epoch FROM v.period_start)::bigint
        OR (evidence #>> '{metadata,superserve_period_end}')::bigint IS DISTINCT FROM extract(epoch FROM v.period_end)::bigint
        OR (evidence->>'effective_at')::bigint < extract(epoch FROM v.provider_invoice_start)::bigint + 1
        OR (evidence->>'effective_at')::bigint < extract(epoch FROM v.provider_created_at)::bigint
        OR (evidence->>'effective_at')::bigint > ceil(extract(epoch FROM v.adopted_at))::bigint
        OR evidence->>'effective_at' IS NULL
        OR (evidence->>'expires_at')::bigint IS DISTINCT FROM extract(epoch FROM v.provider_invoice_end)::bigint + 1
        OR jsonb_typeof(evidence #> '{applicability_config,scope,prices}') IS DISTINCT FROM 'array'
        OR jsonb_array_length(evidence #> '{applicability_config,scope,prices}') = 0
        OR evidence #> '{applicability_config,scope,price_type}' IS NOT NULL THEN
        RAISE EXCEPTION 'adopted grant does not match the entitlement';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM billing_invoice_calendar cal WHERE cal.team_id = v.team_id
        AND cal.period_start = v.period_start AND cal.period_end = v.period_end
        AND cal.customer_id = c.customer_id AND cal.subscription_id = c.subscription_id
        AND cal.invoice_start = v.provider_invoice_start AND cal.invoice_end = v.provider_invoice_end)
        OR v.provider_invoice_start <> date_trunc('second', v.provider_invoice_start)
        OR v.provider_invoice_end <> date_trunc('second', v.provider_invoice_end)
        OR v.provider_invoice_start >= v.period_end OR v.provider_invoice_end < v.period_end THEN
        RAISE EXCEPTION 'adopted grant differs from the authoritative calendar';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(evidence #> '{applicability_config,scope,prices}') price
        WHERE jsonb_typeof(price->'id') IS DISTINCT FROM 'string' OR btrim(price->>'id') = '' OR price->>'id' = c.base_price_id) THEN
        RAISE EXCEPTION 'adopted grant price scope is invalid';
    END IF;
END;
$$;

CREATE FUNCTION guard_billing_usage_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c billing_commercial_contract; p billing_contract_payment; s timestamptz; e timestamptz; amount bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'entitlement history is immutable'; END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO STRICT c FROM billing_commercial_contract WHERE team_id = NEW.team_id AND id = NEW.contract_id FOR UPDATE;
        SELECT * INTO STRICT p FROM billing_contract_payment WHERE team_id = NEW.team_id AND contract_id = NEW.contract_id AND id = NEW.payment_id;
        SELECT period_start, period_end, amount_cents INTO s, e, amount FROM billing_contract_entitlement(c, clock_timestamp());
        IF (NEW.kind, NEW.amount_cents, NEW.currency)
            IS DISTINCT FROM (c.entitlement_kind, amount, c.currency)
            OR p.service_period_start > NEW.period_start OR p.service_period_end < NEW.period_end THEN
            RAISE EXCEPTION 'entitlement lacks eligible paid contract';
        END IF;
        IF s IS NULL OR (NEW.period_start, NEW.period_end) IS DISTINCT FROM (s, e) THEN
            RAISE EXCEPTION 'only the current anniversary period can be claimed';
        END IF;
        IF NEW.issuance_source = 'adopted' AND NEW.state = 'issued' THEN
            PERFORM billing_validate_entitlement_adoption(NEW);
        ELSIF NEW.issuance_source <> 'created' OR NEW.state <> 'pending' OR NOT billing_contract_eligible(c, NEW.period_start, NEW.period_end) THEN
            RAISE EXCEPTION 'entitlement lacks eligible paid contract';
        END IF;
    ELSE
        IF (to_jsonb(NEW) - ARRAY['state','first_attempt_at','request_payload','provider_invoice_start','provider_invoice_end','stripe_credit_grant_id','issuance_evidence','issued_at','issuance_source','provider_created_at','adopted_at','adopted_available_balance_cents'])
            IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','first_attempt_at','request_payload','provider_invoice_start','provider_invoice_end','stripe_credit_grant_id','issuance_evidence','issued_at','issuance_source','provider_created_at','adopted_at','adopted_available_balance_cents']) THEN
            RAISE EXCEPTION 'entitlement terms and identity are immutable';
        END IF;
        IF OLD.state = 'issued' THEN RAISE EXCEPTION 'issued entitlement is immutable'; END IF;
        IF NEW.issuance_source IS DISTINCT FROM OLD.issuance_source THEN
            RAISE EXCEPTION 'adoption cannot replace an issuance intent';
        END IF;
        IF OLD.state = 'uncertain' THEN
            IF NEW.state NOT IN ('uncertain','issued') OR
                (NEW.first_attempt_at, NEW.request_payload, NEW.provider_invoice_start, NEW.provider_invoice_end)
                IS DISTINCT FROM (OLD.first_attempt_at, OLD.request_payload, OLD.provider_invoice_start, OLD.provider_invoice_end) THEN
                RAISE EXCEPTION 'possible Stripe success must retain its original request';
            END IF;
        ELSIF NEW.state <> 'uncertain' THEN
            RAISE EXCEPTION 'issuance must record a possible external write before confirmation';
        ELSE
            SELECT * INTO STRICT c FROM billing_commercial_contract WHERE id = NEW.contract_id FOR UPDATE;
            IF NOT billing_contract_eligible(c, NEW.period_start, NEW.period_end)
                OR clock_timestamp() < NEW.period_start OR clock_timestamp() >= NEW.period_end
                OR NEW.first_attempt_at > clock_timestamp() OR NEW.first_attempt_at < clock_timestamp() - interval '1 minute' THEN
                RAISE EXCEPTION 'entitlement is not eligible for issuance';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM billing_invoice_calendar cal WHERE cal.team_id = NEW.team_id
                AND cal.period_start = NEW.period_start AND cal.period_end = NEW.period_end
                AND cal.customer_id = c.customer_id AND cal.subscription_id = c.subscription_id
                AND cal.invoice_start = NEW.provider_invoice_start AND cal.invoice_end = NEW.provider_invoice_end) THEN
                RAISE EXCEPTION 'grant invoice boundaries differ from the authoritative calendar';
            END IF;
            IF NEW.provider_invoice_start <> date_trunc('second', NEW.provider_invoice_start)
                OR NEW.provider_invoice_end <> date_trunc('second', NEW.provider_invoice_end)
                OR NEW.provider_invoice_start >= NEW.period_end OR NEW.provider_invoice_end < NEW.period_end
                OR (NEW.request_payload->>'customer') IS DISTINCT FROM c.customer_id
                OR (NEW.request_payload->>'category') IS DISTINCT FROM 'promotional'
                OR (NEW.request_payload #>> '{amount,type}') IS DISTINCT FROM 'monetary'
                OR (NEW.request_payload #>> '{amount,monetary,currency}') IS DISTINCT FROM NEW.currency
                OR (NEW.request_payload #>> '{amount,monetary,value}')::bigint IS DISTINCT FROM NEW.amount_cents
                OR (NEW.request_payload #>> '{metadata,entitlement_id}') IS DISTINCT FROM NEW.id::text
                OR (NEW.request_payload->>'expires_at')::bigint IS DISTINCT FROM extract(epoch FROM NEW.provider_invoice_end)::bigint + 1
                OR (NEW.request_payload->>'effective_at')::bigint IS DISTINCT FROM greatest(ceil(extract(epoch FROM NEW.first_attempt_at))::bigint, extract(epoch FROM NEW.provider_invoice_start)::bigint + 1)
                OR (NEW.request_payload->>'effective_at')::bigint > extract(epoch FROM NEW.provider_invoice_end)::bigint
                OR jsonb_typeof(NEW.request_payload #> '{applicability_config,scope,prices}') IS DISTINCT FROM 'array'
                OR jsonb_array_length(NEW.request_payload #> '{applicability_config,scope,prices}') = 0
                OR NEW.request_payload #> '{applicability_config,scope,price_type}' IS NOT NULL THEN
                RAISE EXCEPTION 'grant request does not match entitlement or mapped invoice';
            END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.request_payload #> '{applicability_config,scope,prices}') price
                WHERE jsonb_typeof(price->'id') IS DISTINCT FROM 'string' OR btrim(price->>'id') = '' OR price->>'id' = c.base_price_id) THEN
                RAISE EXCEPTION 'grant price scope is invalid';
            END IF;
        END IF;
        IF NEW.state = 'issued' AND (
            NEW.issuance_evidence->>'id' IS DISTINCT FROM NEW.stripe_credit_grant_id
            OR NEW.issuance_evidence->'customer' IS DISTINCT FROM NEW.request_payload->'customer'
            OR NEW.issuance_evidence->'amount' IS DISTINCT FROM NEW.request_payload->'amount'
            OR NEW.issuance_evidence->'category' IS DISTINCT FROM NEW.request_payload->'category'
            OR NEW.issuance_evidence->'effective_at' IS DISTINCT FROM NEW.request_payload->'effective_at'
            OR NEW.issuance_evidence->'expires_at' IS DISTINCT FROM NEW.request_payload->'expires_at'
            OR NEW.issuance_evidence->'applicability_config' IS DISTINCT FROM NEW.request_payload->'applicability_config'
            OR NEW.issuance_evidence #>> '{metadata,entitlement_id}' IS DISTINCT FROM NEW.id::text
            OR NEW.issued_at > clock_timestamp() OR NEW.issued_at < NEW.first_attempt_at) THEN
            RAISE EXCEPTION 'grant confirmation does not match the frozen request';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_usage_entitlement_guard BEFORE INSERT OR UPDATE OR DELETE ON billing_usage_entitlement
    FOR EACH ROW EXECUTE FUNCTION guard_billing_usage_entitlement();

-- No browser role may read or write these records or invoke their functions.
DO $$
DECLARE t text; r text; f regprocedure;
BEGIN
    FOREACH t IN ARRAY ARRAY['billing_commercial_contract','billing_contract_entitlement_schedule','billing_contract_payment','billing_usage_entitlement'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC', t);
        FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                EXECUTE format('REVOKE ALL ON TABLE %I FROM %I', t, r);
                IF r = 'service_role' THEN
                    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I TO service_role', t);
                    EXECUTE format('CREATE POLICY commercial_backend ON %I TO service_role USING (true) WITH CHECK (true)', t);
                END IF;
            END IF;
        END LOOP;
    END LOOP;
    FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace = 'public'::regnamespace
        AND proname IN ('billing_anniversary_boundary','billing_entitlement_period','billing_contract_eligible',
            'guard_billing_commercial_contract','guard_billing_contract_payment','guard_billing_usage_entitlement',
            'guard_billing_contract_schedule','billing_contract_entitlement','billing_validate_entitlement_adoption') LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f, r);
                IF r = 'service_role' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f); END IF;
            END IF;
        END LOOP;
    END LOOP;
END;
$$;
