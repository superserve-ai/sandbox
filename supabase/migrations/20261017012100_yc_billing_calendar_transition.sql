-- Regional billing databases only. Retain the old interval and its authority;
-- never use the historical cutover's discard/finalize behavior for YC adoption.
CREATE TABLE billing_yc_calendar_transition (
    operation_id uuid PRIMARY KEY REFERENCES billing_yc_operation(id),
    team_id uuid NOT NULL UNIQUE REFERENCES team(id),
    anniversary timestamptz NOT NULL,
    previous_anchor timestamptz,
    previous_account jsonb NOT NULL,
    shortened_periods jsonb NOT NULL,
    approved_by text NOT NULL,
    evidence_reference text NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE billing_yc_calendar_transition ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION guard_yc_calendar_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'YC calendar transition evidence is immutable';
END $$;
CREATE TRIGGER billing_yc_calendar_transition_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
ON billing_yc_calendar_transition FOR EACH STATEMENT EXECUTE FUNCTION guard_yc_calendar_receipt();

-- These records have no period foreign key. A key-share lock gives their
-- writers the same protection as FK-backed close work, mappings and exports.
-- After a key change, recheck the receipt with a fresh READ COMMITTED snapshot
-- so a writer waiting on the old key cannot recreate a straddling record.
CREATE FUNCTION fence_yc_calendar_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_team uuid; s timestamptz; e timestamptz; boundary timestamptz; has_period boolean := true;
BEGIN
    IF TG_TABLE_NAME IN ('billing_entitlement_withheld','billing_entitlement_debt') THEN
        SELECT team_id INTO STRICT owner_team FROM billing_commercial_contract WHERE id=NEW.contract_id FOR UPDATE;
    ELSE
        owner_team := NEW.team_id;
    END IF;
    IF TG_TABLE_NAME = 'billing_entitlement_debt' THEN
        s := NEW.period_start;
        SELECT period_end INTO e FROM billing_commercial_contract c,
            LATERAL billing_entitlement_period(c.entitlement_anchor,s) WHERE c.id=NEW.contract_id;
    ELSIF TG_TABLE_NAME = 'team_credit_ledger' THEN
        s := NEW.billing_period_start; e := NEW.billing_period_end;
    ELSE
        s := NEW.period_start; e := NEW.period_end;
    END IF;
    IF s IS NULL OR e IS NULL THEN RETURN NEW; END IF;
    IF TG_TABLE_NAME = 'team_billing_period' THEN
        IF TG_OP = 'INSERT' THEN
            IF NOT EXISTS (SELECT 1 FROM team_billing_period WHERE team_id=owner_team AND period_start=s AND period_end=e) THEN
                -- Fence stale future-calendar inserts, even when they do not
                -- overlap any period materialized by this reconciliation yet.
                PERFORM 1 FROM team_billing_account WHERE team_id=owner_team FOR SHARE;
            END IF;
        ELSIF (NEW.team_id,NEW.period_start,NEW.period_end) IS DISTINCT FROM (OLD.team_id,OLD.period_start,OLD.period_end) THEN
            -- A key editor already owns the period row: do not wait in the
            -- inverse order against an account-first transition.
            PERFORM 1 FROM team_billing_account WHERE team_id=owner_team FOR SHARE NOWAIT;
        END IF;
    END IF;
    IF TG_TABLE_NAME IN ('billing_usage_entitlement','billing_entitlement_withheld','billing_entitlement_debt') THEN
        -- Entitlement claims already lock their contract before inserting.
        PERFORM 1 FROM billing_commercial_contract WHERE id=NEW.contract_id FOR UPDATE;
    ELSIF TG_TABLE_NAME = 'billing_usage_export' THEN
        -- The existing cumulative fence takes UPDATE; avoid a lock upgrade
        -- between simultaneous export writers.
        PERFORM 1 FROM team_billing_period p WHERE p.team_id=owner_team
            AND tstzrange(p.period_start,p.period_end,'[)') && tstzrange(s,e,'[)')
            ORDER BY p.period_start,p.period_end FOR UPDATE;
    ELSIF TG_TABLE_NAME <> 'team_billing_period' THEN
        PERFORM 1 FROM team_billing_period p WHERE p.team_id=owner_team
            AND tstzrange(p.period_start,p.period_end,'[)') && tstzrange(s,e,'[)')
            ORDER BY p.period_start,p.period_end FOR KEY SHARE;
    END IF;
    IF TG_TABLE_NAME <> 'team_billing_period' THEN
        SELECT EXISTS(SELECT 1 FROM team_billing_period p WHERE p.team_id=owner_team
            AND p.period_start=s AND p.period_end=e) INTO has_period;
        IF NOT has_period THEN
            -- Missing-parent writers also fence a not-yet-saved anniversary.
            -- They may already own period/contract locks, so never wait in
            -- the inverse order against account-first reconciliation.
            PERFORM 1 FROM team_billing_account WHERE team_id=owner_team FOR SHARE NOWAIT;
        END IF;
    END IF;
    SELECT anniversary INTO boundary FROM billing_yc_calendar_transition WHERE team_id=owner_team;
    IF boundary IS NULL AND NOT has_period THEN
        SELECT starts_at INTO boundary FROM billing_yc_operation WHERE team_id=owner_team;
    END IF;
    IF s >= boundary AND NOT EXISTS (
        SELECT 1 FROM billing_entitlement_period(boundary,s) b WHERE b.period_start=s AND b.period_end=e) THEN
        RAISE EXCEPTION 'yc_calendar_conflict: team %, period [%, %) does not match anniversary %; follow docs/billing/yc-calendar-recovery.md', owner_team,s,e,boundary;
    END IF;
    IF s < boundary AND e > boundary THEN
        RAISE EXCEPTION 'yc_calendar_conflict: team %, period [%, %) crosses YC anniversary %; reload periods and follow docs/billing/yc-calendar-recovery.md', owner_team,s,e,boundary
            USING ERRCODE='P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON team_billing_usage
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON billing_usage_export
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON team_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON billing_usage_entitlement
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON billing_entitlement_withheld
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON billing_entitlement_debt
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();
CREATE TRIGGER a_yc_calendar_fence BEFORE INSERT OR UPDATE ON team_billing_period
    FOR EACH ROW EXECUTE FUNCTION fence_yc_calendar_record();

CREATE FUNCTION reconcile_yc_billing_calendar(p_team uuid, p_operation uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    o billing_yc_operation; a team_billing_account; p team_billing_period;
    existing billing_yc_calendar_transition;
    boundary timestamptz; s timestamptz; e timestamptz;
    n integer := 0; reason text; snapshots jsonb := '[]'::jsonb; orphan record;
BEGIN
    -- Caller holds the webhook lease, then invoice advisory lock, then account.
    -- Existing contracts precede periods, matching entitlement claims; periods
    -- precede their dependent export/usage records.
    SELECT * INTO STRICT a FROM team_billing_account WHERE team_id=p_team FOR UPDATE;
    SELECT * INTO STRICT o FROM billing_yc_operation WHERE team_id=p_team AND id=p_operation;
    boundary := o.starts_at;
    IF boundary IS NULL OR o.ends_at IS NULL OR boundary > clock_timestamp()
        OR o.customer_id IS NULL OR o.subscription_id IS NULL THEN
        RAISE EXCEPTION 'YC calendar requires the saved provider anniversary and association';
    END IF;
    SELECT * INTO existing FROM billing_yc_calendar_transition WHERE team_id=p_team;
    IF FOUND THEN
        IF existing.operation_id <> o.id OR existing.anniversary <> boundary THEN
            RAISE EXCEPTION 'YC calendar receipt differs from saved operation';
        END IF;
    END IF;
    PERFORM 1 FROM billing_commercial_contract WHERE team_id=p_team ORDER BY id FOR UPDATE;
    -- Include historical prefixes: non-FK writers may overlap them without
    -- using an exact period key. Audit only after every such writer drains.
    PERFORM 1 FROM team_billing_period WHERE team_id=p_team
        ORDER BY period_start,period_end FOR UPDATE;
    -- A delayed retry materializes every elapsed month from the original
    -- anniversary, rather than leaving a gap before the current month.
    WHILE billing_anniversary_boundary(boundary,n+1) <= clock_timestamp() LOOP
        n := n+1;
    END LOOP;
    -- Legacy non-FK records retain authority even if a previous correction
    -- already made the period rows adjacent or materialized the new calendar.
    FOR orphan IN
        SELECT 'usage summary' kind,period_start s,period_end e FROM team_billing_usage WHERE team_id=p_team
        UNION ALL SELECT 'cumulative export',period_start,period_end FROM billing_usage_export WHERE team_id=p_team
        UNION ALL SELECT 'credit settlement',billing_period_start,billing_period_end FROM team_credit_ledger WHERE team_id=p_team AND billing_period_start IS NOT NULL
        UNION ALL SELECT 'usage entitlement',period_start,period_end FROM billing_usage_entitlement WHERE team_id=p_team
        UNION ALL SELECT 'entitlement withholding',u.period_start,u.period_end FROM billing_entitlement_withheld u
            JOIN billing_commercial_contract c ON c.id=u.contract_id WHERE c.team_id=p_team
        UNION ALL SELECT 'entitlement debt',u.period_start,b.period_end FROM billing_entitlement_debt u
            JOIN billing_commercial_contract c ON c.id=u.contract_id
            CROSS JOIN LATERAL billing_entitlement_period(c.entitlement_anchor,u.period_start) b WHERE c.team_id=p_team
    LOOP
        IF orphan.e > boundary AND NOT EXISTS (
            SELECT 1 FROM billing_entitlement_period(boundary,orphan.s) b
            WHERE b.period_start=orphan.s AND b.period_end=orphan.e) THEN
            RAISE EXCEPTION 'yc_calendar_conflict: team %, period [%, %), anniversary %: incompatible %; follow docs/billing/yc-calendar-recovery.md',
                p_team,orphan.s,orphan.e,boundary,orphan.kind;
        END IF;
    END LOOP;
    FOR p IN SELECT * FROM team_billing_period WHERE team_id=p_team
        AND period_end>boundary
        ORDER BY period_start,period_end FOR UPDATE
    LOOP
        -- Exact anniversary periods already have authority, including finalized
        -- history. Do not reopen them or rewrite their status on a retry.
        IF EXISTS (SELECT 1 FROM billing_entitlement_period(boundary,p.period_start) b
            WHERE p.period_start=b.period_start AND p.period_end=b.period_end) THEN
            CONTINUE;
        END IF;
        reason := NULL;
        IF NOT (p.period_start < boundary AND p.period_end > boundary) THEN
            reason := 'incompatible calendar';
        ELSIF p.status <> 'open' OR p.finalized_at IS NOT NULL OR p.exported_at IS NOT NULL
            OR p.approved_at IS NOT NULL OR p.approved_by IS NOT NULL OR p.approval_source IS NOT NULL
            OR p.blocked_at IS NOT NULL OR p.blocked_reason IS NOT NULL
            OR p.gross_charges_usd IS NOT NULL OR p.credits_applied_usd IS NOT NULL OR p.net_invoice_amount_usd IS NOT NULL THEN
            reason := 'period status, approval or financial settlement';
        ELSIF EXISTS (SELECT 1 FROM team_billing_usage u WHERE u.team_id=p_team
            AND tstzrange(u.period_start,u.period_end,'[)') && tstzrange(p.period_start,p.period_end,'[)')) THEN
            reason := 'usage summary';
        ELSIF EXISTS (SELECT 1 FROM billing_usage_export u WHERE u.team_id=p_team
            AND tstzrange(u.period_start,u.period_end,'[)') && tstzrange(p.period_start,p.period_end,'[)')) THEN
            reason := 'cumulative export';
        ELSIF EXISTS (SELECT 1 FROM team_credit_ledger u WHERE u.team_id=p_team
            AND tstzrange(u.billing_period_start,u.billing_period_end,'[)') && tstzrange(p.period_start,p.period_end,'[)')
            AND u.billing_period_start IS NOT NULL) THEN
            reason := 'credit settlement';
        ELSIF EXISTS (SELECT 1 FROM billing_usage_entitlement u WHERE u.team_id=p_team
            AND tstzrange(u.period_start,u.period_end,'[)') && tstzrange(p.period_start,p.period_end,'[)')) THEN
            reason := 'usage entitlement';
        ELSIF EXISTS (SELECT 1 FROM billing_entitlement_withheld u JOIN billing_commercial_contract c ON c.id=u.contract_id
            WHERE c.team_id=p_team AND tstzrange(u.period_start,u.period_end,'[)') && tstzrange(p.period_start,p.period_end,'[)'))
            OR EXISTS (SELECT 1 FROM billing_entitlement_debt u JOIN billing_commercial_contract c ON c.id=u.contract_id
            WHERE c.team_id=p_team AND u.period_start>=p.period_start AND u.period_start<p.period_end) THEN
            reason := 'entitlement withholding or debt evidence';
        ELSIF EXISTS (SELECT 1 FROM billing_incremental_period u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end)) THEN
            reason := 'incremental enrollment or exports';
        ELSIF EXISTS (SELECT 1 FROM billing_export_measurement u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end))
            OR EXISTS (SELECT 1 FROM billing_export_usage u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end)) THEN
            reason := 'export measurements';
        ELSIF EXISTS (SELECT 1 FROM billing_invoice_calendar u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end))
            OR EXISTS (SELECT 1 FROM billing_invoice_close u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end)) THEN
            reason := 'invoice mapping or close';
        ELSIF EXISTS (SELECT 1 FROM billing_period_close_work u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end)) THEN
            reason := 'close work';
        ELSIF EXISTS (SELECT 1 FROM billing_period_anomaly u WHERE (u.team_id,u.period_start,u.period_end)=(p.team_id,p.period_start,p.period_end)) THEN
            reason := 'billing review evidence';
        END IF;
        IF reason IS NOT NULL THEN
            RAISE EXCEPTION 'yc_calendar_conflict: team %, period [%, %), anniversary %: %; preserve authority and follow docs/billing/yc-calendar-recovery.md',
                p_team,p.period_start,p.period_end,boundary,reason USING ERRCODE='P0001';
        END IF;
        snapshots := snapshots || jsonb_build_array(to_jsonb(p));
        UPDATE team_billing_period SET period_end=boundary,updated_at=clock_timestamp()
            WHERE (team_id,period_start,period_end)=(p.team_id,p.period_start,p.period_end);
    END LOOP;
    FOR m IN 0..n LOOP
        s := billing_anniversary_boundary(boundary,m);
        e := billing_anniversary_boundary(boundary,m+1);
        INSERT INTO team_billing_period(team_id,period_start,period_end,status)
            VALUES(p_team,s,e,'open') ON CONFLICT(team_id,period_start,period_end) DO NOTHING;
    END LOOP;
    INSERT INTO billing_yc_calendar_transition(operation_id,team_id,anniversary,previous_anchor,previous_account,shortened_periods,approved_by,evidence_reference)
        VALUES(o.id,p_team,boundary,a.commercial_billing_anchor,to_jsonb(a),snapshots,o.approved_by,o.evidence_reference)
        ON CONFLICT(operation_id) DO NOTHING;
END $$;

REVOKE ALL ON FUNCTION reconcile_yc_billing_calendar(uuid,uuid) FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
        GRANT EXECUTE ON FUNCTION reconcile_yc_billing_calendar(uuid,uuid) TO service_role;
    END IF;
    FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
            EXECUTE format('REVOKE ALL ON billing_yc_calendar_transition FROM %I',r);
            EXECUTE format('REVOKE ALL ON FUNCTION reconcile_yc_billing_calendar(uuid,uuid) FROM %I',r);
        END IF;
    END LOOP;
END $$;
