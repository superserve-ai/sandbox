DO $$
DECLARE
    relation record;
    has_rows boolean;
    schema_fingerprint text;
    original_catalog jsonb;
    original_limits jsonb;
    removed_count integer;
    guard_count integer;
BEGIN
    PERFORM set_config('search_path', 'pg_catalog, public', true);
    PERFORM set_config('row_security', 'off', true);

    LOCK TABLE pg_catalog.pg_namespace, pg_catalog.pg_class, pg_catalog.pg_attribute,
        pg_catalog.pg_proc, pg_catalog.pg_trigger, pg_catalog.pg_constraint,
        pg_catalog.pg_rewrite IN SHARE MODE NOWAIT;

    FOR relation IN
        SELECT c.oid, n.nspname, c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE (n.nspname = 'public' OR (n.nspname = 'supabase_migrations'
            AND c.relname = 'schema_migrations')) AND c.relkind IN ('r', 'p', 'm')
        ORDER BY c.oid
    LOOP
        EXECUTE format('LOCK TABLE ONLY %I.%I IN ACCESS EXCLUSIVE MODE NOWAIT', relation.nspname, relation.relname);
    END LOOP;

    IF NOT EXISTS (SELECT 1 FROM public.billing_plan WHERE family = 'starter'
        OR offer_key IN ('starter_monthly', 'starter_annual')) THEN
        RETURN;
    END IF;

    SELECT md5(string_agg(format('%s:%s:%s:%s:%s:%s', c.relname, c.relkind,
        a.attnum, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull),
        ',' ORDER BY c.relname, a.attnum)) INTO schema_fingerprint
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f');

    IF schema_fingerprint IS NULL OR schema_fingerprint NOT IN (
        '864226d10c5c2f1f7cb04a2e45155030', 'd4ade84aa27a5aff64b1d2e06428e88b')
        OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE left(n.nspname, 3) <> 'pg_' AND n.nspname NOT IN ('public', 'information_schema')
                AND NOT (n.nspname = 'supabase_migrations' AND c.relname = 'schema_migrations')
                AND c.relkind IN ('r', 'p', 'm', 'f')) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation requires a recognized schema';
    END IF;

    IF to_regclass('supabase_migrations.schema_migrations') IS NOT NULL AND (
        (SELECT array_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text ORDER BY a.attnum)
            FROM pg_attribute a WHERE a.attrelid = to_regclass('supabase_migrations.schema_migrations')
                AND a.attnum > 0 AND NOT a.attisdropped)
            IS DISTINCT FROM ARRAY['version:text:true', 'statements:text[]:false', 'name:text:false']::text[]
        OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass('supabase_migrations.schema_migrations')
            AND relkind = 'r' AND NOT relrowsecurity AND NOT relforcerowsecurity)
        OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = to_regclass('supabase_migrations.schema_migrations') AND NOT tgisinternal)
        OR EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class = to_regclass('supabase_migrations.schema_migrations'))
        OR (SELECT array_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint
            WHERE conrelid = to_regclass('supabase_migrations.schema_migrations'))
            IS DISTINCT FROM ARRAY['PRIMARY KEY (version)']::text[]
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses unknown migration bookkeeping';
    END IF;

    IF (SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM public.billing_plan p
        WHERE family = 'starter' OR offer_key IN ('starter_monthly', 'starter_annual')) IS DISTINCT FROM
        '[{"offer_key":"starter_annual","family":"starter","display_name":"Starter","charge_interval_months":12,"charge_amount_cents":100000,"monthly_credit_cents":10000,"available":false,"sort_order":11},{"offer_key":"starter_monthly","family":"starter","display_name":"Starter","charge_interval_months":1,"charge_amount_cents":10000,"monthly_credit_cents":10000,"available":false,"sort_order":10}]'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses altered or partial seeds';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_constraint WHERE contype = 'f' AND confrelid = 'public.billing_plan'::regclass)
        OR EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class = 'public.billing_plan'::regclass) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses catalog dependencies';
    END IF;

    SELECT count(*) INTO guard_count FROM pg_trigger
    WHERE tgrelid = 'public.billing_plan'::regclass AND NOT tgisinternal;
    IF (guard_count = 0 AND EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.billing_plan'::regclass AND contype = 'f'))
        OR (guard_count <> 0 AND (guard_count <> 2 OR
        (SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
            WHERE t.tgrelid = 'public.billing_plan'::regclass AND NOT t.tgisinternal
                AND t.tgenabled = 'O' AND t.tgnargs = 0 AND t.tgqual IS NULL
                AND md5(p.prosrc) = '6dde1882c668344208e6c020b81a778a'
                AND p.pronamespace = 'public'::regnamespace
                AND ((t.tgname = 'billing_plan_identity_guard' AND t.tgtype = 27
                    AND t.tgattr::text = '1')
                    OR (t.tgname = 'billing_plan_truncate_guard' AND t.tgtype = 34
                        AND t.tgattr::text = ''))) <> 2)) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses unknown catalog guards';
    END IF;

    IF (SELECT jsonb_agg(to_jsonb(t) - 'next_run_at') FROM public.billing_export_discovery t)
            IS DISTINCT FROM '[{"singleton":true,"after_team":null,"reset_existing":true}]'::jsonb
        OR (SELECT jsonb_agg(to_jsonb(t)) FROM public.billing_funding_policy t)
            IS DISTINCT FROM '[{"singleton":true,"max_observed_teams":4}]'::jsonb
        OR (SELECT jsonb_agg(to_jsonb(t)) FROM public.billing_invoice_collection_scheduler t)
            IS DISTINCT FROM '[{"id":true}]'::jsonb
        OR (SELECT jsonb_agg(to_jsonb(t) - 'next_run_at') FROM public.billing_period_close_discovery t)
            IS DISTINCT FROM '[{"singleton":true,"after_team":"00000000-0000-0000-0000-000000000000","after_start":"-infinity","after_end":"-infinity"}]'::jsonb
        OR (SELECT jsonb_agg(to_jsonb(t) - 'updated_at') FROM public.promotion_device_policy t)
            IS DISTINCT FROM '[{"singleton":true,"device_enforced":false,"evidence_required":false}]'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses changed financial control state';
    END IF;

    FOR relation IN
        SELECT c.oid, c.relname,
            c.relname ~ '(billing|stripe|checkout|payment|contract|entitlement|invoice|audit|history|journal|credit|ledger|grant|funding|recharge|evidence)'
            OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid
                AND a.attnum > 0 AND NOT a.attisdropped
                AND a.attname ~ '(stripe|checkout|subscription|invoice|contract|payment|entitlement|request_payload|evidence)') AS financial
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm')
            AND c.relname NOT IN ('billing_plan', 'plan_limits')
        ORDER BY c.oid
    LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I t WHERE to_jsonb(t)::text ~ %L)',
            relation.relname, 'starter_monthly|starter_annual') INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation refuses semantic references';
        END IF;
        IF relation.financial AND relation.relname NOT IN ('billing_export_discovery',
            'billing_funding_policy', 'billing_invoice_collection_scheduler',
            'billing_period_close_discovery', 'promotion_device_policy') THEN
            EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I)', relation.relname) INTO has_rows;
            IF has_rows THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation requires empty financial and provider history';
            END IF;
        END IF;
    END LOOP;

    SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) INTO original_catalog
    FROM public.billing_plan p WHERE offer_key NOT IN ('starter_monthly', 'starter_annual');
    SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) INTO original_limits FROM public.plan_limits p;

    IF guard_count = 2 THEN
        ALTER TABLE public.billing_plan DISABLE TRIGGER billing_plan_identity_guard;
    END IF;
    DELETE FROM public.billing_plan WHERE offer_key IN ('starter_monthly', 'starter_annual');
    GET DIAGNOSTICS removed_count = ROW_COUNT;
    IF guard_count = 2 THEN
        ALTER TABLE public.billing_plan ENABLE TRIGGER billing_plan_identity_guard;
    END IF;

    IF removed_count <> 2
        OR (SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM public.billing_plan p) IS DISTINCT FROM original_catalog
        OR (SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM public.plan_limits p) IS DISTINCT FROM original_limits THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'obsolete catalog reconciliation changed preserved state';
    END IF;
END;
$$;
