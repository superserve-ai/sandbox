-- Adopt the concurrently prebuilt saved-snapshot indexes. Production and
-- staging tables must never fall back to transactional CREATE INDEX; only an
-- empty database created by a fresh reset may build them in this migration.

BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Cooperate with manual/CD prebuild and recovery sessions on this database.
SELECT pg_advisory_xact_lock(20819, 20260729);

CREATE TEMP TABLE saved_snapshot_expected_index (
    index_name text PRIMARY KEY,
    table_name text NOT NULL,
    is_unique boolean NOT NULL,
    key_columns text[] NOT NULL,
    predicate text NOT NULL,
    definition text NOT NULL
) ON COMMIT DROP;

INSERT INTO saved_snapshot_expected_index (
    index_name,
    table_name,
    is_unique,
    key_columns,
    predicate,
    definition
)
VALUES
(
    'snapshot_sandbox_runtime_unique',
    'snapshot',
    true,
    ARRAY['sandbox_id'],
    '(kind = ''runtime_checkpoint''::snapshot_kind)',
    'CREATE UNIQUE INDEX snapshot_sandbox_runtime_unique ON public.snapshot USING btree (sandbox_id) WHERE (kind = ''runtime_checkpoint''::snapshot_kind)'
),
(
    'snapshot_team_source_idempotency_unique',
    'snapshot',
    true,
    ARRAY['team_id', 'sandbox_id', 'idempotency_key'],
    '((kind = ''saved''::snapshot_kind) AND (idempotency_key IS NOT NULL))',
    'CREATE UNIQUE INDEX snapshot_team_source_idempotency_unique ON public.snapshot USING btree (team_id, sandbox_id, idempotency_key) WHERE ((kind = ''saved''::snapshot_kind) AND (idempotency_key IS NOT NULL))'
),
(
    'idx_snapshot_team_saved_created',
    'snapshot',
    false,
    ARRAY['team_id', 'created_at', 'id'],
    '((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))',
    'CREATE INDEX idx_snapshot_team_saved_created ON public.snapshot USING btree (team_id, created_at DESC, id DESC) WHERE ((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))'
),
(
    'idx_snapshot_source_saved_created',
    'snapshot',
    false,
    ARRAY['sandbox_id', 'created_at', 'id'],
    '((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))',
    'CREATE INDEX idx_snapshot_source_saved_created ON public.snapshot USING btree (sandbox_id, created_at DESC, id DESC) WHERE ((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))'
),
(
    'idx_snapshot_parent_saved',
    'snapshot',
    false,
    ARRAY['parent_snapshot_id'],
    '((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))',
    'CREATE INDEX idx_snapshot_parent_saved ON public.snapshot USING btree (parent_snapshot_id) WHERE ((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))'
),
(
    'idx_snapshot_saved_host',
    'snapshot',
    false,
    ARRAY['host_id', 'status'],
    '((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))',
    'CREATE INDEX idx_snapshot_saved_host ON public.snapshot USING btree (host_id, status) WHERE ((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL))'
),
(
    'idx_snapshot_saved_reconcile',
    'snapshot',
    false,
    ARRAY['status', 'updated_at', 'id'],
    '((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL) AND (status = ANY (ARRAY[''creating''::snapshot_status, ''deleting''::snapshot_status])))',
    'CREATE INDEX idx_snapshot_saved_reconcile ON public.snapshot USING btree (status, updated_at, id) WHERE ((kind = ''saved''::snapshot_kind) AND (deleted_at IS NULL) AND (status = ANY (ARRAY[''creating''::snapshot_status, ''deleting''::snapshot_status])))'
),
(
    'idx_sandbox_source_snapshot_pin',
    'sandbox',
    false,
    ARRAY['source_snapshot_id'],
    '(source_snapshot_id IS NOT NULL)',
    'CREATE INDEX idx_sandbox_source_snapshot_pin ON public.sandbox USING btree (source_snapshot_id) WHERE (source_snapshot_id IS NOT NULL)'
),
(
    'idx_sandbox_destroyed_snapshot_pin',
    'sandbox',
    false,
    ARRAY['destroyed_at', 'id'],
    '((source_snapshot_id IS NOT NULL) AND (destroyed_at IS NOT NULL))',
    'CREATE INDEX idx_sandbox_destroyed_snapshot_pin ON public.sandbox USING btree (destroyed_at, id) WHERE ((source_snapshot_id IS NOT NULL) AND (destroyed_at IS NOT NULL))'
),
(
    'idx_sandbox_snapshot_operation',
    'sandbox',
    false,
    ARRAY['snapshot_operation_started_at'],
    '((snapshot_operation_id IS NOT NULL) AND (destroyed_at IS NULL))',
    'CREATE INDEX idx_sandbox_snapshot_operation ON public.sandbox USING btree (snapshot_operation_started_at) WHERE ((snapshot_operation_id IS NOT NULL) AND (destroyed_at IS NULL))'
);

CREATE FUNCTION pg_temp.require_saved_snapshot_index(
    requested_index_name text,
    required boolean
) RETURNS void
    LANGUAGE plpgsql
AS $$
DECLARE
    expected saved_snapshot_expected_index%ROWTYPE;
    index_oid oid;
    actual_table_schema text;
    actual_table_name text;
    actual_access_method text;
    actual_relkind "char";
    actual_unique boolean;
    actual_valid boolean;
    actual_ready boolean;
    actual_live boolean;
    actual_immediate boolean;
    actual_key_count smallint;
    actual_attribute_count smallint;
    actual_keys text[];
    actual_predicate text;
    actual_definition text;
    has_expressions boolean;
BEGIN
    SELECT *
    INTO STRICT expected
    FROM saved_snapshot_expected_index
    WHERE index_name = requested_index_name;

    SELECT object.oid, object.relkind
    INTO index_oid, actual_relkind
    FROM pg_class object
    JOIN pg_namespace object_namespace
      ON object_namespace.oid = object.relnamespace
    WHERE object_namespace.nspname = 'public'
      AND object.relname = requested_index_name;

    IF index_oid IS NULL THEN
        IF required THEN
            RAISE EXCEPTION
                'required saved-snapshot index public.% is missing',
                requested_index_name;
        END IF;
        RETURN;
    END IF;

    IF actual_relkind <> 'i' THEN
        RAISE EXCEPTION
            'public.% exists but is not a regular index (relkind=%)',
            requested_index_name,
            actual_relkind;
    END IF;

    SELECT table_namespace.nspname,
           indexed_table.relname,
           access_method.amname,
           catalog.indisunique,
           catalog.indisvalid,
           catalog.indisready,
           catalog.indislive,
           catalog.indimmediate,
           catalog.indnkeyatts,
           catalog.indnatts,
           ARRAY(
               SELECT pg_get_indexdef(
                          catalog.indexrelid,
                          key_position,
                          true
                      )
               FROM generate_series(
                        1,
                        catalog.indnkeyatts
                    ) AS key_position
               ORDER BY key_position
           ),
           pg_get_expr(catalog.indpred, catalog.indrelid, false),
           pg_get_indexdef(catalog.indexrelid),
           catalog.indexprs IS NOT NULL
    INTO actual_table_schema,
         actual_table_name,
         actual_access_method,
         actual_unique,
         actual_valid,
         actual_ready,
         actual_live,
         actual_immediate,
         actual_key_count,
         actual_attribute_count,
         actual_keys,
         actual_predicate,
         actual_definition,
         has_expressions
    FROM pg_index catalog
    JOIN pg_class indexed_table
      ON indexed_table.oid = catalog.indrelid
    JOIN pg_namespace table_namespace
      ON table_namespace.oid = indexed_table.relnamespace
    JOIN pg_class index_object
      ON index_object.oid = catalog.indexrelid
    JOIN pg_am access_method
      ON access_method.oid = index_object.relam
    WHERE catalog.indexrelid = index_oid;

    IF NOT FOUND
       OR actual_table_schema <> 'public'
       OR actual_table_name <> expected.table_name
       OR actual_access_method <> 'btree'
       OR actual_unique IS DISTINCT FROM expected.is_unique
       OR NOT actual_valid
       OR NOT actual_ready
       OR NOT actual_live
       OR NOT actual_immediate
       OR actual_key_count <> cardinality(expected.key_columns)
       OR actual_attribute_count <> actual_key_count
       OR actual_keys IS DISTINCT FROM expected.key_columns
       OR actual_predicate IS DISTINCT FROM expected.predicate
       OR actual_definition IS DISTINCT FROM expected.definition
       OR has_expressions
    THEN
        RAISE EXCEPTION
            'saved-snapshot index public.% does not match the required valid/ready/live btree definition (actual=%)',
            requested_index_name,
            COALESCE(actual_definition, '<not an index>');
    END IF;
END;
$$;

-- Reject drifted and invalid same-named objects before deciding whether the
-- fresh-reset fallback is allowed.
DO $$
DECLARE
    expected record;
BEGIN
    FOR expected IN
        SELECT index_name
        FROM saved_snapshot_expected_index
        ORDER BY index_name
    LOOP
        PERFORM pg_temp.require_saved_snapshot_index(
            expected.index_name,
            false
        );
    END LOOP;
END;
$$;

DO $$
DECLARE
    tables_are_populated boolean;
    missing_indexes text;
    expected record;
BEGIN
    tables_are_populated :=
        EXISTS (SELECT 1 FROM public.snapshot LIMIT 1)
        OR EXISTS (SELECT 1 FROM public.sandbox LIMIT 1);

    -- A fresh reset has no concurrent application writers. Still close the
    -- theoretical check/build race before using ordinary CREATE INDEX: once
    -- both tables are write-locked, recheck emptiness under that lock.
    IF NOT tables_are_populated THEN
        LOCK TABLE public.sandbox, public.snapshot IN SHARE MODE;
        tables_are_populated :=
            EXISTS (SELECT 1 FROM public.snapshot LIMIT 1)
            OR EXISTS (SELECT 1 FROM public.sandbox LIMIT 1);
    END IF;

    SELECT string_agg(index_name, ', ' ORDER BY index_name)
    INTO missing_indexes
    FROM saved_snapshot_expected_index expected_index
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_class index_object
        JOIN pg_namespace index_namespace
          ON index_namespace.oid = index_object.relnamespace
        WHERE index_namespace.nspname = 'public'
          AND index_object.relname = expected_index.index_name
    );

    IF tables_are_populated AND missing_indexes IS NOT NULL THEN
        RAISE EXCEPTION
            'populated snapshot/sandbox tables require concurrent prebuild of all saved-snapshot indexes; missing: %',
            missing_indexes
            USING HINT =
                'Run scripts/prebuild-saved-snapshot-indexes.sql with psql, then retry this migration.';
    END IF;

    -- The ordinary build path exists only so local/CI schema resets can apply
    -- the complete migration history to an empty database.
    IF NOT tables_are_populated THEN
        FOR expected IN
            SELECT *
            FROM saved_snapshot_expected_index
            ORDER BY index_name
        LOOP
            IF NOT EXISTS (
                SELECT 1
                FROM pg_class index_object
                JOIN pg_namespace index_namespace
                  ON index_namespace.oid = index_object.relnamespace
                WHERE index_namespace.nspname = 'public'
                  AND index_object.relname = expected.index_name
            ) THEN
                EXECUTE expected.definition;
            END IF;
        END LOOP;
    END IF;

    FOR expected IN
        SELECT index_name
        FROM saved_snapshot_expected_index
        ORDER BY index_name
    LOOP
        PERFORM pg_temp.require_saved_snapshot_index(
            expected.index_name,
            true
        );
    END LOOP;
END;
$$;

COMMIT;
