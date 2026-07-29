\set ON_ERROR_STOP on

-- Build the saved-snapshot contract indexes outside Supabase's migration
-- transaction. CREATE INDEX CONCURRENTLY must be the only command in its
-- transaction, so keep these statements sequential and run this file with
-- psql before 20260729000010_saved_snapshot_indexes.sql.
SET lock_timeout = '5s';
SET statement_timeout = '30min';

-- Serialize CD and operator invocations on this database. Session-level
-- ownership spans every autocommit transaction required by CONCURRENTLY and
-- is also released automatically if psql exits on an error.
SELECT pg_advisory_lock(20819, 20260729);

CREATE TEMP TABLE saved_snapshot_expected_index (
    index_name text PRIMARY KEY,
    table_name text NOT NULL,
    is_unique boolean NOT NULL,
    key_columns text[] NOT NULL,
    predicate text NOT NULL,
    definition text NOT NULL
);

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

-- Fail before mutating anything if a same-named object is invalid or drifted.
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

\echo 'Building saved-snapshot indexes concurrently and sequentially'

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS snapshot_sandbox_runtime_unique
    ON public.snapshot USING btree (sandbox_id)
    WHERE kind = 'runtime_checkpoint';

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS snapshot_team_source_idempotency_unique
    ON public.snapshot USING btree (team_id, sandbox_id, idempotency_key)
    WHERE kind = 'saved' AND idempotency_key IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_team_saved_created
    ON public.snapshot USING btree (team_id, created_at DESC, id DESC)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_source_saved_created
    ON public.snapshot USING btree (sandbox_id, created_at DESC, id DESC)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_parent_saved
    ON public.snapshot USING btree (parent_snapshot_id)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_saved_host
    ON public.snapshot USING btree (host_id, status)
    WHERE kind = 'saved' AND deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_snapshot_saved_reconcile
    ON public.snapshot USING btree (status, updated_at, id)
    WHERE kind = 'saved'
      AND deleted_at IS NULL
      AND status IN ('creating', 'deleting');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_source_snapshot_pin
    ON public.sandbox USING btree (source_snapshot_id)
    WHERE source_snapshot_id IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_destroyed_snapshot_pin
    ON public.sandbox USING btree (destroyed_at, id)
    WHERE source_snapshot_id IS NOT NULL
      AND destroyed_at IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sandbox_snapshot_operation
    ON public.sandbox USING btree (snapshot_operation_started_at)
    WHERE snapshot_operation_id IS NOT NULL
      AND destroyed_at IS NULL;

-- Verify every catalog property again. IF NOT EXISTS is not a definition
-- check, and a canceled concurrent build can leave an invalid index behind.
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
            true
        );
    END LOOP;
END;
$$;

\echo 'All 10 saved-snapshot indexes are exact, valid, ready, and live'

SELECT pg_advisory_unlock(20819, 20260729);
