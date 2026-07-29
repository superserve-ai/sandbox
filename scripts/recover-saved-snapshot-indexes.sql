\set ON_ERROR_STOP on

-- Operator-only recovery after a canceled CREATE INDEX CONCURRENTLY. This
-- deliberately drops only invalid remnants. It never replaces a valid,
-- same-named index and is never invoked automatically by CD.
SET lock_timeout = '5s';
SET statement_timeout = '30min';

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

-- A recovery target must be the exact expected index except for its invalid
-- catalog state. Refuse valid-but-drifted indexes, wrong-table objects, and
-- invalid indexes with a different key or predicate.
DO $$
DECLARE
    expected record;
    index_oid oid;
    index_relkind "char";
BEGIN
    FOR expected IN
        SELECT *
        FROM saved_snapshot_expected_index
        ORDER BY index_name
    LOOP
        index_oid := NULL;
        index_relkind := NULL;

        SELECT object.oid, object.relkind
        INTO index_oid, index_relkind
        FROM pg_class object
        JOIN pg_namespace object_namespace
          ON object_namespace.oid = object.relnamespace
        WHERE object_namespace.nspname = 'public'
          AND object.relname = expected.index_name;

        IF index_oid IS NULL THEN
            CONTINUE;
        END IF;

        IF index_relkind <> 'i' OR NOT EXISTS (
            SELECT 1
            FROM pg_index catalog
            JOIN pg_class indexed_table
              ON indexed_table.oid = catalog.indrelid
            JOIN pg_namespace table_namespace
              ON table_namespace.oid = indexed_table.relnamespace
            JOIN pg_class index_object
              ON index_object.oid = catalog.indexrelid
            JOIN pg_am access_method
              ON access_method.oid = index_object.relam
            WHERE catalog.indexrelid = index_oid
              AND table_namespace.nspname = 'public'
              AND indexed_table.relname = expected.table_name
              AND access_method.amname = 'btree'
              AND catalog.indisunique = expected.is_unique
              AND catalog.indimmediate
              AND catalog.indnkeyatts =
                  cardinality(expected.key_columns)
              AND catalog.indnatts = catalog.indnkeyatts
              AND catalog.indexprs IS NULL
              AND ARRAY(
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
                  ) = expected.key_columns
              AND pg_get_expr(
                      catalog.indpred,
                      catalog.indrelid,
                      false
                  ) = expected.predicate
              AND pg_get_indexdef(catalog.indexrelid) =
                  expected.definition
        ) THEN
            RAISE EXCEPTION
                'refusing recovery: public.% is not the exact expected saved-snapshot index',
                expected.index_name;
        END IF;
    END LOOP;
END;
$$;

\echo 'Dropping invalid saved-snapshot index remnants, if any'

SELECT format(
           'DROP INDEX CONCURRENTLY IF EXISTS %I.%I;',
           index_namespace.nspname,
           index_object.relname
       )
FROM pg_index catalog
JOIN pg_class index_object
  ON index_object.oid = catalog.indexrelid
JOIN pg_namespace index_namespace
  ON index_namespace.oid = index_object.relnamespace
JOIN saved_snapshot_expected_index expected
  ON expected.index_name = index_object.relname
JOIN pg_class indexed_table
  ON indexed_table.oid = catalog.indrelid
JOIN pg_namespace table_namespace
  ON table_namespace.oid = indexed_table.relnamespace
JOIN pg_am access_method
  ON access_method.oid = index_object.relam
WHERE index_namespace.nspname = 'public'
  AND index_object.relkind = 'i'
  AND table_namespace.nspname = 'public'
  AND indexed_table.relname = expected.table_name
  AND access_method.amname = 'btree'
  AND catalog.indisunique = expected.is_unique
  AND catalog.indimmediate
  AND catalog.indnkeyatts = cardinality(expected.key_columns)
  AND catalog.indnatts = catalog.indnkeyatts
  AND catalog.indexprs IS NULL
  AND ARRAY(
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
      ) = expected.key_columns
  AND pg_get_expr(catalog.indpred, catalog.indrelid, false) =
      expected.predicate
  AND pg_get_indexdef(catalog.indexrelid) = expected.definition
  AND NOT catalog.indisvalid
ORDER BY index_object.relname
\gexec

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_index catalog
        JOIN pg_class index_object
          ON index_object.oid = catalog.indexrelid
        JOIN pg_namespace index_namespace
          ON index_namespace.oid = index_object.relnamespace
        JOIN saved_snapshot_expected_index expected
          ON expected.index_name = index_object.relname
        WHERE index_namespace.nspname = 'public'
          AND NOT catalog.indisvalid
    ) THEN
        RAISE EXCEPTION
            'saved-snapshot recovery left an invalid index remnant';
    END IF;
END;
$$;

\echo 'Invalid remnants removed; rerun prebuild-saved-snapshot-indexes.sql'

SELECT pg_advisory_unlock(20819, 20260729);
