"""Prebuild the sandbox snapshot FK index outside the CLI migration transaction."""

import time

import psycopg

import migrate_database as migration
from retained_storage_recovery import MUTEX


FILE = "20261007201056_sandbox_snapshot_reference_index.sql"
NAME = "idx_sandbox_snapshot_id"
BUILD_TIMEOUT = 30
DEFINITION = ("CREATE INDEX idx_sandbox_snapshot_id ON public.sandbox USING btree (snapshot_id) "
              "WHERE (snapshot_id IS NOT NULL)")


def check(conn):
    row = conn.execute("SELECT pg_get_indexdef(c.oid),i.indisvalid,i.indisready,i.indislive "
                       "FROM pg_class c LEFT JOIN pg_index i ON i.indexrelid=c.oid "
                       "WHERE c.oid=to_regclass(%s)", ("public." + NAME,)).fetchone()
    if row is not None and row != (DEFINITION, True, True, True):
        raise migration.MigrationError(
            "Snapshot reference index is invalid or mismatched; review its recovery before retrying")
    return row is not None


def prepare(database_url, root, deadline):
    if not (root / "supabase/migrations" / FILE).exists():
        return
    try:
        with psycopg.connect(database_url, autocommit=True, connect_timeout=5) as conn:
            conn.execute(migration.EXECUTION_GUARD)
            conn.execute("SET statement_timeout='1900ms'")
            conn.execute("SET idle_session_timeout='2s'")
            if not conn.execute("SELECT pg_try_advisory_lock(%s)", (MUTEX,)).fetchone()[0]:
                raise migration.MigrationError("Another migration executor holds the migration mutex")
            # A fresh database reaches the normal migration with an empty table.
            if conn.execute("SELECT to_regclass('public.sandbox')").fetchone()[0] is None:
                return
            if check(conn):
                return
            budget_ms = int(min(BUILD_TIMEOUT, deadline - time.monotonic() - 6) * 1000)
            if budget_ms < 2000:
                raise migration.MigrationError("Migration deadline exceeded before snapshot index preparation")
            # Concurrent builds do not block ordinary writes. Give only this
            # statement a longer budget, still bounded by the command deadline;
            # a 2s transaction timer would cancel its individual build phases.
            conn.execute("SET transaction_timeout=0")
            conn.execute("SELECT set_config('statement_timeout',%s,false)", (f"{budget_ms}ms",))
            conn.execute("CREATE INDEX CONCURRENTLY idx_sandbox_snapshot_id "
                         "ON public.sandbox(snapshot_id) WHERE snapshot_id IS NOT NULL")
            conn.execute("SET statement_timeout='1900ms'")
            conn.execute("RESET transaction_timeout")
            if not check(conn):
                raise migration.MigrationError("Snapshot reference index preparation did not complete")
    except psycopg.Error as error:
        raise migration.MigrationError(
            f"Snapshot reference index preparation failed (SQLSTATE {error.sqlstate or 'unknown'}); "
            "inspect index validity before retrying") from None
