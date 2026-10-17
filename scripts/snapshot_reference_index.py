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


def state(conn):
    return conn.execute("SELECT pg_get_indexdef(c.oid),i.indisvalid,i.indisready,i.indislive "
                        "FROM pg_class c LEFT JOIN pg_index i ON i.indexrelid=c.oid "
                        "WHERE c.oid=to_regclass(%s)", ("public." + NAME,)).fetchone()


def check(conn):
    row = state(conn)
    if row is not None and row != (DEFINITION, True, True, True):
        raise migration.MigrationError(
            "Snapshot reference index is invalid or mismatched; review its recovery before retrying")
    return row is not None


def budget(conn, deadline):
    """Give one concurrent DDL statement its own time and lock budget."""
    budget_ms = int(min(BUILD_TIMEOUT, deadline - time.monotonic() - 6) * 1000)
    if budget_ms < 2000:
        raise migration.MigrationError("Migration deadline exceeded before snapshot index preparation")
    # Concurrent builds do not block ordinary writes, but they still take the
    # table's lock and wait behind transactions already holding it. A live cell
    # always has one, so the session's 250ms lock budget refuses the build
    # outright (SQLSTATE 55P03) and leaves an invalid index behind. Bound the
    # lock by the same deadline as the build itself; a 2s transaction timer
    # would cancel the build's individual phases.
    conn.execute("SET transaction_timeout=0")
    conn.execute("SELECT set_config('statement_timeout',%s,false)", (f"{budget_ms}ms",))
    conn.execute("SELECT set_config('lock_timeout',%s,false)", (f"{budget_ms}ms",))


def restore(conn):
    conn.execute("SET statement_timeout='1900ms'")
    conn.execute("RESET lock_timeout")
    conn.execute("RESET transaction_timeout")


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
            row = state(conn)
            if row is not None and row[0] == DEFINITION and not row[1]:
                # Our own definition, left invalid by an interrupted concurrent
                # build. Postgres never uses such an index and it carries no
                # state, so clearing it is the documented recovery. Doing it
                # here rather than refusing is what keeps a contended build
                # costing a retry instead of standing every later migration —
                # and the API and proxy deploy lanes behind them — down until
                # someone opens a psql session. A definition that is not ours
                # still fails closed in check() below.
                budget(conn, deadline)
                conn.execute("DROP INDEX CONCURRENTLY idx_sandbox_snapshot_id")
                restore(conn)
            if check(conn):
                return
            budget(conn, deadline)
            conn.execute("CREATE INDEX CONCURRENTLY idx_sandbox_snapshot_id "
                         "ON public.sandbox(snapshot_id) WHERE snapshot_id IS NOT NULL")
            restore(conn)
            if not check(conn):
                raise migration.MigrationError("Snapshot reference index preparation did not complete")
    except psycopg.Error as error:
        raise migration.MigrationError(
            f"Snapshot reference index preparation failed (SQLSTATE {error.sqlstate or 'unknown'}); "
            "inspect index validity before retrying") from None
