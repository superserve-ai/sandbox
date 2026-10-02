"""Exercise deployment's Supabase CLI against disposable Docker PostgreSQL."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
VERSION = "20261003010004"
CLI = os.environ.get("SUPABASE_CLI", "supabase")


def run(*args, **kwargs):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=120, **kwargs)


class MigrationCLITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container = "migration-cli-" + uuid.uuid4().hex[:12]
        cls.addClassCleanup(run, "docker", "rm", "-f", cls.container)
        result = run("docker", "run", "-d", "--name", cls.container,
                     "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                     "-p", "127.0.0.1::5432", "postgres:16")
        if result.returncode:
            raise RuntimeError(result.stdout)
        for _ in range(60):
            # The image's temporary initialization server only accepts sockets.
            if run("docker", "exec", cls.container,
                   "pg_isready", "-h", "127.0.0.1", "-U", "postgres").returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("disposable PostgreSQL did not become ready")
        port = run("docker", "port", cls.container, "5432").stdout.strip()
        cls.port = port.rsplit(":", 1)[1]

    def setUp(self):
        self.database = "test_" + uuid.uuid4().hex[:12]
        result = run("docker", "exec", self.container, "createdb",
                     "-U", "postgres", self.database)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.temp = tempfile.TemporaryDirectory(prefix="migration-cli-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        self.migrations = self.project / "supabase" / "migrations"
        self.migrations.mkdir(parents=True)
        (self.project / "supabase" / "config.toml").write_text(
            'project_id = "migration-cli-test"\n')

    def copy_migrations(self, through=None):
        for source in sorted((ROOT / "supabase" / "migrations").glob("*.sql")):
            if through is None or source.name.split("_")[0] <= through:
                shutil.copyfile(source, self.migrations / source.name)

    def sql(self, sql):
        result = run("docker", "exec", "-i", self.container, "psql",
                     "-XAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                     "-d", self.database, input=sql)
        self.assertEqual(result.returncode, 0, result.stdout)
        return result.stdout.strip()

    def push(self, error=None):
        result = run(CLI, "db", "push", "--db-url",
                     f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable",
                     "--workdir", str(self.project), "--yes")
        if error is None:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(error, result.stdout)
        return result

    def function(self):
        return self.sql("SELECT pg_get_functiondef("
                        "'fence_retained_storage_owner_creation()'::regprocedure)")

    def history(self):
        return self.sql("SELECT row_to_json(m) FROM supabase_migrations.schema_migrations m "
                        "ORDER BY version")

    def assert_no_pending_migrations(self):
        count = len(list((ROOT / "supabase" / "migrations").glob("*.sql")))
        self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations"),
                         str(count))
        history = self.history()
        self.push()
        self.assertEqual(self.history(), history)

    def test_fresh_database(self):
        self.copy_migrations()
        self.push()
        self.assert_no_pending_migrations()

    def test_partial_rollout_timeout_atomicity_and_recovery(self):
        self.copy_migrations("20261003010003")
        self.push()
        old_function = self.function()
        old_history = self.history()
        self.assertNotIn("retained-storage-owner-pending:", old_function)

        # The failed deployment stopped at this prefix, before its function DDL.
        broken = self.migrations / f"{VERSION}_mark_pending_retained_storage_owners.sql"
        broken.write_text("SET LOCAL lock_timeout = '250ms';\n"
                          "LOCK TABLE sandbox, sandbox_snapshot IN SHARE ROW EXCLUSIVE MODE;\n")
        self.push(error="25P01")
        self.assertEqual(self.function(), old_function)
        self.assertEqual(self.history(), old_history)
        self.copy_migrations(VERSION)

        for table in ("sandbox", "sandbox_snapshot"):
            with self.subTest(locked_table=table):
                holder = subprocess.Popen(
                    ["docker", "exec", "-i", self.container, "psql", "-XAt",
                     "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", self.database],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    text=True)
                try:
                    holder.stdin.write("SET application_name='migration-cli-lock-holder'; BEGIN; "
                                       f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE; "
                                       "SELECT pg_sleep(60); ROLLBACK;\n")
                    holder.stdin.close()
                    for _ in range(100):
                        if self.sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a "
                                    "USING(pid) WHERE a.application_name='migration-cli-lock-holder' "
                                    f"AND l.relation='{table}'::regclass AND l.granted") == "1":
                            break
                        time.sleep(0.05)
                    else:
                        self.fail("lock holder did not acquire table lock")
                    start = time.monotonic()
                    self.push(error="55P03")
                    self.assertLess(time.monotonic() - start, 15,
                                    "migration did not respect its 250ms lock timeout")
                    self.assertEqual(self.function(), old_function)
                    self.assertEqual(self.history(), old_history)
                finally:
                    self.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                             "WHERE application_name='migration-cli-lock-holder'")
                    holder.wait(timeout=10)

        # A COMMIT in the migration would leave the new function installed when
        # the CLI's later history insert fails. It must roll back with that row.
        self.sql(f"""
            CREATE FUNCTION reject_test_history() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.version = '{VERSION}' THEN
                    RAISE EXCEPTION 'test migration history failure';
                END IF;
                RETURN NEW;
            END; $$;
            CREATE TRIGGER reject_test_history BEFORE INSERT OR UPDATE
            ON supabase_migrations.schema_migrations
            FOR EACH ROW EXECUTE FUNCTION reject_test_history();
        """)
        self.push(error="test migration history failure")
        self.assertEqual(self.function(), old_function)
        self.assertEqual(self.history(), old_history)
        self.sql("DROP TRIGGER reject_test_history ON supabase_migrations.schema_migrations; "
                 "DROP FUNCTION reject_test_history();")

        self.push()
        self.assertIn("retained-storage-owner-pending:", self.function())
        self.assertEqual(self.sql("SELECT row_to_json(m) FROM supabase_migrations.schema_migrations m "
                                  f"WHERE version < '{VERSION}' ORDER BY version"), old_history)
        self.copy_migrations()
        self.push()
        self.assert_no_pending_migrations()


if __name__ == "__main__":
    unittest.main(verbosity=2)
