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
                     "-p", "127.0.0.1::5432", "postgres:17.6")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
