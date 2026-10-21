"""Devbox identity boundaries and real PostgreSQL transaction recovery."""

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import migrate_devbox_shared_auth as devbox
import migrate_shared_auth as shared
import test_shared_auth_migrations as fixtures


def binding():
    return dict(purpose="disposable-shared-auth-bootstrap", project="test-project", zone="test-zone",
                instance="devbox-test", instance_id="123", devbox_id="abcdef123456", run_id="456",
                database_system_identifier="789", database_oid="5", candidate_revision="b" * 40,
                expires_at="2099-01-01T00:00:00Z",
                database={"host": "127.0.0.1", "port": 54322, "name": "postgres"},
                source_sha256={name: hashlib.sha256(source().encode()).hexdigest()
                               for name, source in devbox.MIGRATIONS})


class IdentityTest(unittest.TestCase):
    def test_cli_isolates_shadowing_imports_before_source_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            for name in ("migrate_devbox_shared_auth", "migrate_shared_auth", "migrate_database"):
                shutil.copyfile(Path(__file__).with_name(name + ".py"), scripts / (name + ".py"))
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
            git("init")
            git("add", "scripts")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                "-c", "commit.gpgsign=false", "commit", "-m", "fixture")
            revision = git("rev-parse", "HEAD")
            marker = root / "untrusted-import-executed"
            poison = f"open({str(marker)!r}, 'w').write('executed')\nraise RuntimeError('untrusted import')\n"
            for name in ("psycopg.py", "argparse.py", "json.py"):
                (scripts / name).write_text(poison)
            hook = root / "untrusted-hook"
            hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
            hook.chmod(0o755)
            git("config", "core.fsmonitor", str(hook))
            git("config", "diff.external", str(hook))
            git("config", "filter.untrusted.clean", str(hook))
            git("config", "filter.untrusted.process", str(hook))
            (root / ".git/info/attributes").write_text("scripts/*.py filter=untrusted\n")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            shutil.copyfile(hook, fake_bin / "git")
            (fake_bin / "git").chmod(0o755)
            args = [str(scripts / "migrate_devbox_shared_auth.py"), "inspect", "--revision", revision,
                    "--binding", str(root / "absent-binding.json")]
            env = dict(os.environ, PYTHONPATH=str(scripts), PATH=str(fake_bin) + os.pathsep + os.environ['PATH'],
                       GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.fsmonitor", GIT_CONFIG_VALUE_0=str(hook))
            plain = subprocess.run([sys.executable, *args], env=env, capture_output=True, text=True)
            self.assertIn("python -I", plain.stderr)
            isolated = subprocess.run([sys.executable, "-I", *args], env=env, capture_output=True, text=True)
            self.assertEqual(isolated.returncode, 1)
            # Reaching binding/root validation proves the pinned helpers loaded.
            self.assertIn('"next_step"', isolated.stdout, isolated.stderr)
            self.assertFalse(marker.exists())
            (scripts / "migrate_shared_auth.py").write_text(poison)
            dirty = subprocess.run([sys.executable, "-I", *args], env=env, capture_output=True, text=True)
            self.assertIn("Pinned initializer source could not be verified", dirty.stderr)
            self.assertFalse(marker.exists())

    def test_protected_file_reads_verified_descriptor_despite_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.json"
            replacement = Path(directory) / "replacement.json"
            path.write_text("approved")
            replacement.write_text("unverified replacement")
            def checked_descriptor(fd):
                os.replace(replacement, path)
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
            with patch.object(devbox.os, "fstat", side_effect=checked_descriptor):
                self.assertEqual(devbox.protected_file(path), "approved")
            link = Path(directory) / "binding-link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                devbox.protected_file(link)

    def test_binding_requires_disposable_exact_source_and_unexpired_lease(self):
        devbox.validate_binding(binding())
        for key, value in (("purpose", "production"), ("instance", "production-api"),
                           ("devbox_id", "wrong"), ("candidate_revision", "main"),
                           ("expires_at", "2020-01-01T00:00:00Z"),
                           ("database", {"host": "db.example.com", "port": 5432, "name": "postgres"}),
                           ("source_sha256", {})):
            with self.subTest(key=key):
                data = binding()
                data[key] = value
                with self.assertRaises(shared.SharedMigrationError):
                    devbox.validate_binding(data)

    def test_remote_connections_and_libpq_overrides_are_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            params = devbox.connection_parameters("postgresql://postgres:synthetic@127.0.0.1:54322/postgres?sslmode=disable")
            self.assertEqual(params["hostaddr"], "127.0.0.1")
            self.assertEqual(params["password"], "synthetic")
            for url in (
                "postgresql://postgres@db.project.supabase.co:54322/postgres",
                "postgresql://postgres@localhost:54322/postgres",
                "postgresql://postgres@127.0.0.1:5432/postgres",
                "postgresql://postgres@127.0.0.1:54322/customer",
                "postgresql://supabase_admin@127.0.0.1:54322/postgres",
                "postgresql://postgres@127.0.0.1:54322/postgres?hostaddr=10.0.0.1",
                "postgresql://postgres@127.0.0.1:54322/postgres?service=production",
            ):
                with self.subTest(url=url), self.assertRaises(shared.SharedMigrationError):
                    devbox.connection_parameters(url)
            os.environ["PGSERVICE"] = "production"
            with self.assertRaisesRegex(shared.SharedMigrationError, "libpq_service_not_allowed"):
                devbox.connection_parameters("postgresql://postgres@127.0.0.1:54322/postgres")

    def test_host_metadata_config_and_runtime_all_must_match(self):
        data = binding()
        metadata = {"project/project-id": "test-project", "instance/zone": "projects/123/zones/test-zone",
                    "instance/name": "devbox-test", "instance/id": "123"}
        import json
        runtime = json.dumps({"host": {k: data[k] for k in ("project", "zone", "instance", "instance_id")}})
        def files(path):
            return "DEVBOX_ID=abcdef123456\n" if path == devbox.CONFIG else runtime
        with patch.object(devbox, "metadata_value", side_effect=lambda key: metadata[key]), \
                patch.object(devbox, "protected_file", side_effect=files):
            devbox.verify_host(data)
            metadata["instance/id"] = "999"
            with self.assertRaisesRegex(shared.SharedMigrationError, "vm_identity_mismatch"):
                devbox.verify_host(data)

    def test_production_entrypoint_still_rejects_devbox(self):
        with self.assertRaisesRegex(shared.SharedMigrationError, "unsupported_auth_target"):
            shared.apply(None, "devbox", "a" * 40, "", True)

    def test_database_cluster_and_session_identity_must_match(self):
        data = binding()
        expected = ("postgres", "postgres", "postgres", "789", "5", "172.18.0.2", 54322)
        def connection(row):
            return SimpleNamespace(execute=lambda _: SimpleNamespace(fetchone=lambda: row))
        devbox.verify_database(connection(expected), data)
        for index, wrong in ((0, "customer"), (1, "supabase_admin"), (2, "other"),
                             (3, "999"), (4, "9"), (6, 5432)):
            row = list(expected)
            row[index] = wrong
            with self.subTest(index=index), self.assertRaisesRegex(shared.SharedMigrationError, "database_identity_mismatch"):
                devbox.verify_database(connection(tuple(row)), data)


class DatabaseTest(fixtures.cli_test.MigrationCLITest):
    test_fresh_database = None

    def setUp(self):
        super().setUp()
        def cleanup_database():
            for sql in (f"DROP DATABASE {self.database} WITH (FORCE)",
                        "DROP ROLE IF EXISTS promotion_evidence_proxy"):
                result = fixtures.cli_test.run("docker", "exec", self.container, "psql", "-U", "postgres",
                                               "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql)
                self.assertEqual(result.returncode, 0, result.stdout)
        self.addCleanup(cleanup_database)
        for role in shared.ROLES[:-1]:
            self.sql(f"DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') "
                     f"THEN CREATE ROLE {role}; END IF; END $$;")
        self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY,created_at timestamptz,"
                 "email text,email_confirmed_at timestamptz,deleted_at timestamptz);")
        # Follow install-api.sh: the pinned CLI applies both migration folders
        # and writes the real baseline receipt. Never synthesize its history.
        shared.regional.verified_aggregate(fixtures.cli_test.ROOT)
        self.copy_migrations()
        for source in (fixtures.cli_test.ROOT / "supabase/shared-auth-history").glob("*.sql"):
            shutil.copyfile(source, self.migrations / source.name)
        self.assertEqual(fixtures.cli_test.run(fixtures.cli_test.CLI, "--version").stdout.splitlines()[0],
                         shared.regional.CLI_VERSION)
        self.push()
        # PG17 grants a nonsuperuser role creator administrative membership.
        # Supabase's postgres session gets this exact non-inheriting grant.
        self.sql("GRANT promotion_evidence_proxy TO postgres WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
        self.url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"
        self.conn = fixtures.psycopg.connect(self.url, autocommit=True, options=shared.OPTIONS)
        self.addCleanup(self.conn.close)

    def test_atomic_apply_replay_inspect_and_region_history_preservation(self):
        before = shared.ordinary_history(self.conn)
        self.assertEqual([x["state"] for x in devbox.initialize(self.conn, "a" * 40)], ["pending"] * 4)
        devbox.initialize(self.conn, "a" * 40, True)
        receipts = self.conn.execute(f"SELECT * FROM {shared.LEDGER} ORDER BY version").fetchall()
        devbox.initialize(self.conn, "a" * 40, True)
        self.assertEqual(receipts, self.conn.execute(f"SELECT * FROM {shared.LEDGER} ORDER BY version").fetchall())
        self.assertEqual([x["state"] for x in devbox.initialize(self.conn, "a" * 40)], ["applied"] * 4)
        self.assertEqual(before, shared.ordinary_history(self.conn))

    def test_fault_rolls_back_all_four_and_rejects_existing_users(self):
        real = shared._apply
        def fail(conn, target, revision, sql, execute, migration):
            if migration == "acceptances":
                raise shared.SharedMigrationError("injected_failure")
            return real(conn, target, revision, sql, execute, migration)
        with patch.object(shared, "_apply", side_effect=fail), self.assertRaisesRegex(shared.SharedMigrationError, "injected_failure"):
            devbox.initialize(self.conn, "a" * 40, True)
        self.assertFalse(shared.ledger_exists(self.conn))
        self.assertFalse(shared.objects_present(self.conn))
        self.conn.execute("INSERT INTO auth.users(id) VALUES(gen_random_uuid())")
        with self.assertRaisesRegex(shared.SharedMigrationError, "nonempty_auth_database"):
            devbox.initialize(self.conn, "a" * 40, True)
        self.assertFalse(shared.ledger_exists(self.conn))

    def test_baseline_and_role_drift_are_not_repaired(self):
        self.conn.execute("ALTER ROLE promotion_evidence_proxy INHERIT")
        with self.assertRaisesRegex(shared.SharedMigrationError, "proxy_role_mismatch"):
            devbox.initialize(self.conn, "a" * 40, True)
        self.conn.execute("ALTER ROLE promotion_evidence_proxy NOINHERIT")
        self.conn.execute("UPDATE supabase_migrations.schema_migrations SET name='changed' WHERE version=%s", (shared.regional.VERSION,))
        with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
            devbox.initialize(self.conn, "a" * 40, True)
        self.assertFalse(shared.ledger_exists(self.conn))

    def test_installer_baseline_statement_drift_is_rejected(self):
        for mutation in ("statements[2:cardinality(statements)]",
                         "ARRAY(SELECT s FROM unnest(statements) WITH ORDINALITY AS t(s,n) ORDER BY n DESC)"):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(f"UPDATE supabase_migrations.schema_migrations SET statements={mutation} "
                                  "WHERE version=%s", (shared.regional.VERSION,))
                with self.assertRaisesRegex(shared.SharedMigrationError, "historical_aggregate_mismatch"):
                    devbox.initialize(self.conn, "a" * 40, True)
                self.assertFalse(shared.ledger_exists(self.conn))

    def test_proxy_role_membership_escalation_is_rejected(self):
        for sql in ("GRANT service_role TO promotion_evidence_proxy",
                    "GRANT promotion_evidence_proxy TO authenticated",
                    "GRANT promotion_evidence_proxy TO postgres WITH INHERIT TRUE",
                    "GRANT promotion_evidence_proxy TO postgres WITH SET TRUE"):
            with self.conn.transaction(force_rollback=True):
                self.conn.execute(sql)
                with self.assertRaisesRegex(shared.SharedMigrationError, "proxy_role_mismatch"):
                    devbox.initialize(self.conn, "a" * 40, True)
                self.assertFalse(shared.ledger_exists(self.conn))

    def test_signup_is_blocked_until_bootstrap_commits(self):
        real = shared._apply
        checked = []
        with fixtures.psycopg.connect(self.url, autocommit=True, options="-c lock_timeout=100ms") as other:
            def witness(conn, target, revision, sql, execute, migration):
                if migration == "authority":
                    with self.assertRaises(fixtures.psycopg.errors.LockNotAvailable):
                        other.execute("INSERT INTO auth.users(id) VALUES(gen_random_uuid())")
                    checked.append(True)
                return real(conn, target, revision, sql, execute, migration)
            with patch.object(shared, "_apply", side_effect=witness):
                devbox.initialize(self.conn, "a" * 40, True)
            self.assertEqual(checked, [True])
            other.execute("INSERT INTO auth.users(id) VALUES(gen_random_uuid())")


if __name__ == "__main__":
    unittest.main()
