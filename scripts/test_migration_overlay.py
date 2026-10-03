"""Validate database-specific migration inputs with the actual deployment CLI."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import migrate_database as migration
import test_migration_cli as cli_test

CLI, ROOT = cli_test.CLI, cli_test.ROOT


class HistoryResponseTest(unittest.TestCase):
    def response(self, data):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(data), stderr="")

    def test_normal_array_and_agent_envelope(self):
        expected = [{"version": migration.VERSION, "name": migration.NAME,
                     "statement_count": 1, "sha256": migration.SHA256}]
        for envelope in (False, True):
            def encode(rows):
                return self.response({"rows": rows, "boundary": "test", "warning": "test"}
                                     if envelope else rows)
            with self.subTest(envelope=envelope):
                with patch.object(migration, "run_cli", return_value=encode([{"present": False}])):
                    self.assertEqual(migration.history_row(CLI, "unused", ROOT), [])
                with patch.object(migration, "run_cli", side_effect=[
                        encode([{"present": True}]), encode(expected)]):
                    rows = migration.history_row(CLI, "unused", ROOT)
                    self.assertEqual(rows, expected)
                    migration.verify_history(rows, "use4")

    def test_malformed_responses_fail_closed(self):
        invalid = [None, True, 1, "rows", {}, {"rows": None}, {"rows": {}},
                   [None], ["row"], {"rows": [1]}]
        responses = [self.response(data) for data in invalid]
        responses.append(subprocess.CompletedProcess([], 0, stdout="not json", stderr=""))
        for response in responses:
            for history_query in (False, True):
                with self.subTest(data=response.stdout, history_query=history_query):
                    results = ([self.response([{"present": True}])] if history_query else []) + [response]
                    with patch.object(migration, "run_cli", side_effect=results):
                        with self.assertRaisesRegex(migration.MigrationError, "Unrecognized CLI history response"):
                            migration.history_row(CLI, "unused", ROOT)


class ConnectionIdentityTest(unittest.TestCase):
    def test_rejections_are_categorical_and_do_not_expose_values(self):
        project = migration.PROJECTS["usw2"]
        url = f"postgres://postgres.{project}:private-example@aws-0-us-west-1.pooler.supabase.com:6543/postgres"
        with self.assertRaises(migration.MigrationError) as error:
            migration.verify_connection_identity(url, "usw2")
        self.assertEqual(str(error.exception), "Migration connection rejected: transaction_pooler_not_supported")
        for url, reason in (("", "missing_url"),
                            ("postgres://user:private-example@[bad", "malformed_url"),
                            (f"postgres://user:private-example@db.{project}.supabase.co/postgres?private-example=x", "unsupported_query_parameter")):
            self.assertEqual(migration.connection_rejection(url, "usw2"), reason)

    def test_session_pooler_requires_exact_project_and_retains_timeout_options(self):
        for target, project in migration.PROJECTS.items():
            for port in ("", ":5432"):
                url = f"postgres://postgres.{project}:example@aws-0-us-west-1.pooler.supabase.com{port}/postgres?sslmode=require"
                migration.verify_connection_identity(url, target)
                self.assertIn("transaction_timeout", migration.bounded_url(url))
                self.assertIn("lock_timeout", migration.bounded_url(url))
                for other in migration.PROJECTS.keys() - {target}:
                    with self.assertRaises(migration.MigrationError):
                        migration.verify_connection_identity(url, other)
        with patch.object(migration, "run_cli", return_value=subprocess.CompletedProcess([], 0, stdout='[{"ready":false}]')):
            with self.assertRaises(migration.MigrationError):
                migration.preflight(CLI, "unused", ROOT, None)

    def test_direct_projects(self):
        for target, project in migration.PROJECTS.items():
            for url in (
                f"postgresql://postgres:example@db.{project}.supabase.co:5432/postgres",
            ):
                migration.verify_connection_identity(url, target)
                for other in migration.PROJECTS.keys() - {target}:
                    with self.assertRaises(migration.MigrationError):
                        migration.verify_connection_identity(url, other)

    def test_ambiguous_and_redirected_connections_are_rejected(self):
        project = migration.PROJECTS["use4"]
        valid = f"postgresql://postgres:example@db.{project}.supabase.co/postgres"
        for url in (
            "postgresql://postgres@localhost/postgres",
            "postgresql://postgres@aws-0-us-east-1.pooler.supabase.com/postgres",
            valid.replace("supabase.co", "supabase.co.example.com"),
            valid.replace("postgres:example", "postgres.otherproject:example"),
            valid.replace("/postgres", ":6543/postgres"),
            f"postgres://postgres.{project}:example@aws-0-us-east-1.pooler.supabase.com.example.com:5432/postgres",
            f"postgres://postgres.{project}:example@aws-0-us-east-1.pooler.supabase.com:6543/postgres",
            valid + "?hostaddr=127.0.0.1",
            valid + "?host=other",
            valid + "?host=",
            valid + "?user=other",
            valid + "?user=",
            valid + "?options=-csearch_path=other",
            valid + "?sslmode=require&sslmode=disable",
            valid + "#ignored",
        ):
            with self.subTest(url=url), self.assertRaises(migration.MigrationError):
                migration.verify_connection_identity(url, "use4")


class MigrationOverlayTest(cli_test.MigrationCLITest):
    # Keep this class's tests separate from the retained-storage CLI tests.
    test_fresh_database = None
    test_partial_rollout_timeout_atomicity_and_recovery = None

    def invoke(self, target, action="push", root=ROOT):
        url = f"postgresql://postgres@127.0.0.1:{self.port}/{self.database}?sslmode=disable"
        # Only connection identity is replaced for disposable local PostgreSQL.
        # The CLI has no override flag; its production URL guard is tested above.
        with patch.object(migration, "verify_connection_identity"), contextlib.redirect_stdout(io.StringIO()):
            migration.migrate(target, action, url, root=root, cli=CLI)

    def test_regional_databases_do_not_receive_auth_setup(self):
        roles = self.sql("SELECT count(*) FROM pg_roles WHERE rolname='promotion_evidence_proxy'")
        for target in ("staging", "usw2"):
            with self.subTest(target=target):
                self.database = f"regional_{target}"
                result = cli_test.run("docker", "exec", self.container, "createdb", "-U", "postgres", self.database)
                self.assertEqual(result.returncode, 0, result.stdout)
                if target == "staging":
                    # Existing Auth tables do not establish ownership of an overlay.
                    self.sql("CREATE TABLE signup_device_attempt(id integer); "
                             "INSERT INTO signup_device_attempt VALUES(1);")
                if target == "usw2":
                    with self.assertRaisesRegex(migration.MigrationError, "completed recovery"):
                        self.invoke(target)
                    self.assertEqual(self.sql("SELECT to_regclass('supabase_migrations.schema_migrations') IS NULL"), "t")
                    continue
                self.invoke(target)
                self.invoke(target, "list")
                before = self.history()
                self.invoke(target)
                self.assertEqual(self.history(), before)
                if target == "staging":
                    self.assertEqual(self.sql("SELECT count(*) FROM signup_device_attempt"), "1")
                else:
                    self.assertEqual(self.sql("SELECT to_regclass('signup_device_attempt') IS NULL"), "t")
                self.assertEqual(self.sql("SELECT count(*) FROM pg_roles WHERE rolname='promotion_evidence_proxy'"), roles)

    def test_east_existing_history_and_guards(self):
        self.copy_migrations("20261002155219")
        self.push()
        before = self.history()
        with self.assertRaisesRegex(migration.MigrationError, "missing or mismatched"):
            self.invoke("use4")
        self.assertEqual(self.history(), before)

        aggregate = migration.verified_aggregate(ROOT).decode()
        self.sql("CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid, created_at timestamptz);")
        self.sql(aggregate + f"\nINSERT INTO supabase_migrations.schema_migrations(version,name,statements) "
                 f"VALUES('{migration.VERSION}','{migration.NAME}',ARRAY[$historical${aggregate}$historical$]);")
        self.sql("INSERT INTO signup_device_attempt(attempt_id) "
                 "VALUES('00000000-0000-0000-0000-000000000001');")
        auth_history = self.sql("SELECT row_to_json(m) FROM supabase_migrations.schema_migrations m "
                                f"WHERE version='{migration.VERSION}'")
        for target in ("staging", "usw2"):
            with self.assertRaisesRegex(migration.MigrationError, "Unexpected shared-Auth"):
                self.invoke(target)

        def restore():
            self.sql(f"UPDATE supabase_migrations.schema_migrations SET name='{migration.NAME}', "
                     f"statements=ARRAY[$historical${aggregate}$historical$] WHERE version='{migration.VERSION}'")

        for label, mutation in (
                ("name", "name='wrong'"), ("hash", "statements=ARRAY['SELECT 1']"),
                ("count", f"statements=ARRAY[$historical${aggregate}$historical$,'SELECT 2']")):
            with self.subTest(history_mutation=label):
                self.sql(f"UPDATE supabase_migrations.schema_migrations SET {mutation} "
                         f"WHERE version='{migration.VERSION}'")
                with self.assertRaisesRegex(migration.MigrationError, "missing or mismatched"):
                    self.invoke("use4")
                restore()

        with patch.object(migration, "cli_run", return_value=migration.AGGREGATE) as runner:
            with self.assertRaisesRegex(migration.MigrationError, "proposed replaying"):
                self.invoke("use4")
            self.assertEqual(runner.call_count, 1)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / "supabase", root / "supabase")
            artifact = root / "supabase/shared-auth-history" / migration.AGGREGATE
            artifact.write_bytes(artifact.read_bytes() + b"\n")
            with self.assertRaisesRegex(migration.MigrationError, "aggregate hash mismatch"):
                self.invoke("use4", root=root)
            artifact.write_text(aggregate)
            source = root / "supabase/shared-auth-migrations" / next(iter(migration.SOURCES))
            original = source.read_bytes()
            source.write_bytes(original + b"\n")
            with self.assertRaisesRegex(migration.MigrationError, "source hash mismatch"):
                self.invoke("use4", root=root)
            source.write_bytes(original)
            duplicate = root / "supabase/migrations" / migration.AGGREGATE
            duplicate.write_text(aggregate)
            with self.assertRaisesRegex(migration.MigrationError, "Duplicate or shared-Auth"):
                self.invoke("use4", root=root)
            duplicate.unlink()

            self.invoke("use4", "dry-run", root)
            self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations "
                                     "WHERE version LIKE '202610030100%'"), "0")
            self.invoke("use4", root=root)
            history = self.history()
            self.invoke("use4", root=root)
            self.assertEqual(self.history(), history)
            self.assertEqual(self.sql("SELECT row_to_json(m) FROM supabase_migrations.schema_migrations m "
                                     f"WHERE version='{migration.VERSION}'"), auth_history)
            self.assertEqual(self.sql("SELECT count(*) FROM signup_device_attempt"), "1")
            self.assertEqual(self.sql("SELECT count(*) FROM supabase_migrations.schema_migrations "
                                     "WHERE version LIKE '202610030100%'"), "24")
            # A later regional migration still uses the same historical overlay.
            (root / "supabase/migrations/20990101000000_future.sql").write_text(
                "CREATE TABLE future_regional_marker(id integer); INSERT INTO future_regional_marker VALUES(1);")
            self.invoke("use4", root=root)
            self.invoke("use4", root=root)
            self.assertEqual(self.sql("SELECT count(*) FROM future_regional_marker"), "1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
