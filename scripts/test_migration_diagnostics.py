"""Failure diagnostics must be useful without exposing subprocess data."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import migrate_database as migration

SECRET = "postgres://example-user:private-example@private.example/postgres"


class DiagnosticsTest(unittest.TestCase):
    def result(self, data, code=0, stderr=""):
        return subprocess.CompletedProcess([SECRET], code, json.dumps(data), stderr)

    def failure(self, callback, pattern):
        with self.assertRaisesRegex(migration.MigrationError, pattern) as error:
            callback()
        text = str(error.exception)
        for value in (SECRET, "private-example", "private.example", "example-user"):
            self.assertNotIn(value, text)
        return text

    def test_preflight_success_and_each_settings_failure(self):
        good = dict.fromkeys(migration.PREFLIGHT_CHECKS, True)
        for envelope in (False, True):
            for failed in (None, *good):
                row = good | ({failed: False} if failed else {})
                result = self.result({"rows": [row], "warning": SECRET} if envelope else [row])
                with self.subTest(envelope=envelope, failed=failed), patch.object(migration, "run_cli", return_value=result):
                    if failed:
                        text = self.failure(lambda: migration.preflight("cli", SECRET, Path("."), None), "category=settings_mismatch")
                        self.assertIn(f"{failed}=false", text)
                        for name in good.keys() - {failed}:
                            self.assertIn(f"{name}=true", text)
                    else:
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            migration.preflight("cli", SECRET, Path("."), None)
                        self.assertIn("category=passed", output.getvalue())
                        self.assertNotIn(SECRET, output.getvalue())

    def test_json_and_shape_errors(self):
        for data, category in ((SECRET, "output_shape"), ({"rows": SECRET}, "output_shape"),
                               ([SECRET], "output_shape"), ([], "check_shape"),
                               ([{"ready": True}], "check_shape"),
                               ([dict.fromkeys(migration.PREFLIGHT_CHECKS, 1)], "check_shape"),
                               ([dict.fromkeys(migration.PREFLIGHT_CHECKS, SECRET)], "check_shape")):
            with self.subTest(category=category), patch.object(migration, "run_cli", return_value=self.result(data)):
                self.failure(lambda: migration.preflight("cli", SECRET, Path("."), None), f"category={category}")
        result = subprocess.CompletedProcess([], 0, SECRET, SECRET)
        with patch.object(migration, "run_cli", return_value=result):
            self.failure(lambda: migration.preflight("cli", SECRET, Path("."), None), "category=invalid_json")

    def test_cli_exit_allowlists_and_markers(self):
        for name, patterns in migration.ERROR_MARKERS.items():
            for pattern in patterns:
                result = self.result(SECRET, 7, SECRET + " SQLSTATE 28P01 SQLSTATE SECRT " + pattern)
                with self.subTest(marker=name), patch.object(migration, "run_cli", return_value=result):
                    text = self.failure(lambda: migration.invoke_cli([SECRET], None, "preflight_query"), "category=cli_exit exit_code=7")
                    self.assertIn("SQLSTATE 28P01", text)
                    self.assertIn(f"markers={name}", text)
                    self.assertNotIn("SECRT", text)
        with patch.object(migration, "run_cli", return_value=self.result(SECRET, 1, SECRET)):
            text = self.failure(lambda: migration.invoke_cli([SECRET], None, "preflight_query"), "SQLSTATE none markers=none")
            self.assertIn("stage=preflight_query", text)

    def test_process_errors_are_sanitized(self):
        for error, category in ((OSError(SECRET), "process_io_error"),
                                (subprocess.TimeoutExpired([SECRET], 60, output=SECRET, stderr=SECRET), "command_timeout")):
            with self.subTest(category=category), patch.object(migration, "run_cli", side_effect=error):
                self.failure(lambda: migration.invoke_cli([SECRET], None, "cli_version"), f"stage=cli_version category={category}")
        with patch.object(migration.time, "monotonic", return_value=2):
            self.failure(lambda: migration.invoke_cli([SECRET], 1, "history_query"), "stage=history_query: Migration command deadline exceeded")

    def test_version_failure_never_prints_actual_output(self):
        with patch.object(migration, "verify_connection_identity"), patch.object(migration, "run_cli", return_value=self.result(SECRET)):
            self.failure(lambda: migration.migrate("usw2", "preflight", SECRET), "stage=cli_version category=version_mismatch")

    def test_history_and_execution_stages(self):
        failure = self.result(SECRET, 1, "SQLSTATE 55P03 " + SECRET)
        for stage, prior in (("history_presence", []), ("history_query", [self.result([{"present": True}])])):
            with patch.object(migration, "run_cli", side_effect=prior + [failure]):
                self.failure(lambda: migration.history_row("cli", SECRET, Path(".")), f"stage={stage} category=cli_exit")
        for args, stage in ((["db", "push", "--dry-run"], "migration_preview"),
                            (["db", "push"], "migration_execute"), (["migration", "list"], "migration_list")):
            with patch.object(migration, "run_cli", return_value=failure):
                self.failure(lambda: migration.cli_run("cli", SECRET, Path("."), args), f"stage={stage} category=cli_exit")
        self.failure(lambda: migration.verify_history([{"secret": SECRET}], "use4"), "category=east_history_mismatch")
        self.failure(lambda: migration.verify_history([{"secret": SECRET}], "usw2"), "category=unexpected_regional_history")

    def test_main_unexpected_exception_is_sanitized(self):
        with patch("sys.argv", ["migrate_database.py", "usw2", "preflight"]), patch.object(migration, "migrate", side_effect=ValueError(SECRET)), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(migration.main(), 1)
        self.assertEqual(output.getvalue(), "stage=runner category=unexpected_error; no raw output logged\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
