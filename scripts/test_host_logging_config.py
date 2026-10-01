import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HostLoggingConfigChecks(unittest.TestCase):
    def setUp(self):
        self.config = (ROOT / "infra/modules/host-logging/templates/ops-agent.yaml.tftpl").read_text()
        self.reconcile = (ROOT / "infra/modules/host-logging/templates/reconcile.sh.tftpl").read_text()
        self.validate = (ROOT / "infra/modules/host-logging/templates/validate.sh.tftpl").read_text()

    def _run_embedded_scan(self, template, kind, root, limit=100, failure=None, occurrence=0):
        """Run the exact Python traversal embedded in a rendered script.

        Keeping the source extraction tied to the template prevents this test
        from quietly becoming an independent storage-accounting model.
        """
        matches = list(re.finditer(
            r'python3 - "\$kind" "\$root" "\$max_entries"(?:\s+>\s*"?\$listing"?)?\s+<<\'PY\'\n(.*?)\nPY',
            template,
            re.DOTALL,
        ))
        self.assertTrue(matches, "storage scanner heredoc missing")
        self.assertLess(occurrence, len(matches), "storage scanner occurrence missing")
        scanner = matches[occurrence].group(1)
        wrapper = textwrap.dedent(
            """
            import os
            import sys

            failure = sys.argv.pop(1)
            original_scandir = os.scandir

            class Entry:
                def __init__(self, entry):
                    self._entry = entry
                    self.name = entry.name
                    self.path = entry.path

                def is_dir(self, follow_symlinks=False):
                    return self._entry.is_dir(follow_symlinks=follow_symlinks)

                def is_file(self, follow_symlinks=False):
                    return self._entry.is_file(follow_symlinks=follow_symlinks)

                def stat(self, follow_symlinks=False):
                    if failure == "stat":
                        raise OSError("injected stat failure")
                    return self._entry.stat(follow_symlinks=follow_symlinks)

            class Entries:
                def __init__(self, path):
                    self.path = path

                def __enter__(self):
                    if failure == "open":
                        raise OSError("injected scandir open failure")
                    return self

                def __exit__(self, *args):
                    return False

                def __iter__(self):
                    if failure == "iteration":
                        raise OSError("injected scandir iteration failure")
                    for entry in original_scandir(self.path):
                        yield Entry(entry)

            def scandir(path):
                return Entries(path)

            os.scandir = scandir
            exec(compile(%r, "embedded-storage-scanner", "exec"), {"__name__": "__main__"})
            """
        ) % scanner
        return subprocess.run(
            [sys.executable, "-c", wrapper, failure or "none", kind, str(root), str(limit)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _run_storage_compliance(self, result_path, *, buffer_limit=10, self_log_limit=10,
                                syslog_limit=10, journal_max=10, journal_keep_free=100):
        """Run the validate template's storage-compliance fragment unchanged."""
        start = self.validate.index(
            "storage_bytes=0; buffer_bytes=0; self_log_bytes=0; syslog_bytes=0"
        )
        end = self.validate.index("\nexit 100", start) + len("\nexit 100")
        fragment = self.validate[start:end]
        substitutions = {
            "agent_buffer_bytes": buffer_limit,
            "agent_self_log_max_bytes": self_log_limit,
            "syslog_max_bytes": syslog_limit,
            "journal_max_use_bytes": journal_max,
            "journal_keep_free_bytes": journal_keep_free,
        }
        for name, value in substitutions.items():
            fragment = fragment.replace("${" + name + "}", str(value))
        script = textwrap.dedent(
            f"""
            set -u
            drift=0
            journal_max_use_bytes={journal_max}
            storage_scan_result="$1"
            {fragment}
            """
        )
        return subprocess.run(
            ["bash", "-c", script, "storage-compliance", str(result_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _scan_storage_stores(self, root, limit=100):
        """Collect rows by executing each embedded scanner implementation."""
        stores = (("buffer", root / "buffer"), ("self_log", root / "self-log"),
                  ("syslog", root / "syslog"))
        rows = []
        for kind, path in stores:
            scanned = self._run_embedded_scan(self.validate, kind, path, limit=limit)
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            rows.append(scanned.stdout.strip())
        return "\n".join(rows) + "\n"

    def test_allowlist_and_single_journal_path(self):
        self.assertIn("systemd_journald", self.config)
        self.assertIn("proxy.service", self.config + self.reconcile)
        self.assertIn("superserve-secretsproxy.service", self.reconcile)
        self.assertIn("systemd.service", self.reconcile)
        self.assertNotIn("syslog-file", self.config)

    def test_parse_before_filter_and_platform_context(self):
        self.assertLess(self.config.index("parse_application_json"), self.config.index("exclude_debug_after_parse"))
        self.assertLess(self.config.index("capture_journal_provenance"), self.config.index("parse_application_json"))
        self.assertIn("labels.environment", self.config)
        self.assertIn("labels.region", self.config)
        self.assertIn("labels.host_id", self.config)
        self.assertIn("labels.instance_id", self.config)
        self.assertNotIn("copy_from: resource.labels.instance_name", self.config)
        self.assertIn("redact_sensitive_fields", self.config)
        self.assertIn("jsonPayload.level", self.config)
        self.assertIn("jsonPayload.body_snippet", self.config)
        self.assertIn("jsonPayload.MESSAGE", self.config)
        self.assertIn("allowlisted_application_fields", self.config)
        self.assertIn("drop_unallowlisted_payload", self.config)
        self.assertIn("jsonPayload:*", self.config)
        self.assertIn("labels.host_logging_heartbeat", self.config)
        self.assertNotIn("jsonPayload.severity == NULL", self.config)
        self.assertIn("default_pipeline:", self.config)

    def test_durable_retention_and_safe_activation(self):
        self.assertIn("SystemMaxUse", self.reconcile)
        self.assertIn("SystemKeepFree", self.reconcile)
        self.assertIn("journald_candidate_path", self.reconcile)
        self.assertIn("superserve-otel-collector.service", self.reconcile)
        self.assertIn("cmp -s", self.reconcile)
        self.assertIn("diagnose", self.reconcile)
        self.assertIn("exit 100", self.validate)

    def test_reconciliation_bounds_package_and_storage_transitions(self):
        # The selected package is diagnosed before activation, while the
        # previous package and service/configuration state are captured for
        # rollback if installation or activation fails.
        self.assertIn("apt-get download", self.reconcile)
        self.assertIn("staged_agent", self.reconcile)
        self.assertIn("old_package_version", self.reconcile)
        self.assertIn("package_change_attempted", self.reconcile)
        self.assertIn("apt-get install -y --no-install-recommends", self.reconcile)
        self.assertIn("storage_scan_timeout_seconds", self.reconcile)
        self.assertIn("storage_scan_timeout_seconds", self.validate)
        self.assertIn("storage_scan_max_entries", self.reconcile)
        self.assertIn("storage_scan_max_entries", self.validate)
        self.assertIn("activation_committed=1", self.reconcile)
        self.assertIn("trap on_exit EXIT", self.reconcile)
        self.assertIn("agent_self_log_max_bytes", self.reconcile)
        self.assertIn("syslog_max_bytes", self.reconcile)
        self.assertIn("heartbeat_interval_seconds", self.reconcile)
        self.assertIn("storage_remediation_deadline", self.reconcile)
        self.assertIn("disposable retention cleanup incomplete", self.reconcile)

    def test_validation_and_enforcement_render_identical_metrics_dropin(self):
        expected_comment = "# Keep the standalone application-metrics collector below the logging"
        self.assertIn(expected_comment, self.reconcile)
        self.assertIn(expected_comment, self.validate)

    def test_os_config_shell_reexec_and_bounded_storage_contract(self):
        for script in (self.reconcile, self.validate):
            self.assertIn('exec /bin/bash "$0" "$@"', script)
            self.assertIn("scan_limit=$((max_entries + 1))", script)
            self.assertNotIn("find /var/log -maxdepth 1", script)
            self.assertNotIn("| sort | head", script)
        self.assertIn("exit 100", self.reconcile)
        self.assertIn("storage_scan_deadline", self.reconcile)
        self.assertIn("logrotate -f", self.reconcile)

    def test_cleanup_and_failure_alert_producers_are_bounded(self):
        self.assertEqual(self.validate.count("trap "), 1)
        self.assertIn("cleanup()", self.validate)
        self.assertIn("storage_scan_result", self.validate)
        self.assertIn("ops_agent_self_log_files", self.config)
        self.assertIn("ops_agent_self_logs", self.config)

    def test_storage_scans_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "buffer").mkdir()
            (root / "self-log").mkdir()
            (root / "syslog").mkdir()
            (root / "self-log" / "logging-module.log").write_bytes(b"agent")
            (root / "syslog" / "syslog").write_bytes(b"journal")

            for template in (self.validate, self.reconcile):
                with self.subTest(template="validate" if template is self.validate else "reconcile"):
                    scanner_count = 3 if template is self.reconcile else 1
                    for occurrence in range(scanner_count):
                        valid = self._run_embedded_scan(template, "syslog", root / "syslog", occurrence=occurrence)
                        self.assertEqual(valid.returncode, 0, valid.stderr)
                        if occurrence != 1 or template is self.validate:
                            self.assertIn("syslog", valid.stdout)
                        for failure in ("open", "iteration", "stat"):
                            failed = self._run_embedded_scan(
                                template, "syslog", root / "syslog", failure=failure, occurrence=occurrence)
                            self.assertNotEqual(failed.returncode, 0, failure)

                    missing = self._run_embedded_scan(template, "buffer", root / "never-created")
                    self.assertEqual(missing.returncode, 0, missing.stderr)
                    self.assertEqual(missing.stdout.strip(), "buffer 0 0")

            for index in range(3):
                (root / "buffer" / f"chunk-{index}").write_bytes(b"x")
            capped = self._run_embedded_scan(self.validate, "buffer", root / "buffer", limit=1)
            self.assertEqual(capped.returncode, 0, capped.stderr)
            self.assertEqual(capped.stdout.strip(), "buffer 2 1")
            self.assertIn('[ "$storage_scan_capped" -eq 0 ]', self.validate)

    def test_storage_failure_preserves_activation_and_delivery_state(self):
        for template in (self.validate, self.reconcile):
            with self.subTest(template="validate" if template is self.validate else "reconcile"):
                self.assertIn('test -n "$kind" || exit 1', template)
                self.assertIn('[ "$seen_buffer" -eq 1 ] && [ "$seen_self_log" -eq 1 ] && [ "$seen_syslog" -eq 1 ] || exit 1', template)
        self.assertIn('if [ "$status" -ne 0 ] && [ "$activation_committed" -eq 0 ]', self.reconcile)
        self.assertIn('rollback || true', self.reconcile)
        self.assertIn('activation_committed=0', self.reconcile)
        self.assertIn('activation_committed=1', self.reconcile)
        self.assertIn('exit 101', self.validate)
        self.assertIn('checkpoint', self.reconcile.lower())
        self.assertIn('buffer', self.reconcile.lower())

    def test_selected_agent_export_boundary(self):
        order = [
            "capture_journal_provenance",
            "parse_application_json",
            "reset_promoted_special_fields",
            "add_platform_context",
            "redact_sensitive_fields",
            "allowlisted_application_fields",
            "drop_unallowlisted_payload",
            "exclude_debug_after_parse",
        ]
        positions = [self.config.index(name) for name in order]
        self.assertEqual(positions, sorted(positions))
        for promoted in ("labels:", "httpRequest:", "operation:", "sourceLocation:",
                         "spanId:", "trace:", "traceSampled:", "insertId:"):
            self.assertIn(promoted, self.config)
        for trusted in ("labels.host_id", "labels.incarnation", "labels.instance_id",
                        "labels.environment", "labels.region", "labels.unit"):
            self.assertIn(trusted, self.config)
        for untrusted in ("jsonPayload.authorization", "jsonPayload.request_body",
                          "jsonPayload.file_contents", "jsonPayload.command_payload",
                          "jsonPayload.MESSAGE"):
            self.assertIn(untrusted, self.config)
        self.assertIn("metadata only", self.config)
        self.assertIn("jsonPayload.level", self.config)
        self.assertIn("labels.host_logging_heartbeat", self.config)

    def test_selected_agent_buffer_budget(self):
        variables = (ROOT / "infra/modules/host-logging/variables.tf").read_text()
        module = (ROOT / "infra/modules/host-logging/main.tf").read_text()
        readme = (ROOT / "infra/modules/host-logging/README.md").read_text()
        self.assertIn('default     = "2.52.0"', variables)
        self.assertIn("platform-managed", variables + readme + self.reconcile)
        self.assertIn("disk-buffer", variables + readme + self.reconcile)
        self.assertIn("accounting/compliance threshold", self.config + self.validate + self.reconcile)
        self.assertIn("agent_buffer_bytes", module)
        self.assertIn("agent_self_log_max_bytes", module)
        self.assertIn("syslog_max_bytes", module)
        self.assertIn("journal_max_use_bytes + storage_bytes", self.validate)
        self.assertIn("journal_max_use_bytes + var.agent_buffer_bytes + var.agent_self_log_max_bytes + var.syslog_max_bytes", module)
        self.assertNotIn("Buffer_Max_Size", self.config + self.reconcile)
        self.assertIn("storage_scan_capped=1", self.validate)
        self.assertIn('[ "$storage_scan_capped" -eq 0 ] || drift=1', self.validate)
        self.assertIn('if [ "$storage_scan_capped" -ne 0 ]; then', self.reconcile)
        self.assertIn("pending buffer state preserved", self.reconcile)
        self.assertIn("activation_committed=1", self.reconcile)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for store in ("buffer", "self-log", "syslog"):
                (root / store).mkdir()
            (root / "buffer" / "chunk").write_bytes(b"buffer")
            (root / "self-log" / "agent.log").write_bytes(b"self-log")
            (root / "syslog" / "syslog").write_bytes(b"syslog")
            result_path = root / "storage-scan-result"
            checkpoint = root / "checkpoint"
            exporter_state = root / "exporter-state"
            checkpoint.write_text("pending checkpoint")
            exporter_state.write_text("validated exporter draining")

            result_path.write_text(self._scan_storage_stores(root))
            compliant = self._run_storage_compliance(result_path)
            self.assertEqual(compliant.returncode, 100, compliant.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            (root / "buffer" / "chunk-2").write_bytes(b"buffer")
            (root / "buffer" / "chunk-3").write_bytes(b"buffer")
            result_path.write_text(self._scan_storage_stores(root, limit=1))
            capped = self._run_storage_compliance(result_path)
            self.assertEqual(capped.returncode, 101, capped.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            unreadable = self._run_embedded_scan(
                self.validate, "buffer", root / "buffer", failure="stat"
            )
            self.assertNotEqual(unreadable.returncode, 0)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            result_path.write_text("buffer 1 0\nself_log 1 0\n")
            incomplete = self._run_storage_compliance(result_path)
            self.assertNotEqual(incomplete.returncode, 0)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            result_path.write_text("buffer 11 0\nself_log 1 0\nsyslog 1 0\n")
            over_budget = self._run_storage_compliance(result_path)
            self.assertEqual(over_budget.returncode, 101, over_budget.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")


if __name__ == "__main__":
    unittest.main()
