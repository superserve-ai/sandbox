import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HostLoggingConfigChecks(unittest.TestCase):
    def setUp(self):
        self.config = (ROOT / "infra/modules/host-logging/templates/ops-agent.yaml.tftpl").read_text()
        self.reconcile = (ROOT / "infra/modules/host-logging/templates/reconcile.sh.tftpl").read_text()
        self.validate = (ROOT / "infra/modules/host-logging/templates/validate.sh.tftpl").read_text()

    def test_allowlist_and_single_journal_path(self):
        self.assertIn("systemd_journald", self.config)
        self.assertIn("proxy.service", self.config + self.reconcile)
        self.assertIn("superserve-secretsproxy.service", self.reconcile)
        self.assertIn("systemd.service", self.reconcile)
        self.assertNotIn("syslog-file", self.config)

    def test_parse_before_filter_and_platform_context(self):
        self.assertLess(self.config.index("parse_application_json"), self.config.index("exclude_debug_after_parse"))
        self.assertIn("labels.environment", self.config)
        self.assertIn("labels.region", self.config)
        self.assertIn("labels.host_id", self.config)
        self.assertIn("labels.instance_id", self.config)
        self.assertNotIn("copy_from: resource.labels.instance_name", self.config)
        self.assertIn("redact_sensitive_fields", self.config)
        self.assertIn("jsonPayload.level", self.config)
        self.assertIn("jsonPayload.body_snippet", self.config)
        self.assertIn("jsonPayload.MESSAGE", self.config)
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


if __name__ == "__main__":
    unittest.main()
