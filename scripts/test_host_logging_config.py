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


if __name__ == "__main__":
    unittest.main()
