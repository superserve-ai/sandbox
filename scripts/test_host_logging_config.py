import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infra/modules/host-logging"


class HostLoggingConfigChecks(unittest.TestCase):
    def setUp(self):
        self.config = (MODULE / "templates/otel-logs.yaml.tftpl").read_text()
        self.service = (MODULE / "templates/otel-logs.service.tftpl").read_text()
        self.reconcile = (MODULE / "templates/reconcile.sh.tftpl").read_text()
        self.validate = (MODULE / "templates/validate.sh.tftpl").read_text()
        self.variables = (MODULE / "variables.tf").read_text()

    def test_allowlist_and_single_journal_path(self):
        self.assertIn("journald:", self.config)
        self.assertIn("filter/approved_sources:", self.config)
        self.assertIn("filter/info_plus:", self.config)
        self.assertIn("parse_application_message", self.config)
        self.assertIn("clear_untrusted_body", self.config)
        self.assertIn("host_logging.parse_outcome", self.config)
        self.assertNotIn("filelog/", self.config)
        self.assertNotIn("ops-agent", self.config.lower())
        self.assertEqual(self.config.count("receivers: [journald]"), 1)
        self.assertIn("googlecloud:", self.config)

    def test_trusted_metadata_and_collision_resistance_contract(self):
        for field in ("host_id", "provider_instance_id", "incarnation", "environment", "region", "unit", "generation"):
            self.assertIn(field, self.config)
        for field in ("delete_key(attributes[\"application\"], \"host_id\")",
                      "delete_key(attributes[\"application\"], \"labels\")",
                      "delete_key(attributes[\"application\"], \"parse_outcome\")",
                      "delete_key(attributes[\"application\"], \"httpRequest\")"):
            self.assertIn(field, self.config)
        self.assertIn("raw_body_discarded", self.config)

    def test_release_and_state_are_pinned_and_separate(self):
        self.assertRegex(self.variables, r'otel_release_version[^\n]+')
        self.assertRegex(self.variables, r'default\s+=\s+"0\.119\.0"')
        self.assertRegex(self.variables, r'default\s+=\s+"[0-9a-f]{64}"')
        self.assertIn("file_storage/cursor", self.config)
        self.assertIn("file_storage/queue", self.config)
        self.assertIn("otel_queue_max_bytes", self.variables)
        self.assertIn("${cursor_dir}", self.service)
        self.assertIn("${queue_dir}", self.service)
        self.assertNotIn("superserve-otel-collector.service", self.service)

    def test_candidate_validation_and_failure_preservation(self):
        self.assertIn('validate --config', self.reconcile)
        self.assertIn('sha256sum -c', self.reconcile)
        self.assertIn('trap rollback EXIT', self.reconcile)
        self.assertIn('activation_committed=1', self.reconcile)
        self.assertIn('cmp -s', self.reconcile)
        self.assertIn('host-identity.json', self.reconcile)
        self.assertIn('host-logging-identity.env', self.reconcile)
        self.assertIn('superserve-host-logging-heartbeat.timer', self.reconcile)
        self.assertIn('${heartbeat_interval_seconds}s', self.reconcile)
        self.assertIn('storage: file_storage/cursor', self.validate)
        self.assertIn('storage: file_storage/queue', self.validate)


if __name__ == "__main__":
    unittest.main()
