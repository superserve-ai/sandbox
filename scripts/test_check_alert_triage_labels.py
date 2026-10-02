import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-alert-triage-labels.py")
spec = importlib.util.spec_from_file_location("check_alert_triage_labels", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = SCRIPT.parents[1]


class TriageCoverageChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        shutil.copytree(ROOT / "infra", self.root / "infra")

    def test_current_inventory(self):
        self.assertEqual(module.check(self.root), [])

    def test_new_policy_requires_reviewed_mapping(self):
        path = self.root / "infra/modules/cloud-ids/main.tf"
        path.write_text(path.read_text() + '\nresource "google_monitoring_alert_policy" "example_alert" {}\n')
        self.assertTrue(any("google_monitoring_alert_policy.example_alert" in error for error in module.check(self.root)))

    def test_missing_generated_variant_mapping(self):
        path = self.root / "infra/alerts/runbook-map.md"
        path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.startswith("| `backup[backlog_age]` |")))
        self.assertTrue(any("google_monitoring_alert_policy.backup" in error for error in module.check(self.root)))

    def test_new_generated_variant_requires_review(self):
        path = self.root / "infra/modules/observability/backup-alerts.tf"
        path.write_text(path.read_text().replace("    backlog_age = {", "    new_variant = {}\n    backlog_age = {", 1))
        self.assertTrue(any("google_monitoring_alert_policy.backup[new_variant]" in error for error in module.check(self.root)))

    def test_aggregate_operation_must_be_unset(self):
        path = self.root / "infra/alerts/runbook-map.md"
        path.write_text(path.read_text().replace("| `sandbox_failed` | `lifecycle_failure` | `sandbox_lifecycle` | `api` | `lifecycle_failure` | — |", "| `sandbox_failed` | `lifecycle_failure` | `sandbox_lifecycle` | `api` | `lifecycle_failure` | `create` |"))
        self.assertTrue(any("aggregate operation" in error for error in module.check(self.root)))


if __name__ == "__main__":
    unittest.main()
