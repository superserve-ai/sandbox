import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-alert-runbooks.py")
spec = importlib.util.spec_from_file_location("check_alert_runbooks", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = SCRIPT.parents[1]


class RunbookCoverageChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        shutil.copytree(ROOT / "infra", self.root / "infra")

    def test_current_inventory(self):
        self.assertEqual(module.check(self.root), [])

    def test_new_policy_requires_reviewed_mapping(self):
        path = self.root / "infra/modules/observability/main.tf"
        path.write_text(path.read_text() + '\nresource "google_monitoring_alert_policy" "example_alert" {}\n')
        self.assertTrue(any("google_monitoring_alert_policy.example_alert" in error for error in module.check(self.root)))

    def test_disabled_policy_requires_mapping(self):
        path = self.root / "infra/alerts/runbook-map.md"
        path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.startswith("| `ids_medium` (disabled) |")))
        self.assertTrue(any("google_monitoring_alert_policy.ids_medium" in error for error in module.check(self.root)))

    def test_generated_variant_requires_mapping(self):
        path = self.root / "infra/alerts/runbook-map.md"
        path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.startswith("| `launch_path[launcher_not_ready]` |")))
        self.assertTrue(any("google_monitoring_alert_policy.launch_path" in error for error in module.check(self.root)))

    def test_new_generated_variants_require_review(self):
        cases = (
            ("backup-alerts.tf", "    upload_failures = {", "backup"),
            ("backup-alerts.tf", "      uncovered_paused = {", "backup_coverage"),
            ("backup-alerts.tf", "    root_fs_warning = {", "host_disk"),
            ("launch-path-alerts.tf", "    launcher_not_ready = {", "launch_path"),
        )
        for filename, anchor, policy in cases:
            with self.subTest(policy=policy):
                path = self.root / "infra/modules/observability" / filename
                original = path.read_text()
                indent = " " * (len(anchor) - len(anchor.lstrip()))
                path.write_text(original.replace(anchor, f"{indent}new_variant = {{}}\n{anchor}", 1))
                self.assertTrue(any(f"google_monitoring_alert_policy.{policy}[new_variant]" in error for error in module.check(self.root)))
                path.write_text(original)

    def test_changed_region_generated_variant_requires_review(self):
        path = self.root / "infra/modules/observability/backup-alerts.tf"
        path.write_text(path.read_text().replace('"uncovered_paused_${region}" => {', '"new_variant_${region}" => {', 1))
        errors = module.check(self.root)
        self.assertTrue(any("backup_coverage[new_variant_<region>]" in error for error in errors))
        self.assertTrue(any("backup_coverage[uncovered_paused_<region>]" in error for error in errors))

    def test_new_lifecycle_operation_requires_review(self):
        path = self.root / "infra/envs/production/us-central1/sandbox-lifecycle-alerts.tf"
        path.write_text(path.read_text().replace("    create = {", "    new_variant = {}\n    create = {", 1))
        self.assertTrue(any("google_monitoring_alert_policy.sandbox_lifecycle_latency[new_variant]" in error for error in module.check(self.root)))


if __name__ == "__main__":
    unittest.main()
