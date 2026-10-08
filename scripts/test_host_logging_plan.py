import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gate", ROOT / "scripts/host_logging_plan.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def plan():
    # Provider-shaped plan emitted by terraform test -json -verbose from the
    # real host-logging and observability modules with mocked cloud providers.
    return json.loads((ROOT / "scripts/fixtures/host_logging_module_plan.json").read_text())


def resource(data, suffix):
    return next(item["change"] for item in data["resource_changes"] if suffix in item["address"])


class HostLoggingPlanTests(unittest.TestCase):
    def test_invalid_plan_cannot_be_treated_as_no_logging_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.json"
            for content, status, output in (
                ("invalid json", 1, ""), ("{}", 1, ""),
                (json.dumps({"resource_changes": []}), 0, "false"),
                (json.dumps(plan()), 0, "true"),
            ):
                source.write_text(content)
                result = subprocess.run([sys.executable, str(ROOT / "scripts/host_logging_plan.py"), str(source)], capture_output=True, text=True)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout.strip(), output)

    def test_migration_transition_uses_plan_without_external_receipt(self):
        data = json.loads((ROOT / "scripts/fixtures/host_logging_migration_plan.json").read_text())
        change = resource(data, "terraform_data.legacy_migration")
        change["before"] = copy.deepcopy(change["after"])
        change["before"]["input"]["phase"] = "drain"
        MODULE.validate_migration_transition(data)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.json"
            source.write_text(json.dumps(data))
            result = subprocess.run([sys.executable, str(ROOT / "scripts/host_logging_plan.py"),
                                     "--check", str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

        change["before"]["input"]["phase"] = "preserve"
        with self.assertRaisesRegex(ValueError, "transition"):
            MODULE.validate_migration_transition(data)

    def test_unrelated_host_replacement_is_not_a_logging_change(self):
        data = {"resource_changes": [{"address": "module.sandbox_host.google_compute_instance.host", "change": {"actions": ["delete", "create"]}}]}
        self.assertFalse(MODULE.changes_host_logging(data))
        data["resource_changes"] += plan()["resource_changes"]
        self.assertTrue(MODULE.changes_host_logging(data))


if __name__ == "__main__":
    unittest.main()
