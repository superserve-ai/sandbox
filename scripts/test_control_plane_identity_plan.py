import importlib.util
import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_control_plane_identity_plan.py")
SPEC = importlib.util.spec_from_file_location("check_control_plane_identity_plan", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def plan(actions, before, after):
    return {
        "resource_changes": [
            {
                "address": MODULE.API_RESOURCE,
                "change": {"actions": actions, "before": before, "after": after},
            }
        ]
    }


def service(account):
    return {"template": [{"service_account": account}]}


class ControlPlaneIdentityPlanTests(unittest.TestCase):
    def test_automatic_workflow_gates_every_serving_cell(self):
        workflow = (SCRIPT.parent.parent / ".github/workflows/terraform-cd.yml").read_text()
        for cell in ("staging", "production-usw2", "production-use4"):
            self.assertIn(
                f"check_control_plane_identity_plan.py\" --cell {cell}",
                workflow,
            )

    def test_noop_plan_is_allowed(self):
        self.assertIsNone(MODULE.changed_identity(plan(["no-op"], service("old"), service("old"))))

    def test_unrelated_api_update_with_same_identity_is_allowed(self):
        before = service("cell@example.iam.gserviceaccount.com")
        after = {**service("cell@example.iam.gserviceaccount.com"), "ingress": "internal"}
        self.assertIsNone(MODULE.changed_identity(plan(["update"], before, after)))

    def test_identity_update_is_rejected(self):
        transition = MODULE.changed_identity(
            plan(
                ["update"],
                service("legacy@example.iam.gserviceaccount.com"),
                service("cell@example.iam.gserviceaccount.com"),
            )
        )
        self.assertIsNotNone(transition)

    def test_create_and_incomplete_plan_are_rejected(self):
        self.assertIsNotNone(MODULE.changed_identity(plan(["create"], None, service("cell@example.com"))))
        self.assertIsNotNone(MODULE.changed_identity(plan(["update"], None, service("cell@example.com"))))

    def test_main_reports_staged_workflow(self):
        payload = json.dumps(plan(["update"], service("old@example.com"), service("new@example.com")))
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            original_stdin = MODULE.sys.stdin
            original_argv = MODULE.sys.argv
            try:
                MODULE.sys.stdin = io.StringIO(payload)
                MODULE.sys.argv = [str(SCRIPT), "--cell", "staging"]
                self.assertEqual(MODULE.main(), 1)
            finally:
                MODULE.sys.stdin = original_stdin
                MODULE.sys.argv = original_argv
        self.assertIn("staged control-plane identity rollout", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
