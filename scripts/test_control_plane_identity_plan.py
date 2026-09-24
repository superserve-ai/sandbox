import importlib.util
import io
import json
import re
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
    def test_shared_queue_preserves_multiple_pending_deployments(self):
        workflows = SCRIPT.parent.parent / ".github/workflows"
        participants = {
            path.name for path in workflows.glob("*.yml")
            if "group: control-plane-deploy" in path.read_text()
        }
        self.assertEqual(participants, {
            "control-plane-identity-rollout.yml", "deploy-api.yml", "terraform-cd.yml",
            "terraform-rollout-staging.yml", "terraform-rollout-production.yml",
        })
        # GitHub's native max queue retains both pending CD/API runs behind
        # an active rollout; every participant must opt out of the single slot.
        for name in participants:
            with self.subTest(workflow=name):
                block = re.search(r"^concurrency:\n((?:[ \t]+[^\n]*\n)+)", (workflows / name).read_text(), re.M).group(1)
                self.assertIn("  group: control-plane-deploy\n", block)
                self.assertIn("  queue: max\n", block)
                self.assertIn("  cancel-in-progress: false\n", block)

    def test_production_pins_before_planning_and_checks_saved_traffic(self):
        workflow = (SCRIPT.parent.parent / ".github/workflows/terraform-cd.yml").read_text()
        for region, cell in (("us-west2", "usw2"), ("us-east4", "use4")):
            with self.subTest(region=region):
                block = workflow.split(f"cd infra/envs/production/{region}\n", 1)[1].split("trap - EXIT", 1)[0]
                live_commands = block.split("trap rollback EXIT\n", 1)[1]
                self.assertLess(live_commands.index('--to-revisions "${previous}=100"'), live_commands.index("terraform plan"))
                guard = f'--cell production-{cell} --pinned-revision "$previous"'
                self.assertLess(live_commands.index("terraform plan"), live_commands.index(guard))
                self.assertLess(live_commands.index(guard), live_commands.index("terraform apply"))

    def test_template_update_preserves_explicit_previous_revision_in_saved_plan(self):
        before = {**service("reader@example.com"), "traffic": [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "api-old", "percent": 100}]}
        after = {**before, "template": [{"service_account": "reader@example.com", "containers": [{"env": [{"name": "EXAMPLE", "value": "new"}]}]}]}
        candidate = plan(["update"], before, after)
        self.assertIsNone(MODULE.changed_identity(candidate))
        self.assertTrue(MODULE.traffic_is_pinned(candidate, "api-old"))
        tagged = {**after, "traffic": after["traffic"] + [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "api-older", "percent": 0, "tag": "previous"}]}
        self.assertTrue(MODULE.traffic_is_pinned(plan(["update"], before, tagged), "api-old"))
        for traffic in (
            [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", "percent": 100}],
            [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "api-new", "percent": 100}],
            [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": "api-old", "percent": 50}],
            [], None,
        ):
            with self.subTest(traffic=traffic):
                self.assertFalse(MODULE.traffic_is_pinned(plan(["update"], before, {**after, "traffic": traffic}), "api-old"))

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
