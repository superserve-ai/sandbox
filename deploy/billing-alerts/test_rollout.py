import copy
import os
from pathlib import Path
import subprocess
import textwrap
import unittest

import check_plan


class PlanBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"resource_changes": [
            {"address": address, "type": "google_monitoring_alert_policy",
             "change": {"actions": ["create"], "after": {
                 "project": "rayai-prod", "enabled": True,
                 "notification_channels": [check_plan.CHANNEL]}}}
            for address in sorted(check_plan.ADDRESSES)
        ]}

    def test_initial_creation_and_idempotent_retry(self):
        check_plan.validate(self.plan)
        self.plan["resource_changes"][0]["change"]["actions"] = ["no-op"]
        check_plan.validate(self.plan)

    def test_existing_policy_adoption_and_destructive_changes_rejected(self):
        for actions in (["update"], ["delete"], ["delete", "create"]):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"][0]["change"]["actions"] = actions
            with self.assertRaises(ValueError):
                check_plan.validate(plan)
        plan = copy.deepcopy(self.plan)
        plan["resource_changes"][0]["change"].update(
            actions=["no-op"], importing={"id": "existing-policy"})
        with self.assertRaises(ValueError):
            check_plan.validate(plan)

    def test_extra_missing_and_duplicate_resources_rejected(self):
        resource = copy.deepcopy(self.plan["resource_changes"][0])
        for resources in (
            self.plan["resource_changes"][:-1],
            self.plan["resource_changes"] + [resource],
            self.plan["resource_changes"][:-1] + [resource],
        ):
            with self.assertRaises(ValueError):
                check_plan.validate({"resource_changes": resources})
        self.plan["resource_changes"][0]["address"] = (
            'module.billing_alerts.google_monitoring_alert_policy.entitlement_metric["paid_missing"]')
        with self.assertRaises(ValueError):
            check_plan.validate(self.plan)

    def test_wrong_project_disabled_or_rerouted_policy_rejected(self):
        for key, value in (("project", "example-other-project"), ("enabled", False),
                           ("notification_channels", ["projects/rayai-prod/notificationChannels/999"])):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"][0]["change"]["after"][key] = value
            with self.assertRaises(ValueError):
                check_plan.validate(plan)


class RequestBoundaryTests(unittest.TestCase):
    def test_apply_requires_exact_main_revision_and_saved_plan_identity(self):
        workflow = (Path(__file__).parents[2] / ".github/workflows/billing-alert-rollout.yml").read_text()
        script = textwrap.dedent(workflow.split("        run: |\n", 1)[1].split("\n  plan:", 1)[0])
        env = dict(os.environ, GITHUB_REF="refs/heads/main", GITHUB_SHA="a" * 40,
                   EXPECTED_REVISION="a" * 40, OPERATION="apply", PLAN_RUN_ID="123",
                   PLAN_SHA256="b" * 64)

        def accepted(overrides):
            return subprocess.run(["bash", "-c", script], env=env | overrides,
                                  capture_output=True).returncode == 0

        self.assertTrue(accepted({}))
        self.assertTrue(accepted(dict(OPERATION="plan", PLAN_RUN_ID="", PLAN_SHA256="")))
        for overrides in (
            dict(GITHUB_REF="refs/heads/feature"), dict(EXPECTED_REVISION="c" * 40),
            dict(EXPECTED_REVISION="$(false)"), dict(PLAN_RUN_ID=""),
            dict(PLAN_RUN_ID="123/../../other"), dict(PLAN_SHA256=""),
            dict(PLAN_SHA256="not-a-digest"), dict(OPERATION="other"),
            dict(OPERATION="plan"),
        ):
            with self.subTest(overrides=overrides):
                self.assertFalse(accepted(overrides))


if __name__ == "__main__":
    unittest.main()
