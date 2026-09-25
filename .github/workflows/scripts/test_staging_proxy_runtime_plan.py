"""Check that the staging IAM migration cannot expand beyond its approved binding."""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "runtime_plan", Path(__file__).resolve().parents[3] / "scripts/check_staging_proxy_runtime_plan.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class RuntimePlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = {"resource_changes": [
            {"address": guard.BINDING, "change": {
                "actions": ["delete", "create"],
                "before": dict(guard.IDENTITY, condition=guard.CONDITION),
                "after": dict(guard.IDENTITY, condition=[]),
            }},
            {"address": guard.ROLE, "change": {
                "actions": ["no-op"],
                "after": {"project": guard.IDENTITY["project"],
                          "name": guard.IDENTITY["role"], "permissions": list(guard.PERMISSIONS)},
            }},
        ]}

    def test_exact_transition_and_idempotent_retry(self):
        guard.validate(self.plan)
        binding = self.plan["resource_changes"][0]["change"]
        binding["actions"] = ["no-op"]
        binding["before"]["condition"] = []
        guard.validate(self.plan)

    def test_rejects_other_scope_and_condition(self):
        for side in ("before", "after"):
            for field, value in (("project", "example-production"), ("role", "roles/owner"),
                                 ("member", "user:operator@example.com"),
                                 ("condition", [{"expression": "true"}])):
                with self.subTest(side=side, field=field):
                    plan = copy.deepcopy(self.plan)
                    plan["resource_changes"][0]["change"][side][field] = value
                    with self.assertRaises(ValueError):
                        guard.validate(plan)

    def test_fresh_grant_requires_the_same_exact_identity_and_permissions(self):
        binding = self.plan["resource_changes"][0]["change"]
        binding.update(actions=["create"], before=None)
        guard.validate(self.plan)
        for field, value in (("project", "example-production"), ("role", "roles/owner"),
                             ("member", "user:operator@example.com"),
                             ("condition", [{"expression": "true"}])):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"][0]["change"]["after"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                guard.validate(plan)
        self.plan["resource_changes"][1]["change"]["actions"] = ["create"]
        with self.assertRaises(ValueError):
            guard.validate(self.plan)

    def test_rejects_role_edits_and_additional_permissions(self):
        for mutation in ("actions", "permissions", "name"):
            plan = copy.deepcopy(self.plan)
            role = plan["resource_changes"][1]["change"]
            if mutation == "actions":
                role["actions"] = ["update"]
            elif mutation == "permissions":
                role["after"]["permissions"].append("compute.networkEndpointGroups.delete")
            else:
                role["after"]["name"] = "roles/owner"
            with self.assertRaises(ValueError):
                guard.validate(plan)

    def test_rejects_imports_missing_resources_and_other_mutations(self):
        for kind in ("import", "move", "missing-role", "extra", "create", "delete", "unknown"):
            plan = copy.deepcopy(self.plan)
            binding = plan["resource_changes"][0]
            if kind == "import":
                binding["change"]["importing"] = {"id": "example"}
            elif kind == "move":
                binding["previous_address"] = "example.old"
            elif kind == "missing-role":
                plan["resource_changes"].pop()
            elif kind == "extra":
                plan["resource_changes"].append({"address": "google_compute_url_map.proxy"})
            elif kind == "unknown":
                binding["change"]["after"].pop("member")
            else:
                binding["change"]["actions"] = [kind]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                guard.validate(plan)


if __name__ == "__main__":
    unittest.main()
