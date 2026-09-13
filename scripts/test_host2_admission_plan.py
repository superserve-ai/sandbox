import copy
import unittest
from check_host2_admission_plan import HOST, LABEL_FIELDS, validate


class AdmissionPlanTest(unittest.TestCase):
    def plan(self, ready=False):
        old = {"component": "vmd" if ready else "vmd-staging-standby",
               "sandbox_status": "provisioning", "environment": "staging"}
        new = dict(old, component="vmd", sandbox_status="ready" if ready else "provisioning")
        before = {"name": "superserve-vmd-staging-2", "id": "example-instance", "instance_id": "123",
                  "boot_disk": [{"source": "example-boot"}], "attached_disk": [{"source": "example-data"}],
                  "service_account": [{"email": "runtime@example.test"}],
                  "workload_identity_config": [{"identity": "example.test/ns/vmd/sa/peer"}]}
        before.update({k: old.copy() for k in LABEL_FIELDS})
        after = copy.deepcopy(before)
        after.update({k: new.copy() for k in LABEL_FIELDS})
        return {"resource_changes": [{"address": HOST, "change": {
            "actions": ["update"], "before": before, "after": after,
            "after_unknown": {"label_fingerprint": True}}}]}

    def test_both_label_only_transitions(self):
        validate(self.plan())
        validate(self.plan(ready=True))

    def test_rejects_other_actions_and_unknowns(self):
        for case in ("replace", "dashboard", "host1", "disk", "identity", "account", "name",
                     "unknown", "skip", "other-label", "empty"):
            with self.subTest(case=case):
                plan = self.plan()
                change = plan["resource_changes"][0]["change"]
                if case == "replace": change["actions"] = ["delete", "create"]
                if case in ("dashboard", "host1"):
                    plan["resource_changes"].append({"address": case, "change": {"actions": ["update"]}})
                if case == "disk": change["after"]["attached_disk"] = []
                if case == "identity": change["after"]["workload_identity_config"] = []
                if case == "account": change["after"]["service_account"] = []
                if case == "name": change["after"]["name"] = "other-host"
                if case == "unknown": change["after_unknown"]["instance_id"] = True
                if case == "skip": change["after"]["labels"]["sandbox_status"] = "ready"
                if case == "other-label": change["after"]["labels"]["environment"] = "production"
                if case == "empty": plan["resource_changes"] = []
                with self.assertRaises(ValueError): validate(plan)


if __name__ == "__main__":
    unittest.main()
