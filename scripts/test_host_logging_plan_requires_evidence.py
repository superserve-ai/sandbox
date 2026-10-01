import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "host_logging_plan_requires_evidence", ROOT / "scripts/host_logging_plan_requires_evidence.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def plan(environment, region, hosts):
    resources = [
        {
            "address": "module.host_logging.google_os_config_os_policy_assignment.host_logging",
            "change": {"after": {"instance_filter": {"inclusion_labels": [{
                "labels": {"application": "sandbox-host", "environment": environment, "region": region}
            }]}, "os_policies": [{"id": "host-logging", "mode": "ENFORCEMENT"}]}},
        },
    ]
    for host in hosts:
        resources.append({
            "address": f'module.host_logging.google_project_iam_member.log_writer["{host}"]',
            "change": {"after": {"member": f"serviceAccount:{host}@example.test", "role": "roles/logging.logWriter"}},
        })
    resources.extend([
        {
            "address": f'module.host_logging.google_storage_bucket_object.ops_agent_config["{host}"]',
            "change": {"after": {"content": (
                f"labels.environment: {environment}\nlabels.region: {region}\n"
                f"# {host}: host_id={host}-identity\n"
                "receivers: systemd_journald\n"
            )}},
        }
        for host in hosts
    ])
    resources.append({
        "address": f'module.observability.google_monitoring_alert_policy.host_logging_export_failures["{hosts[0]}"]',
        "change": {"after": {"conditions": [{"filter": f'resource.labels.instance_id="{hosts[0]}-id"', "duration": "300s"}]}},
    })
    return {"resource_changes": resources}


class HostLoggingDigestTests(unittest.TestCase):
    def test_equivalent_environment_and_host_substitutions_share_digest(self):
        staging = plan("staging", "us-central1", ["sandbox_host", "sandbox_host_b"])
        production = plan("production", "us-west2", ["sandbox_host_b"])
        self.assertEqual(MODULE.deployment_content_digest(staging), MODULE.deployment_content_digest(production))

    def test_selector_widening_and_functional_changes_change_digest(self):
        baseline = plan("staging", "us-central1", ["sandbox_host", "sandbox_host_b"])
        widened = copy.deepcopy(baseline)
        labels = widened["resource_changes"][0]["change"]["after"]["instance_filter"]["inclusion_labels"][0]["labels"]
        labels["application"] = "*"
        self.assertNotEqual(MODULE.deployment_content_digest(baseline), MODULE.deployment_content_digest(widened))

        for mutation in ("script", "pipeline", "resource_limit", "alert"):
            changed = copy.deepcopy(baseline)
            content_item = next(item for item in changed["resource_changes"]
                                if "google_storage_bucket_object.ops_agent_config" in item["address"])
            if mutation == "script":
                content_item["change"]["after"]["content"] += "drop: debug\n"
            elif mutation == "pipeline":
                changed["resource_changes"][0]["change"]["after"]["os_policies"][0]["mode"] = "AUDIT"
            elif mutation == "resource_limit":
                content_item["change"]["after"]["content"] += "MemoryMax=256M\n"
            else:
                changed["resource_changes"][-1]["change"]["after"]["conditions"][0]["duration"] = "60s"
            with self.subTest(mutation=mutation):
                self.assertNotEqual(MODULE.deployment_content_digest(baseline), MODULE.deployment_content_digest(changed))

    def test_unknown_functional_content_rejected(self):
        baseline = plan("staging", "us-central1", ["sandbox_host"])

        # Unknown leaves, ancestors, and list elements can conceal a selector,
        # script, policy, or grant.  The digest must fail closed rather than
        # treating an incomplete plan as equivalent to a reviewed one.
        cases = []
        for unknown in (
                {"content": True},
                {"content": {"nested": True}},
                {"content": [True]},
        ):
            changed = copy.deepcopy(baseline)
            item = next(entry for entry in changed["resource_changes"]
                        if "google_storage_bucket_object.ops_agent_config" in entry["address"])
            item["change"]["after_unknown"] = unknown
            cases.append(("functional", changed))

        # Provider metadata is the only intentionally tolerated unknown.  It
        # must not make the complete digest unavailable.
        metadata = copy.deepcopy(baseline)
        metadata_item = next(entry for entry in metadata["resource_changes"]
                             if "google_storage_bucket_object.ops_agent_config" in entry["address"])
        metadata_item["change"]["after_unknown"] = {"generation": True, "etag": True}
        self.assertRegex(MODULE.deployment_content_digest(metadata), r"^[0-9a-f]{64}$")

        for label, changed in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    MODULE.deployment_content_digest(changed)

        # An omitted functional value is not equivalent to a known empty value
        # when Terraform marks its parent unresolved.
        omitted = copy.deepcopy(baseline)
        policy = omitted["resource_changes"][0]["change"]
        policy["after"].pop("os_policies")
        policy["after_unknown"] = {"os_policies": True}
        with self.assertRaises(ValueError):
            MODULE.deployment_content_digest(omitted)

        with self.assertRaisesRegex(ValueError, "digest unavailable"):
            MODULE.deployment_content_digest({"resource_changes": []})


if __name__ == "__main__":
    unittest.main()
