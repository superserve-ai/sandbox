import copy
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gate", ROOT / "scripts/host_logging_plan_requires_evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def plan():
    # Provider-shaped plan emitted by terraform test -json -verbose from the
    # real host-logging and observability modules with mocked cloud providers.
    return json.loads((ROOT / "scripts/fixtures/host_logging_module_plan.json").read_text())


def resource(data, suffix):
    return next(item["change"] for item in data["resource_changes"] if suffix in item["address"])


class HostLoggingDigestTests(unittest.TestCase):
    def test_gate_errors_cannot_be_treated_as_no_evidence_required(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.json"
            for content, status, output in (
                ("invalid json", 1, ""), ("{}", 1, ""),
                (json.dumps({"resource_changes": []}), 0, "false"),
                (json.dumps(plan()), 0, "true"),
            ):
                source.write_text(content)
                result = subprocess.run([sys.executable, str(ROOT / "scripts/host_logging_plan_requires_evidence.py"), str(source)], capture_output=True, text=True)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout.strip(), output)

    def test_real_plan_and_deployment_context_substitutions(self):
        staging = plan()
        production = json.loads(json.dumps(staging).replace("example-project", "production-project").replace("staging", "production").replace("us-central1", "us-east4").replace("example-host-logging", "production-host-logging").replace('"123"', '"456"').replace('\\"123\\"', '\\"456\\"').replace("incarnation-a", "incarnation-b").replace("example-vmd-1", "example-vmd-2").replace("_pilot", "_replacement"))
        for item in production["resource_changes"]:
            after = item["change"].get("after") or {}
            if "notification_channels" in after:
                after["notification_channels"] = [channel.replace("notificationChannels/456", "notificationChannels/123") for channel in after["notification_channels"]]
        self.assertEqual(MODULE.deployment_content_digest(staging), MODULE.deployment_content_digest(production))
        self.assertEqual(MODULE.configuration_revision(staging), "2026-10-01-otel-1")

    def test_staging_evidence_gate_binds_revision_digest_and_channel_map(self):
        staging = plan()
        production = copy.deepcopy(staging)
        for item in production["resource_changes"]:
            after = item["change"].get("after") or {}
            if "notification_channels" in after:
                after["notification_channels"] = [channel.replace("notificationChannels/123", "notificationChannels/456") for channel in after["notification_channels"]]
        channel_map = {"projects/example-project/notificationChannels/456": "projects/example-project/notificationChannels/123"}
        evidence = {
            "environment": "staging",
            "accepted": True,
            "configuration_revision": MODULE.configuration_revision(staging),
            "deployment_content_digest": MODULE.deployment_content_digest(staging),
            "notification_channel_map": channel_map,
        }
        MODULE.check_evidence(production, evidence)
        for field, value in (
            ("environment", "production"),
            ("accepted", False),
            ("configuration_revision", "wrong-revision"),
            ("deployment_content_digest", "wrong-digest"),
            ("notification_channel_map", {}),
            ("notification_channel_map", {**channel_map, "projects/example-project/notificationChannels/456": "bad"}),
            ("notification_channel_map", {"projects/example-project/notificationChannels/456": "projects/example-project/notificationChannels/999"}),
        ):
            changed = copy.deepcopy(evidence)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                MODULE.check_evidence(production, changed)

    def test_functional_changes_cannot_reuse_staging_evidence(self):
        baseline = plan()
        expected = MODULE.deployment_content_digest(baseline)
        for mutation in ("selector", "path", "script", "pipeline", "role", "threshold", "query", "channels", "routing", "runbook"):
            changed = copy.deepcopy(baseline)
            assignment = resource(changed, "google_os_config_os_policy_assignment.")["after"]
            resources = assignment["os_policies"][0]["resource_groups"][0]["resources"]
            if mutation == "selector":
                assignment["instance_filter"][0]["inclusion_labels"][0]["labels"]["application"] = "*"
            elif mutation == "path":
                resources[0]["file"][0]["path"] = "/etc/unintended.yaml"
            elif mutation == "script":
                resource(changed, "google_storage_bucket_object.reconcile_script")["after"]["content"] += "\nexit 0\n"
            elif mutation == "pipeline":
                resource(changed, "google_storage_bucket_object.otel_config")["after"]["content"] += "\nunsafe_pipeline: true\n"
            elif mutation == "role":
                resource(changed, "google_project_iam_member.telemetry_consumer")["after"]["role"] = "roles/owner"
            elif mutation == "threshold":
                resource(changed, "google_monitoring_alert_policy.host_logging_lag")["after"]["conditions"][0]["condition_prometheus_query_language"][0]["duration"] = "600s"
            elif mutation == "query":
                resource(changed, "google_monitoring_alert_policy.host_logging_heartbeat")["after"]["conditions"][0]["condition_prometheus_query_language"][0]["query"] = "vector(1)"
            elif mutation == "routing":
                resource(changed, "google_monitoring_alert_policy.host_logging_lag")["after"]["notification_channels"] = ["projects/example-project/notificationChannels/999"]
            elif mutation == "runbook":
                resource(changed, "google_monitoring_alert_policy.host_logging_lag")["after"]["documentation"][0]["content"] += " Changed runbook procedure."
            else:
                resource(changed, "google_monitoring_alert_policy.host_logging_lag")["after"]["notification_channels"] = []
            with self.subTest(mutation=mutation):
                if mutation == "channels":
                    with self.assertRaises(ValueError):
                        MODULE.deployment_content_digest(changed)
                else:
                    self.assertNotEqual(expected, MODULE.deployment_content_digest(changed))

    def test_unknown_functional_values_fail_closed(self):
        for name, unknown in (
            ("google_storage_bucket_object.otel_config", {"content": True}),
            ("google_os_config_os_policy_assignment.", {"os_policies": True}),
            ("google_project_iam_member.log_writer", {"role": True}),
            ("google_monitoring_alert_policy.host_logging_lag", {"conditions": True}),
        ):
            changed = plan()
            resource(changed, name)["after_unknown"] = unknown
            with self.subTest(resource=name), self.assertRaises(ValueError):
                MODULE.deployment_content_digest(changed)

    def test_reference_must_bind_exact_planned_artifact(self):
        for invalid in ("object", "generation"):
            changed = plan()
            change = resource(changed, "google_os_config_os_policy_assignment.")
            ref = change["after"]["os_policies"][0]["resource_groups"][0]["resources"][0]["file"][0]["file"][0]["gcs"][0]
            if invalid == "object":
                ref["object"] = "other/otel-logs.yaml"
            else:
                ref["generation"] = 1
                resource(changed, "google_storage_bucket_object.otel_config")["after"]["generation"] = 2
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                MODULE.deployment_content_digest(changed)

    def test_migration_digest_binds_heartbeat_view_and_reader(self):
        data = json.loads((ROOT / "scripts/fixtures/host_logging_migration_plan.json").read_text())
        for kind, name, value in [
            ("google_logging_log_view", "heartbeat_receipts", {"parent": "projects/example-project", "location": "global", "bucket": "_Default", "name": "heartbeat", "filter": 'labels.host_logging_heartbeat="true"'}),
            ("google_logging_log_view_iam_member", "heartbeat_reader", {"parent": "projects/example-project", "location": "global", "bucket": "_Default", "name": "heartbeat", "role": "roles/logging.viewAccessor", "member": "serviceAccount:fixture@example-project.iam.gserviceaccount.com"}),
        ]:
            data['resource_changes'].append({'address': 'module.host_logging.' + kind + '.' + name, 'change': {'actions': ['create'], 'after': value, 'after_unknown': {}}})
        digest = MODULE.migration_content_digest(data)
        for name, field, value in [('google_logging_log_view.heartbeat_receipts', 'filter', 'resource.type="gce_instance"'), ('google_logging_log_view_iam_member.heartbeat_reader', 'role', 'roles/logging.admin'), ('google_logging_log_view_iam_member.heartbeat_reader', 'member', 'allUsers')]:
            changed = copy.deepcopy(data)
            resource(changed, name)['after'][field] = value
            self.assertNotEqual(digest, MODULE.migration_content_digest(changed))
        resource(data, 'google_logging_log_view.heartbeat_receipts')['after_unknown'] = {'filter': True}
        with self.assertRaises(ValueError):
            MODULE.migration_content_digest(data)

    def migration_plan_and_receipt(self):
        data = json.loads((ROOT / "scripts/fixtures/host_logging_migration_plan.json").read_text())
        change = resource(data, "terraform_data.legacy_migration")
        change["before"] = copy.deepcopy(change["after"])
        change["before"]["input"]["phase"] = "drain"
        target = change["after"]["input"]
        receipt = {"migration": {
            "phase": "retire", "legacy_policy_name": target["legacy_policy_name"],
            "deployment_content_digest": MODULE.migration_content_digest(data),
            "instance_ids": target["instance_ids"], "metrics_continuity": True,
            "verified_instance_ids": target["verified_instance_ids"], "drained_instance_ids": target["drained_instance_ids"],
            "otel_deployment_content_digest": MODULE.deployment_content_digest(data),
            "rollback_verified": True, "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "overlap_gap_count": 0, "duplicate_count": 2, "pending_records": 0, "oldest_pending_age_seconds": 0,
        }}
        return data, receipt

    def test_migration_requires_matching_fresh_drain_and_metrics_evidence(self):
        data, receipt = self.migration_plan_and_receipt()
        MODULE.validate_migration_evidence(data, receipt)
        for field, value in (("phase", "overlap"), ("instance_ids", ["old"]),
                             ("verified_instance_ids", []), ("drained_instance_ids", []),
                             ("otel_deployment_content_digest", "old-revision"),
                             ("legacy_policy_name", "wrong-policy"), ("metrics_continuity", False),
                             ("rollback_verified", False), ("pending_records", 1),
                             ("deployment_content_digest", "wrong"), ("observed_at", "2020-01-01T00:00:00Z")):
            changed = copy.deepcopy(receipt);changed["migration"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE.validate_migration_evidence(data, changed)

    def test_migration_cannot_skip_overlap_or_change_its_target_artifact(self):
        data, receipt = self.migration_plan_and_receipt()
        resource(data, "terraform_data.legacy_migration")["before"]["input"]["phase"] = "preserve"
        with self.assertRaisesRegex(ValueError, "transition"):
            MODULE.validate_migration_evidence(data, receipt)
        data, _ = self.migration_plan_and_receipt()
        resource(data, "google_storage_bucket_object.legacy_migration_target")["after"]["content"] = "{}"
        with self.assertRaisesRegex(ValueError, "differs"):
            MODULE.migration_content_digest(data)

    def test_migration_references_bind_bucket_and_generation(self):
        def migration_references(data):
            assignment = resource(data, "google_os_config_os_policy_assignment.")
            references = []

            def visit(value):
                if isinstance(value, dict):
                    if value.get("id", "").startswith("legacy-migration-"):
                        for file in value.get("file", []):
                            for source in file.get("file", []):
                                references.extend(source.get("gcs", []))
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)

            visit(assignment["after"]["os_policies"])
            return references

        changed = json.loads(json.dumps((self.migration_plan_and_receipt())[0]))
        migration_references(changed)[0]["bucket"] = "wrong-bucket"
        with self.assertRaisesRegex(ValueError, "unbound migration artifact reference"):
            MODULE.migration_content_digest(changed)

        changed = json.loads(json.dumps((self.migration_plan_and_receipt())[0]))
        reference = migration_references(changed)[0]
        reference["generation"] = 1
        artifact = resource(changed, "google_storage_bucket_object.legacy_migration_script")
        artifact["after"]["generation"] = 2
        with self.assertRaisesRegex(ValueError, "migration generation differs"):
            MODULE.migration_content_digest(changed)

    def test_unrelated_host_replacement_needs_no_logging_evidence(self):
        data = {"resource_changes": [{"address": "module.sandbox_host.google_compute_instance.host", "change": {"actions": ["delete", "create"]}}]}
        self.assertFalse(MODULE.requires_evidence(data))
        data["resource_changes"] += plan()["resource_changes"]
        self.assertTrue(MODULE.requires_evidence(data))


if __name__ == "__main__":
    unittest.main()
