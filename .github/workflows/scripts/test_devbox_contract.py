"""Exercise the shared devbox naming, label and manifest contract."""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import devbox_contract as contract


CREATED = datetime(2026, 10, 20, 15, 0, tzinfo=timezone.utc)
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def manifest():
    return contract.new_manifest(
        name="awille-ai-dev-a7f3c9", devbox_id="3f9c0a1b2c4d", owner="awille-ai", actor="awille-ai",
        created_at=CREATED, expires_at=contract.expiry(CREATED, 24),
        revisions={"sandbox": {"branch": "main", "sha": SHA_A}, "ui": {"branch": "main", "sha": SHA_B}})


class NamingTests(unittest.TestCase):
    def test_owner_normalization(self):
        self.assertEqual(contract.normalize_owner("AWille-AI"), "awille-ai")
        self.assertEqual(contract.normalize_owner("dependabot[bot]"), "dependabot-bot-")
        self.assertEqual(len(contract.normalize_owner("x" * 80)), 63)
        with self.assertRaises(contract.ContractError):
            contract.normalize_owner("  ")

    def test_generated_names_fit_the_name_rule(self):
        for owner in ("awille-ai", "dependabot-bot-", "9lives", "under_score", "1234", "a" * 63):
            with self.subTest(owner=owner):
                name = contract.generate_name(owner, "a7f3c9")
                contract.validate_name(name)
                self.assertTrue(name.endswith("-dev-a7f3c9"))
                self.assertLessEqual(len(name), contract.MAX_NAME_LENGTH)
        self.assertEqual(contract.generate_name("awille-ai", "a7f3c9"), "awille-ai-dev-a7f3c9")
        self.assertEqual(contract.generate_name("1234", "a7f3c9"), "box-dev-a7f3c9")
        self.assertRegex(contract.generate_name("awille-ai"), r"^awille-ai-dev-[0-9a-f]{6}$")

    def test_supplied_names_are_validated(self):
        self.assertEqual(contract.resolve_name("  my-box  ", "owner"), "my-box")
        self.assertEqual(contract.resolve_name("", "owner", "abcdef"), "owner-dev-abcdef")
        for bad in ("a", "1box", "box-", "Box", "my_box", "a" * 41, "box.dev", "box dev", "foo-data"):
            with self.subTest(name=bad), self.assertRaises(contract.ContractError):
                contract.resolve_name(bad, "owner")
        contract.validate_name("a" * 40)
        contract.validate_name("foo-database")

    def test_devbox_id(self):
        self.assertRegex(contract.new_devbox_id(), r"^[0-9a-f]{12}$")
        self.assertNotEqual(contract.new_devbox_id(), contract.new_devbox_id())
        with self.assertRaises(contract.ContractError):
            contract.validate_devbox_id("3F9C0A1B2C4D")

    def test_lifetime_bounds(self):
        self.assertEqual(contract.parse_lifetime_hours(""), 24)
        self.assertEqual(contract.parse_lifetime_hours(None), 24)
        self.assertEqual(contract.parse_lifetime_hours("168"), 168)
        self.assertEqual(contract.parse_lifetime_hours(1), 1)
        for bad in ("0", "169", "-1", "1.5", "abc", "24h"):
            with self.subTest(value=bad), self.assertRaises(contract.ContractError):
                contract.parse_lifetime_hours(bad)


class LabelTests(unittest.TestCase):
    def test_labels_use_epoch_expiry_and_no_discovery_labels(self):
        values = contract.labels("my-box", "3f9c0a1b2c4d", "AWille-AI", contract.expiry(CREATED, 24))
        self.assertEqual(values, {
            "managed-by": "superserve-devbox", "devbox-name": "my-box", "devbox-id": "3f9c0a1b2c4d",
            "owner": "awille-ai", "expires-at": "1792594800"})
        self.assertFalse(set(values) & set(contract.FORBIDDEN_LABELS))
        self.assertEqual(contract.format_labels(values),
                         "managed-by=superserve-devbox,devbox-name=my-box,devbox-id=3f9c0a1b2c4d,"
                         "owner=awille-ai,expires-at=1792594800")

    def test_check_labels_refuses_foreign_or_replaced_boxes(self):
        values = contract.labels("my-box", "3f9c0a1b2c4d", "owner", CREATED)
        self.assertEqual(contract.check_labels(values, "my-box", "3f9c0a1b2c4d"), "3f9c0a1b2c4d")
        for found, devbox_id in (
            ({**values, "devbox-id": "000000000000"}, "3f9c0a1b2c4d"),
            ({**values, "managed-by": "terraform"}, None),
            ({**values, "devbox-name": "other"}, None),
            ({**values, "sandbox_role": "vmd"}, None),
            ({**values, "component": "vmd"}, None),
            ({}, None),
        ):
            with self.subTest(found=found), self.assertRaises(contract.ContractError):
                contract.check_labels(found, "my-box", devbox_id)

    def test_target_resolution_uses_labels_not_name_prefix(self):
        values = contract.labels("my-box", "3f9c0a1b2c4d", "owner", CREATED)
        target = {"name": "devbox-my-box", "labels": values}
        instances = [{"name": "devbox-my-box-2", "labels": {**values, "devbox-name": "my-box-2"}},
                     {"name": "devbox-my-box", "labels": {}}, target]
        self.assertIs(contract.select_instance(instances, "my-box"), target)
        with self.assertRaises(contract.ContractError):
            contract.select_instance([{"name": "devbox-my-box", "labels": {}}], "my-box")
        with self.assertRaises(contract.ContractError):
            contract.select_instance([target, dict(target)], "my-box")
        with self.assertRaises(contract.ContractError):
            contract.select_instance([{"name": "my-box", "labels": values}], "my-box")
        self.assertEqual(contract.discovery_filter("my-box"),
                         "labels.managed-by=superserve-devbox AND labels.devbox-name=my-box")

    def test_resource_names_fit_gcp_limits(self):
        name = "a" * contract.MAX_NAME_LENGTH
        self.assertEqual(contract.instance_name("my-box"), "devbox-my-box")
        self.assertEqual(contract.data_disk_name("my-box"), "devbox-my-box-data")
        self.assertLessEqual(len(contract.data_disk_name(name)), 63)
        self.assertEqual(contract.concurrency_group("my-box"), "devbox-my-box")


class ManifestTests(unittest.TestCase):
    def test_initial_manifest(self):
        value = manifest()
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["state"], "creating")
        self.assertEqual(value["expires_at"], "2026-10-21T15:00:00Z")
        self.assertEqual([r["name"] for r in value["resources"]],
                         ["devbox-awille-ai-dev-a7f3c9", "devbox-awille-ai-dev-a7f3c9",
                          "devbox-awille-ai-dev-a7f3c9-data", "superserve-devbox-3f9c0a1b2c4d"])
        self.assertEqual(value["deploys"], [])

    def test_revisions_require_full_shas(self):
        with self.assertRaises(contract.ContractError):
            contract.revision("main", "abc123")
        for branch in ("", "-main", "a..b", "x`[y](z)", "has space"):
            with self.subTest(branch=branch), self.assertRaises(contract.ContractError):
                contract.revision(branch, SHA_A)
        self.assertEqual(contract.revision("feature/x_1.2-y", SHA_A)["branch"], "feature/x_1.2-y")

    def test_validate_rejects_unknown_schema_and_state(self):
        for key, value in (("schema_version", 2), ("state", "running"), ("deploys", {}),
                           ("created_at", "yesterday"), ("resources", [{"type": "vm", "name": "x"}])):
            with self.subTest(key=key), self.assertRaises(contract.ContractError):
                contract.validate_manifest({**manifest(), key: value})
        with self.assertRaises(contract.ContractError):
            contract.with_state(manifest(), "running")
        self.assertEqual(contract.with_state(manifest(), "ready")["state"], "ready")

    def test_initial_components_follow_their_repository(self):
        self.assertEqual(manifest()["components"], {
            "vmd": {"branch": "main", "sha": SHA_A}, "proxy": {"branch": "main", "sha": SHA_A},
            "api": {"branch": "main", "sha": SHA_A}, "ui": {"branch": "main", "sha": SHA_B}})
        with self.assertRaises(contract.ContractError):
            contract.validate_manifest({**manifest(), "components": {"vmd": {"branch": "main", "sha": SHA_A}}})

    def test_record_deploy_moves_only_deployed_components(self):
        before = manifest()
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        after = contract.record_deploy(
            before, at=at, actor="someone", components=["api"], migrations="applied", result="succeeded",
            revisions={"sandbox": {"branch": "feature", "sha": SHA_C}})
        self.assertEqual(before["deploys"], [])
        self.assertEqual(after["expires_at"], before["expires_at"])
        self.assertEqual(after["state"], "ready")
        self.assertEqual(after["revisions"], {"sandbox": {"branch": "feature", "sha": SHA_C},
                                              "ui": {"branch": "main", "sha": SHA_B}})
        self.assertEqual(after["components"]["api"], {"branch": "feature", "sha": SHA_C})
        self.assertEqual(after["components"]["vmd"], {"branch": "main", "sha": SHA_A})
        self.assertEqual(after["deploys"], [{
            "at": "2026-10-20T18:00:00Z", "actor": "someone", "components": ["api"],
            "from": {"sandbox": SHA_A, "ui": SHA_B}, "to": {"sandbox": SHA_C, "ui": SHA_B},
            "migrations": "applied", "result": "succeeded"}])

    def test_failed_deploy_is_recorded_and_marks_the_box_failed(self):
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        failed = contract.record_deploy(manifest(), at=at, actor="x", components=["vmd"], migrations="none",
                                        result="failed", revisions={"sandbox": {"branch": "main", "sha": SHA_C}},
                                        checked_out=["sandbox"], deployed=[])
        self.assertEqual(failed["components"]["vmd"], {"branch": "main", "sha": SHA_A})
        with self.assertRaises(contract.ContractError):
            contract.record_deploy(manifest(), at=at, actor="x", components=["vmd"], migrations="none",
                                   result="failed", revisions={"sandbox": {"branch": "main", "sha": SHA_C}})
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["deploys"][-1]["result"], "failed")
        recovered = contract.record_deploy(failed, at=at, actor="x", components=["vmd"], migrations="none",
                                           result="succeeded", revisions={"sandbox": {"branch": "main", "sha": SHA_A}})
        self.assertEqual(recovered["state"], "ready")
        self.assertEqual(len(recovered["deploys"]), 2)

    def test_failed_deploy_moves_only_what_finished(self):
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        target = {"sandbox": {"branch": "feature", "sha": SHA_C}, "ui": {"branch": "feature", "sha": SHA_C}}
        after = contract.record_deploy(manifest(), at=at, actor="x", components=["api", "ui"], revisions=target,
                                       migrations="failed", result="failed", checked_out=["sandbox", "ui"],
                                       deployed=[])
        self.assertEqual(after["revisions"], target)
        self.assertEqual(after["components"]["api"], {"branch": "main", "sha": SHA_A})
        self.assertEqual(after["components"]["ui"], {"branch": "main", "sha": SHA_B})
        self.assertEqual(after["deploys"][-1]["to"], {"sandbox": SHA_C, "ui": SHA_C})
        nothing = contract.record_deploy(manifest(), at=at, actor="x", components=["vmd"], migrations="none",
                                         result="failed", revisions={"sandbox": target["sandbox"]},
                                         checked_out=[], deployed=[])
        self.assertEqual(nothing["revisions"]["sandbox"], {"branch": "main", "sha": SHA_A})
        for checked_out, deployed, result in ((["sandbox"], ["vmd"], "failed"), (["ui"], ["api"], "failed"),
                                              (None, ["api"], "succeeded")):
            with self.subTest(checked_out=checked_out, deployed=deployed), self.assertRaises(contract.ContractError):
                contract.record_deploy(manifest(), at=at, actor="x", components=["api", "ui"],
                                       revisions=target, migrations="none", result=result,
                                       checked_out=checked_out, deployed=deployed)

    def test_unknown_migration_outcome_is_recordable(self):
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        after = contract.record_deploy(manifest(), at=at, actor="x", components=["api"], migrations="unknown",
                                       result="failed", revisions={"sandbox": {"branch": "main", "sha": SHA_C}},
                                       checked_out=["sandbox"], deployed=[])
        self.assertEqual(after["deploys"][-1]["migrations"], "unknown")

    def test_unconfirmed_and_in_flight_progress_is_recorded_without_a_sha(self):
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        target = {"sandbox": {"branch": "feature", "sha": SHA_C}}
        after = contract.record_deploy(manifest(), at=at, actor="x", components=["vmd", "api"], revisions=target,
                                       migrations="unknown", result="failed", checked_out=[], deployed=[],
                                       unconfirmed=["sandbox"])
        self.assertEqual(after["revisions"]["sandbox"], {"branch": "main", "sha": SHA_A, "unconfirmed": True})
        running = contract.record_deploy(manifest(), at=at, actor="x", components=["vmd", "api"], revisions=target,
                                         migrations="unknown", result="failed", checked_out=["sandbox"],
                                         deployed=[], in_flight="vmd")
        self.assertEqual(running["components"]["vmd"], {"branch": "feature", "sha": "unknown"})
        self.assertEqual(running["components"]["api"], {"branch": "main", "sha": SHA_A})
        for overrides in ({"result": "succeeded", "checked_out": ["sandbox"], "deployed": ["vmd", "api"]},
                          {"checked_out": ["sandbox"]}, {"in_flight": "ui"}):
            arguments = {"at": at, "actor": "x", "components": ["vmd", "api"], "revisions": target,
                         "migrations": "none", "result": "failed", "checked_out": [], "deployed": [],
                         "unconfirmed": ["sandbox"], "in_flight": "vmd", **overrides}
            with self.subTest(overrides=overrides), self.assertRaises(contract.ContractError):
                contract.record_deploy(manifest(), **arguments)
        with self.assertRaises(contract.ContractError):
            contract.validate_manifest({**manifest(), "revisions": {**manifest()["revisions"],
                                        "ui": {"branch": "main", "sha": SHA_B, "unconfirmed": "maybe"}}})

    def test_record_deploy_rejects_unknown_outcomes_and_mismatched_revisions(self):
        at = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc)
        sandbox = {"sandbox": {"branch": "main", "sha": SHA_C}}
        for overrides in ({"migrations": "skipped"}, {"result": "partial"},
                          {"revisions": {"ui": {"branch": "main", "sha": SHA_C}}},
                          {"revisions": {**sandbox, "ui": {"branch": "main", "sha": SHA_C}}}):
            arguments = {"at": at, "actor": "x", "components": ["vmd"], "migrations": "none",
                         "result": "failed", "revisions": sandbox, **overrides}
            with self.subTest(overrides=overrides), self.assertRaises(contract.ContractError):
                contract.record_deploy(manifest(), **arguments)


class ComponentTests(unittest.TestCase):
    def test_component_parsing_and_contract_order(self):
        self.assertEqual(contract.parse_components("all"), ["vmd", "proxy", "api", "ui"])
        self.assertEqual(contract.parse_components(" ui , vmd "), ["vmd", "ui"])
        self.assertEqual(contract.component_scripts(contract.parse_components("ui,api")),
                         ["services-up.sh", "install-api.sh", "install-ui.sh"])
        self.assertEqual(contract.component_scripts(contract.COMPONENTS),
                         ["install-vmd.sh", "install-proxy.sh", "services-up.sh", "install-api.sh", "install-ui.sh"])
        self.assertEqual(contract.CREATE_SCRIPTS[:3], ("host-bootstrap.sh", "services-up.sh", "install-api.sh"))
        self.assertNotIn("seed-base.sh", contract.component_scripts(contract.COMPONENTS))
        for bad in ("", ",", "all,api", "db", "vmd,db"):
            with self.subTest(value=bad), self.assertRaises(contract.ContractError):
                contract.parse_components(bad)

    def test_forwarding_command_covers_contract_ports(self):
        command = contract.forwarding_command("my-box")
        self.assertTrue(command.startswith("gcloud compute ssh devbox-my-box --zone=us-central1-a "
                                           "--project=rayai-dev --tunnel-through-iap -- -N "))
        for port in (3000, 8080, 54321, 8025, 8090):
            self.assertIn(f"-L {port}:127.0.0.1:{port}", command)
        self.assertNotIn("54322", command)


if __name__ == "__main__":
    unittest.main()
