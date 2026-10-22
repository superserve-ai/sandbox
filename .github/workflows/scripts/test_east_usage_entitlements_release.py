import copy
import importlib.util
from pathlib import Path
import re
import unittest


PATH = Path(__file__).resolve().parents[3] / "scripts/east_usage_entitlements_release.py"
SPEC = importlib.util.spec_from_file_location("east_release", PATH)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def plan():
    before = {
        "project": "example-project", "name": "example-api", "location": "us-east4",
        "id": "projects/example-project/locations/us-east4/services/example-api",
        "traffic": [{"revision": "example-api-001", "percent": 100}],
        "template": [{"containers": [{"image": "example.invalid/api@sha256:abc", "env": [
            {"name": "EXISTING", "value": "preserve", "value_source": []},
            {"name": "SECRET_REFERENCE", "value": "", "value_source": [{"secret_key_ref": [{"secret": "example-secret", "version": "latest"}]}]},
        ]}]}],
    }
    after = copy.deepcopy(before)
    after["template"][0]["containers"][0]["env"].insert(0, {"name": release.FLAG, "value": "true", "value_source": []})
    return {"applyable": True, "resource_changes": [{
        "address": release.API, "mode": "managed", "type": "google_cloud_run_v2_service",
        "provider_name": "registry.terraform.io/hashicorp/google",
        "change": {"actions": ["update"], "before": before, "after": after, "after_unknown": {}},
    }]}


class ReleasePlanTests(unittest.TestCase):
    def validate(self, value):
        return release.validate_plan(value, "example-project", "example-api")

    def test_only_flag_and_readonly_dependencies(self):
        value = plan()
        value["resource_changes"].append({"mode": "data", "change": {"actions": ["read"]}})
        value["resource_changes"].append({"mode": "managed", "change": {"actions": ["no-op"]}})
        self.assertEqual(self.validate(value)["other_mutations"], 0)

    def test_rejects_other_resource_mutation(self):
        for address in ("module.cloud_ids.google_compute_packet_mirroring.this", "module.iam.binding"):
            value = plan()
            value["resource_changes"].append({"address": address, "mode": "managed", "change": {"actions": ["update"]}})
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.validate(value)

    def test_rejects_other_api_fields(self):
        for field in ("image", "traffic", "env", "secret", "unknown", "identity", "replacement"):
            value = plan()
            change = value["resource_changes"][0]["change"]
            after = change["after"]
            container = after["template"][0]["containers"][0]
            if field == "image":
                container["image"] = "example.invalid/different"
            elif field == "traffic":
                after["traffic"][0]["percent"] = 0
            elif field == "env":
                container["env"][1]["value"] = "changed"
            elif field == "secret":
                container["env"][2]["value_source"][0]["secret_key_ref"][0]["version"] = "other"
            elif field == "unknown":
                change["after_unknown"] = {"template": [{"containers": [{"env": True}]}]}
            elif field == "identity":
                change["before"]["location"] = after["location"] = "us-west2"
            else:
                change["actions"] = ["delete", "create"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_rejects_state_imports_and_moves_even_without_resource_mutations(self):
        for actions in (["no-op"], ["read"], ["update"]):
            for kind in ("import", "move"):
                value = plan()
                extra = {"address": "module.other.resource", "mode": "managed", "change": {"actions": actions}}
                if kind == "import":
                    extra["change"]["importing"] = {"id": "example"}
                else:
                    extra["previous_address"] = "module.previous.resource"
                value["resource_changes"].append(extra)
                with self.subTest(actions=actions, kind=kind), self.assertRaises(ValueError):
                    self.validate(value)
        value = plan()
        value["resource_changes"][0]["previous_address"] = "module.old_api.service"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_rejects_missing_duplicate_or_nonliteral_flag(self):
        for case in ("missing", "duplicate", "false", "secret"):
            value = plan()
            env = value["resource_changes"][0]["change"]["after"]["template"][0]["containers"][0]["env"]
            if case == "missing":
                env.pop(0)
            elif case == "duplicate":
                env.append(copy.deepcopy(env[0]))
            elif case == "false":
                env[0]["value"] = "false"
            else:
                env[0]["value_source"] = [{"secret_key_ref": [{"secret": "example"}]}]
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.validate(value)


class SourceLandingTests(unittest.TestCase):
    before = 'module "api" {\n  env = {\n    EXISTING = "preserve"\n  }\n}\n'

    def after(self):
        return self.before.replace("  env = {\n", f'  env = {{\n    {release.FLAG} = "true"\n\n')

    def test_exact_enablement_holds_broad_cd(self):
        self.assertTrue(release.source_landing(self.before, self.after(), {release.ROOT_FILE} | release.ACCOMMODATION_FILES))

    def test_mixed_enablement_fails_instead_of_running_broad_cd(self):
        for after, files in (
            (self.after(), {release.ROOT_FILE, "infra/envs/production/us-west2/main.tf"}),
            (self.after().replace('"preserve"', '"changed"'), {release.ROOT_FILE}),
            (self.after(), {release.ROOT_FILE, "internal/api/worker.go"}),
        ):
            with self.subTest(files=files), self.assertRaises(ValueError):
                release.source_landing(self.before, after, files)

    def test_unrelated_later_deploy_keeps_normal_pipeline(self):
        self.assertFalse(release.source_landing(self.after(), self.after(), {"infra/other.tf"}))
        self.assertFalse(release.source_landing(self.after(), self.after().replace('"preserve"', '"changed"'), {release.ROOT_FILE}))


class WorkflowBoundaryTests(unittest.TestCase):
    def test_pending_enablement_holds_only_east_on_later_pushes(self):
        # Check the actual dependency graph: a skipped East gate must not strand
        # the independent West/central chain or leave an East deployment bypass.
        text = (PATH.parents[1] / ".github/workflows/terraform-cd.yml").read_text()
        blocks = dict(re.findall(r"^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)", text.split("jobs:\n", 1)[1], re.M | re.S))
        self.assertIn("if: vars.EAST_USAGE_ENTITLEMENTS_APPLIED == 'true'", blocks["production-us-east4-infra"])
        self.assertIn("if: needs.release-scope.outputs.east_usage_only == 'false'", blocks["wait-for-migrations"])
        dependencies = {}
        for name, block in blocks.items():
            match = re.search(r"^    needs: \[([^]]*)\]", block, re.M)
            dependencies[name] = [x.strip() for x in match.group(1).split(",")] if match else []
        def skipped(initial):
            result = set(initial)
            while True:
                new = result | {name for name, needs in dependencies.items() if set(needs) & result}
                if new == result:
                    return result
                result = new
        initial_hold = skipped({"wait-for-migrations"})
        self.assertEqual(initial_hold, set(blocks) - {"release-scope"})
        later_hold = skipped({"production-us-east4-infra"})
        self.assertEqual(later_hold, {"production-us-east4-infra", "production-us-east4-api"})

    def test_image_only_updates_do_not_replace_runtime_environment(self):
        text = (PATH.parents[1] / ".github/workflows/deploy-api.yml").read_text()
        commands = re.findall(r"gcloud run services update (?:[^\n]*\\\n)*[^\n]*", text)
        self.assertTrue(commands)
        for command in commands:
            self.assertNotRegex(command, r"--(?:set|update|remove|clear)-env-vars|--env-vars-file|--(?:set|remove|clear)-secrets")


if __name__ == "__main__":
    unittest.main()
