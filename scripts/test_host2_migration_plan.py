import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("check_host2_migration_plan.py")
HOST = "module.sandbox_host_b.google_compute_instance.this"
IDENTITY = "module.peer_identity.terraform_data.managed_identity"


def change(address, actions):
    return {
        "address": address,
        "type": address.split(".")[-2],
        "name": address.split(".")[-1],
        "change": {"actions": actions},
    }


class Host2MigrationPlanTest(unittest.TestCase):
    def run_guard(self, changes):
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps({"format_version": "1.2", "resource_changes": changes}),
            text=True, capture_output=True,
        )

    def test_blocks_vm_changes_and_identity_adapter_independently(self):
        for address in (HOST, IDENTITY):
            for actions in (["create"], ["update"], ["delete"],
                            ["delete", "create"], ["create", "delete"]):
                with self.subTest(address=address, actions=actions):
                    result = self.run_guard([change(address, actions)])
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(address, result.stderr)
                    self.assertIn("host2-identity-runbook.md", result.stderr)

    def test_allows_routine_apply_after_migration(self):
        result = self.run_guard([
            change(HOST, ["no-op"]),
            change(IDENTITY, ["no-op"]),
            change("google_project_iam_member.vmd_telemetry", ["create"]),
            change("module.peer_identity.google_privateca_ca_pool.peer", ["update"]),
        ])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_allows_empty_plan(self):
        self.assertEqual(self.run_guard([]).returncode, 0)

    def test_invalid_plan_fails_closed(self):
        for plan in ("", "{}", "null", '{"format_version":"1.2","resource_changes":[{}]}'):
            with self.subTest(plan=plan):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT)], input=plan,
                    text=True, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_all_rollout_paths_guard_the_saved_plan_before_apply(self):
        workflows = SCRIPT.parent.parent / ".github/workflows"
        for name, roots in {
            "terraform-cd.yml": ("staging/us-central1", "production/us-west2"),
            "terraform-rollout-staging.yml": ("staging/us-central1",),
            "terraform-rollout-production.yml": ("production/us-west2",),
        }.items():
            for root in roots:
                with self.subTest(workflow=name, root=root):
                    block = (workflows / name).read_text().split(f"cd infra/envs/{root}\n", 1)[1]
                    before_apply = block.split("terraform apply", 1)[0]
                    self.assertIn("set -euo pipefail", (workflows / name).read_text())
                    self.assertIn(
                        'terraform plan -input=false -out=tfplan\n'
                        '          terraform show -json tfplan | python3 '
                        '"$GITHUB_WORKSPACE/scripts/check_host2_migration_plan.py"\n',
                        before_apply,
                    )


if __name__ == "__main__":
    unittest.main()
