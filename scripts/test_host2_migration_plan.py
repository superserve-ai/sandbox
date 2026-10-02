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
    def run_guard(self, changes, guarded=None, all_hosts=False):
        plan = {"format_version": "1.2", "resource_changes": changes}
        cmd = [sys.executable, str(SCRIPT)] + (["--guarded", guarded] if guarded else [])
        if all_hosts:
            cmd.append("--all-hosts")
        return subprocess.run(cmd, input=json.dumps(plan), text=True, capture_output=True)

    def test_identity_rollout_blocks_all_hosts_disks_and_identity_adapter_changes(self):
        for address in (
            HOST, "module.sandbox_host.google_compute_instance.this",
            "module.sandbox_host_c.google_compute_instance.this",
            "google_compute_instance.legacy", "google_compute_disk.data",
            "google_compute_attached_disk.data", IDENTITY,
        ):
            for actions in (["create"], ["update"], ["delete"], ["delete", "create"]):
                with self.subTest(address=address, actions=actions):
                    result = self.run_guard([change(address, actions)], all_hosts=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(address, result.stderr)
            self.assertEqual(self.run_guard([change(address, ["no-op"])], all_hosts=True).returncode, 0)

    def test_identity_rollout_allows_control_plane_and_iam_changes(self):
        result = self.run_guard([
            change("google_service_account.controlplane_runtime", ["create"]),
            change("module.api.google_cloud_run_v2_service.this", ["update"]),
            change("google_kms_crypto_key_iam_member.controlplane_credentials", ["create"]),
        ], all_hosts=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_staged_identity_rollout_guards_all_hosts_before_each_apply(self):
        workflow = (SCRIPT.parent.parent / ".github/workflows/control-plane-identity-rollout.yml").read_text()
        for root in ("staging/us-central1", "production/us-east4", "production/us-west2"):
            with self.subTest(root=root):
                block = workflow.split(f"cd infra/envs/{root}\n", 1)[1].split("terraform apply", 1)[0]
                self.assertIn(
                    'terraform plan -input=false -out=tfplan\n'
                    '          terraform show -json tfplan | python3 '
                    '"$GITHUB_WORKSPACE/scripts/check_host2_migration_plan.py" --all-hosts\n',
                    block,
                )

    def test_named_guarded_host_is_protected_and_the_other_may_retire(self):
        third = "module.sandbox_host_c.google_compute_instance.this"
        result = self.run_guard([change(third, ["update"])], guarded="module.sandbox_host_c")
        self.assertEqual(result.returncode, 1)
        self.assertIn(third, result.stderr)
        result = self.run_guard([change(HOST, ["delete"]), change(third, ["no-op"])], guarded="module.sandbox_host_c")
        self.assertEqual(result.returncode, 0, result.stderr)
        # Without the flag the default host stays guarded and the third is not.
        self.assertEqual(self.run_guard([change(third, ["update"])]).returncode, 0)

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

    def test_east_rollout_guards_its_named_host_before_apply(self):
        workflow = (SCRIPT.parent.parent / ".github/workflows/terraform-cd.yml").read_text()
        block = workflow.split("cd infra/envs/production/us-east4\n", 1)[1]
        before_apply = block.split("terraform apply", 1)[0]
        self.assertIn(
            'terraform plan -input=false -out=tfplan\n'
            '          terraform show -json tfplan | python3 '
            '"$GITHUB_WORKSPACE/scripts/check_host2_migration_plan.py" --guarded module.sandbox_host_c\n',
            before_apply,
        )

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
                    after_plan = before_apply.split("terraform plan -input=false -out=tfplan\n", 1)[1]
                    self.assertIn(
                        'terraform show -json tfplan | python3 '
                        '"$GITHUB_WORKSPACE/scripts/check_host2_migration_plan.py"\n',
                        after_plan,
                    )


if __name__ == "__main__":
    unittest.main()
