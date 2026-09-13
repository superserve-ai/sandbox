"""Exercise the module's destruction guard with Terraform's built-in resource."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TF = os.environ.get("TERRAFORM", shutil.which("terraform"))
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(TF, "Terraform is required")
class LifecycleTest(unittest.TestCase):
    def test_label_updates_preserve_destroy_protection_in_every_phase(self):
        source = (ROOT / "infra/modules/staging-mwi-host/main.tf").read_text()
        # Use the actual lifecycle policy; omit only provider-specific ignore_changes.
        policy = source.split("  lifecycle {", 1)[1].split("    ignore_changes", 1)[0]
        self.assertRegex(policy, r"prevent_destroy\s*=\s*true")
        config = '''
variable "environment" { default = "staging" }
variable "instance_name" { default = "superserve-vmd-staging-2" }
variable "labels" { type = map(string) }
resource "terraform_data" "host" {
  input = var.labels
  lifecycle { %s }
}
''' % policy
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "main.tf").write_text(config)
            def run(*args):
                return subprocess.run([TF, *args, "-no-color"], cwd=work,
                                      text=True, capture_output=True)
            self.assertEqual(run("init", "-backend=false").returncode, 0)
            for index, (component, status) in enumerate([
                ("vmd-staging-standby", "provisioning"),
                ("vmd", "provisioning"), ("vmd", "ready")]):
                (work / "terraform.tfvars.json").write_text(json.dumps({
                    "labels": {"component": component, "sandbox_status": status}}))
                plan = run("plan", "-out=plan")
                self.assertEqual(plan.returncode, 0, plan.stdout + plan.stderr)
                parsed = subprocess.run([TF, "show", "-json", "plan"], cwd=work,
                                        text=True, capture_output=True, check=True)
                actions = json.loads(parsed.stdout)["resource_changes"][0]["change"]["actions"]
                self.assertEqual(actions, ["create"] if index == 0 else ["update"])
                applied = run("apply", "-auto-approve", "plan")
                self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
                replacement = run("plan", "-replace=terraform_data.host")
                self.assertNotEqual(replacement.returncode, 0)
                self.assertIn("prevent_destroy", replacement.stdout + replacement.stderr)


if __name__ == "__main__":
    unittest.main()
