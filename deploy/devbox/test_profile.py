import json
import re
import unittest
from pathlib import Path

DEVBOX = Path(__file__).resolve().parent
TERRAFORM = DEVBOX / "terraform"
PROFILE = json.loads((DEVBOX / "profile.json").read_text())
TFVARS = dict(re.findall(r'^(\w+)\s*=\s*"([^"]*)"$', (TERRAFORM / "terraform.tfvars").read_text(), re.M))
MAIN_TF = (TERRAFORM / "main.tf").read_text()


class TerraformAgreementTest(unittest.TestCase):
    def test_names_match_the_iam_conditions(self):
        self.assertEqual(PROFILE["resource_name_prefix"], TFVARS["resource_name_prefix"])
        self.assertEqual(PROFILE["bucket"]["name_prefix"], TFVARS["bucket_name_prefix"])
        self.assertEqual(PROFILE["project"], TFVARS["project_id"])

    def test_instances_land_where_iap_ssh_is_allowed(self):
        self.assertEqual(PROFILE["instance"]["network_tags"], [TFVARS["network_tag"]])
        self.assertEqual(PROFILE["region"], TFVARS["region"])
        self.assertEqual(PROFILE["bucket"]["location"], TFVARS["region"])

    def test_instances_run_as_the_box_identity(self):
        account_id = re.search(r'resource "google_service_account" "box" \{[^}]*account_id\s*=\s*"([^"]+)"', MAIN_TF).group(1)
        self.assertEqual(PROFILE["instance"]["service_account"],
                         f"{account_id}@{TFVARS['project_id']}.iam.gserviceaccount.com")


if __name__ == "__main__":
    unittest.main()
