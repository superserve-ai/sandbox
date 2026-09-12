import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from configure import configure


class IssuanceConfigTest(unittest.TestCase):
    def test_gcloud_receives_wrapped_issuance_config(self):
        for existing in (False, True):
            with self.subTest(existing_pool=existing):
                config = {
                    "project_id": "example-project",
                    "pool_id": "peer-pool",
                    "region": "us-central1",
                    "ca_pool": "projects/example-project/locations/us-central1/caPools/peer-ca",
                }
                captured = []

                def run(command, **kwargs):
                    if command[3] == "list":
                        pools = [{"name": "pools/peer-pool", "mode": "TRUST_DOMAIN",
                                  "state": "ACTIVE"}] if existing else []
                        return subprocess.CompletedProcess(command, 0, json.dumps(pools))
                    if command[3] == "create":
                        return subprocess.CompletedProcess(command, 0, "")
                    self.assertEqual(command[3], "update")
                    flag = "--inline-certificate-issuance-config-file="
                    path = next(arg.removeprefix(flag) for arg in command if arg.startswith(flag))
                    captured.append(json.loads(Path(path).read_text()))
                    raise IssuanceCaptured

                with patch("configure.subprocess.run", side_effect=run):
                    with self.assertRaises(IssuanceCaptured):
                        configure(config)
                self.assertEqual(captured, [{"inlineCertificateIssuanceConfig": {
                    "caPools": {"us-central1": config["ca_pool"]},
                    "keyAlgorithm": "ECDSA_P256",
                    "lifetime": "86400s",
                    "rotationWindowPercentage": 50,
                }}])


class IssuanceCaptured(Exception):
    pass


if __name__ == "__main__":
    unittest.main()
