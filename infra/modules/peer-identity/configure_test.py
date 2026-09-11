#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("configure.py")
SPEC = importlib.util.spec_from_file_location("peer_identity_configure", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InlineCertificateIssuanceConfigTest(unittest.TestCase):
    def test_wraps_issuance_fields_under_expected_api_key(self):
        config = {
            "region": "us-central1",
            "ca_pool": "projects/rayai-dev/locations/us-central1/caPools/vmd-peer-staging-usc1",
        }

        self.assertEqual(
            MODULE.inline_certificate_issuance_config(config),
            {
                "inlineCertificateIssuanceConfig": {
                    "caPools": {
                        "us-central1": "projects/rayai-dev/locations/us-central1/caPools/vmd-peer-staging-usc1"
                    },
                    "keyAlgorithm": "ECDSA_P256",
                    "lifetime": "86400s",
                    "rotationWindowPercentage": 50,
                }
            },
        )


if __name__ == "__main__":
    unittest.main()
