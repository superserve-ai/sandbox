import importlib.util
import io
import json
import os
from contextlib import redirect_stderr
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "verify_control_plane_identity",
    Path(__file__).with_name("verify-control-plane-identity.py"),
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


class ManifestObjectResolutionTests(unittest.TestCase):
    def test_object_listing_recurses_below_each_prefix(self):
        for prefix in ("", "templates/", "bases/", "sandboxes/"):
            with self.subTest(prefix=prefix):
                command = VERIFY.storage_list_command("cell-backups", prefix, "reader@example.com")
                self.assertEqual(command[:4], ["gcloud", "storage", "objects", "list"])
                self.assertIn(f"gs://cell-backups/{prefix}**", command)
                self.assertIn("--impersonate-service-account=reader@example.com", command)

    def test_uploader_manifest_resolves_generation_local_and_shared_objects(self):
        manifest = """{
          "generation": "gen-123",
          "files": [
            {"name": "mem.snap", "object": "mem.snap.pabc"},
            {"name": "rootfs.ext4", "object": "bases/sha256.pdef"}
          ]
        }"""
        refs = VERIFY.manifest_references(manifest)
        prefix = "templates/tpl/build/gen-123"
        resolved = {
            VERIFY.object_name(ref, "cell-backups", prefix)
            for ref in refs
        }
        self.assertEqual(
            resolved,
            {
                "templates/tpl/build/gen-123/mem.snap.pabc",
                "bases/sha256.pdef",
            },
        )

    def test_relative_reference_cannot_escape_generation(self):
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.object_name("../other-generation/object", "cell-backups", "templates/tpl/build/gen-123")


class BinaryArtifactProbeTests(unittest.TestCase):
    def test_binary_stdout_is_streamed_without_utf8_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = VERIFY.Evidence(Path(directory))
            evidence.command(
                "binary-artifact",
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'\\xff\\xfe\\x00'); sys.stderr.write('probe stderr')",
                ],
                redact_stdout=True,
                stream_stdout=True,
            )

            self.assertEqual(
                (Path(directory) / "commands" / "01-binary-artifact.stdout").read_text(),
                "<redacted>\n",
            )
            self.assertEqual(
                (Path(directory) / "commands" / "01-binary-artifact.stderr").read_text(),
                "probe stderr",
            )
            self.assertTrue(evidence.index[0]["stdout_streamed"])


class KmsOwnershipTests(unittest.TestCase):
    def test_deployments_only_verify_terraform_owned_grants(self):
        root = Path(__file__).resolve().parents[1]
        for path in (
            "scripts/verify-control-plane-kms.sh",
            "scripts/verify-control-plane-identity.py",
            ".github/workflows/control-plane-identity-rollout.yml",
            ".github/workflows/deploy-api.yml",
            ".github/workflows/terraform-cd.yml",
        ):
            with self.subTest(path=path):
                source = (root / path).read_text()
                self.assertNotIn("KMS_POLICY_OWNER_SERVICE_ACCOUNT", source)
                self.assertNotIn("--kms-owner", source)
                self.assertNotIn("gcloud kms keys add-iam-policy-binding", source)
        source = (root / "scripts/verify-control-plane-kms.sh").read_text()
        self.assertIn("gcloud kms encrypt", source)
        self.assertIn("gcloud kms decrypt", source)


class RuntimeAccessRolloutTests(unittest.TestCase):
    def run_verifier(self, overrides=None, *, failures=(), omitted=(), cell="staging"):
        identity = "reader@example-project.iam.gserviceaccount.com"
        deployer = "deployer@example-project.iam.gserviceaccount.com"
        manifest = "templates/template/build/generation/manifest.json"
        service = {
            "spec": {"template": {"spec": {"serviceAccountName": identity}}},
            "status": {"latestCreatedRevisionName": "api-new", "latestReadyRevisionName": "api-old", "traffic": [{"revisionName": "api-old", "percent": 100}]},
        }
        revision = {
            "metadata": {"name": "api-new", "labels": {"serving.knative.dev/service": "api"}},
            "spec": {"serviceAccountName": identity},
            "status": {"conditions": [{"type": "Ready", "status": "True", "reason": "Retired"}]},
        }
        routed_service = {**service, "status": {"latestReadyRevisionName": "api-new",
                          "traffic": [{"revisionName": "api-new", "percent": 100}]}}
        responses = {
            "service": service,
            "candidate-revision": revision,
            "service-before-route": service,
            "own-template-list": manifest,
            "manifest-read": {"files": [{"object": "memory.pack"}]},
            "secret-access-1": "",
            "kms-iam": {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": [f"serviceAccount:{identity}"]}]},
            "kms-encrypt-as-runtime": "",
            "kms-decrypt-as-runtime": "",
            "route-candidate": "",
            "traffic-after-route": routed_service,
            "latest-revision": {"spec": {"serviceAccountName": identity}},
        }
        responses.update(overrides or {})
        commands = []

        def command(evidence, name, argv, **kwargs):
            commands.append(name)
            self.assertNotIn(argv[1:3], (["asset", "analyze-iam-policy"], ["policy-troubleshoot", "iam"]))
            if "get-iam-policy" in argv:
                self.assertEqual(argv[1:3], ["kms", "keys"])
            if name in failures:
                evidence.index.append({"name": name, "status": "FAIL"})
                raise VERIFY.VerificationError(f"{name}: probe failed")
            if name.startswith(("referenced-read-", "secret-access-", "kms-encrypt-", "kms-decrypt-")) or kwargs.get("expect_denied"):
                self.assertIn(f"--impersonate-service-account={identity}", argv)
            if name.startswith("secret-access-"):
                self.assertTrue(kwargs.get("redact_stdout"))
            if name == "kms-decrypt-as-runtime":
                destination = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--plaintext-file="))
                Path(destination).write_bytes(b"control-plane-kms-access-probe-v1\n")
            if name == "candidate-revision":
                self.assertEqual(argv[4], "api-new")
            if name == "route-candidate":
                self.assertIn("--to-revisions=api-new=100", argv)
                self.assertNotIn("--to-latest", argv)
            if name not in omitted:
                evidence.index.append({"name": name, "status": "PASS"})
            if kwargs.get("expect_denied") or name.startswith("referenced-read-"):
                result = ""
            else:
                result = responses[name]
            return result if isinstance(result, str) else json.dumps(result)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / "contract.json"
            contract_path.write_text(json.dumps({
                "runtime_service_account": identity, "legacy_runtime_account": "legacy@example.com",
                "deployment_identity": deployer, "backup_bucket": "own-cell",
                "backup_object_prefix": "templates/", "backup_object_prefixes": ["templates/", "bases/"],
                "backup_permissions": ["storage.objects.get", "storage.objects.list"],
                "secret_ids": ["runtime-secret"], "host_identities_unchanged": ["host@example.com"],
                "kms_key_resource": "projects/example-project/locations/example-region/keyRings/example/cryptoKeys/example" if cell != "staging" else None,
                "kms_grant_principal": identity, "kms_grant_role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
            }))
            argv = [str(SPEC.origin), "--cell", cell, "--project", "example-project",
                    "--region", "example-region", "--service", "api", "--contract-file", str(contract_path),
                    "--evidence-dir", str(root / "evidence"), "--other-bucket", "other-cell",
                    "--allow-pending-traffic", "--route-traffic", "--candidate-revision", "api-new"]
            previous_umask = os.umask(0o077)
            try:
                with patch.object(sys, "argv", argv), patch.object(VERIFY.Evidence, "command", command), redirect_stderr(io.StringIO()):
                    status = VERIFY.main()
            finally:
                os.umask(previous_umask)
            return status, json.loads((root / "evidence/evidence.json").read_text()), commands

    def test_runtime_access_passes_before_routing_in_all_cells_without_policy_audits(self):
        for cell in ("staging", "production-use4", "production-usw2"):
            with self.subTest(cell=cell):
                status, evidence, commands = self.run_verifier(cell=cell)
                self.assertEqual(status, 0)
                self.assertEqual(evidence["status"], "PASS")
                for name in ("manifest-read", "referenced-read-1", "secret-access-1", "sandbox-list-denied", "cross-cell-1-templates-list-denied"):
                    self.assertLess(commands.index(name), commands.index("route-candidate"))
                if cell != "staging":
                    self.assertLess(commands.index("kms-decrypt-as-runtime"), commands.index("route-candidate"))

    def test_runtime_probe_failure_or_missing_evidence_prevents_routing(self):
        for name in ("manifest-read", "referenced-read-1", "secret-access-1", "kms-encrypt-as-runtime", "kms-decrypt-as-runtime",
                     "sandbox-list-denied", "cross-cell-1-bases-list-denied"):
            for failure_mode in ("failed", "omitted"):
                with self.subTest(name=name, failure_mode=failure_mode):
                    options = {"failures" if failure_mode == "failed" else "omitted": [name]}
                    status, evidence, commands = self.run_verifier(cell="production-use4", **options)
                    self.assertEqual(status, 1)
                    self.assertEqual(evidence["status"], "FAIL")
                    self.assertNotIn("route-candidate", commands)

    def test_wrong_identity_unready_or_unrelated_candidate_never_routes(self):
        valid = {"metadata": {"name": "api-new", "labels": {"serving.knative.dev/service": "api"}},
                 "spec": {"serviceAccountName": "reader@example-project.iam.gserviceaccount.com"},
                 "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        for change in (
            {"spec": {"serviceAccountName": "legacy@example.com"}},
            {"status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}},
            {"status": {}},
            {"metadata": {"name": "api-new", "labels": {"serving.knative.dev/service": "other"}}},
        ):
            with self.subTest(change=change):
                status, _, commands = self.run_verifier(
                    {"candidate-revision": {**valid, **change}})
                self.assertEqual(status, 1)
                self.assertNotIn("route-candidate", commands)

    def test_newer_revision_during_checks_does_not_get_routed(self):
        status, _, commands = self.run_verifier({
            "service-before-route": {"status": {"latestCreatedRevisionName": "api-newer"}},
        })
        self.assertEqual(status, 1)
        self.assertNotIn("route-candidate", commands)

    def test_latest_traffic_cannot_substitute_for_candidate_after_route(self):
        status, evidence, _ = self.run_verifier({
            "traffic-after-route": {"status": {"latestReadyRevisionName": "api-newer",
                "traffic": [{"latestRevision": True, "revisionName": "api-newer", "percent": 100}]}},
        })
        self.assertEqual(status, 1)
        self.assertEqual(evidence["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
