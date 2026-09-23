import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


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


class DeletePermissionProbeTests(unittest.TestCase):
    def test_delete_probe_uses_object_resource_without_mutation(self):
        self.assertEqual(
            VERIFY.storage_object_resource(
                "cell-backups", "templates/example/build-1/generation-1/manifest.json"
            ),
            "//storage.googleapis.com/projects/_/buckets/cell-backups/objects/"
            "templates/example/build-1/generation-1/manifest.json",
        )
        self.assertEqual(
            VERIFY.policy_troubleshooter_access('{"access":"NOT_GRANTED"}'),
            "NOT_GRANTED",
        )

    def test_delete_probe_rejects_missing_access_decision(self):
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.policy_troubleshooter_access("{}")

    def test_create_probe_targets_a_synthetic_object_resource(self):
        self.assertEqual(
            VERIFY.storage_object_resource("cell-backups", "templates/.permission-probe"),
            "//storage.googleapis.com/projects/_/buckets/cell-backups/objects/"
            "templates/.permission-probe",
        )


class ObjectReadPermissionProbeTests(unittest.TestCase):
    def test_denial_matrix_covers_every_prefix_and_cell(self):
        manifest = "templates/tpl/build/gen/manifest.json"
        checks = VERIFY.storage_denial_checks("own", ["east", "west"], manifest)
        observed = {(bucket, name, permission) for _, bucket, name, permission in checks}
        expected = {
            (bucket, f"{prefix}/.permission-probe", f"storage.objects.{operation}")
            for bucket, operations in (
                ("own", ("create", "delete")),
                ("east", ("get", "create", "delete")),
                ("west", ("get", "create", "delete")),
            )
            for prefix in ("templates", "bases", "sandboxes")
            for operation in operations
        }
        expected.add(("own", "sandboxes/.permission-probe", "storage.objects.get"))
        expected.add(("own", manifest, "storage.objects.delete"))
        self.assertEqual(observed, expected)
        self.assertEqual(len({check[0] for check in checks}), len(checks))

    def test_all_denial_probes_reject_grants_and_unknown_results_without_mutating(self):
        checks = VERIFY.storage_denial_checks("own", ["other"], "templates/t/b/g/manifest.json")
        for response in ('{"access":"GRANTED"}', '{"access":"UNKNOWN_INFO"}', '{}', 'null', 'invalid'):
            for name, bucket, object_name, permission in checks:
                with self.subTest(name=name, response=response), tempfile.TemporaryDirectory() as directory:
                    evidence = VERIFY.Evidence(Path(directory))

                    def command(check_name, argv, **_kwargs):
                        self.assertEqual(argv[:3], ["gcloud", "policy-troubleshoot", "iam"])
                        self.assertIn(VERIFY.storage_object_resource(bucket, object_name), argv)
                        self.assertIn(f"--permission={permission}", argv)
                        evidence.index.append({"name": check_name, "status": "PASS"})
                        return response

                    evidence.command = command
                    with self.assertRaises(VERIFY.VerificationError):
                        VERIFY.require_permission_denied(
                            evidence, name, "reader@example.com", bucket, object_name, permission,
                        )
                    self.assertEqual(evidence.index[-1]["status"], "FAIL")

    def test_sandbox_get_probe_is_non_mutating_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = VERIFY.Evidence(Path(directory))
            commands = []

            def command(name, argv, **_kwargs):
                commands.append((name, argv))
                evidence.index.append({"name": name, "status": "PASS"})
                return '{"access":"NOT_GRANTED"}'

            evidence.command = command
            VERIFY.require_permission_denied(
                evidence,
                "sandbox-get-permission-check",
                "reader@example-project.iam.gserviceaccount.com",
                "cell-backups",
                "sandboxes/.permission-probe",
                "storage.objects.get",
            )

            name, argv = commands[0]
            self.assertEqual(name, "sandbox-get-permission-check")
            self.assertIn(
                "//storage.googleapis.com/projects/_/buckets/cell-backups/objects/"
                "sandboxes/.permission-probe",
                argv,
            )
            self.assertIn("--permission=storage.objects.get", argv)

    def test_sandbox_get_probe_rejects_granted_access(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = VERIFY.Evidence(Path(directory))

            def command(name, argv, **_kwargs):
                evidence.index.append({"name": name, "status": "PASS"})
                return '{"access":"GRANTED"}'

            evidence.command = command
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.require_permission_denied(
                    evidence,
                    "cross-cell-get-1",
                    "reader@example-project.iam.gserviceaccount.com",
                    "other-cell-backups",
                    "sandboxes/.permission-probe",
                    "storage.objects.get",
                )
            self.assertEqual(evidence.index[0]["status"], "FAIL")

    def test_cross_cell_template_get_probe_targets_other_cell_template_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = VERIFY.Evidence(Path(directory))
            commands = []

            def command(name, argv, **_kwargs):
                commands.append((name, argv))
                evidence.index.append({"name": name, "status": "PASS"})
                return '{"access":"NOT_GRANTED"}'

            evidence.command = command
            VERIFY.require_permission_denied(
                evidence,
                "cross-cell-template-get-1",
                "reader@example-project.iam.gserviceaccount.com",
                "other-cell-backups",
                "templates/.permission-probe",
                "storage.objects.get",
            )

            name, argv = commands[0]
            self.assertEqual(name, "cross-cell-template-get-1")
            self.assertIn(
                "//storage.googleapis.com/projects/_/buckets/other-cell-backups/objects/"
                "templates/.permission-probe",
                argv,
            )
            self.assertIn("--permission=storage.objects.get", argv)


class EffectiveIamCommandTests(unittest.TestCase):
    def test_effective_iam_uses_supported_project_scope_flag(self):
        command = VERIFY.effective_iam_command(
            "example-project", "reader@example-project.iam.gserviceaccount.com", "cell-backups"
        )
        self.assertIn("--project=example-project", command)
        self.assertNotIn("--scope=projects/example-project", command)


class EffectiveIamCompletenessTests(unittest.TestCase):
    def test_complete_empty_results_allow_protobuf_omission(self):
        for analysis in ({"fullyExplored": True}, {"fullyExplored": True, "analysisResults": []}):
            self.assertEqual(VERIFY.iam_analysis_results(json.dumps(analysis)), [])
            self.assertEqual(VERIFY.iam_analysis_results(json.dumps({
                "fullyExplored": True, "mainAnalysis": analysis,
                "serviceAccountImpersonationAnalysis": [analysis],
            })), [])

    def test_every_analysis_must_explicitly_be_complete(self):
        for incomplete in ({}, {"fullyExplored": False}, {"fullyExplored": "true"}, {"fullyExplored": 1}):
            for document in (
                incomplete,
                {**incomplete, "mainAnalysis": {"fullyExplored": True}},
                {"fullyExplored": True, "mainAnalysis": incomplete},
                {"fullyExplored": True, "mainAnalysis": {"fullyExplored": True},
                 "serviceAccountImpersonationAnalysis": [incomplete]},
            ):
                with self.subTest(document=document), self.assertRaises(VERIFY.VerificationError):
                    VERIFY.iam_analysis_results(json.dumps(document))

    def test_errors_and_malformed_results_are_rejected(self):
        for document in (
            [], None,
            {"fullyExplored": True, "analysisResults": {}},
            {"fullyExplored": True, "nonCriticalErrors": [{"cause": "PERMISSION_DENIED"}]},
            {"fullyExplored": True, "nonCriticalErrors": {}},
            {"fullyExplored": True, "mainAnalysis": None},
            {"fullyExplored": True, "mainAnalysis": {"fullyExplored": True, "nonCriticalErrors": [{}]}},
            {"fullyExplored": True, "serviceAccountImpersonationAnalysis": []},
            {"fullyExplored": True, "mainAnalysis": {"fullyExplored": True},
             "serviceAccountImpersonationAnalysis": {}},
            {"fullyExplored": True, "mainAnalysis": {"fullyExplored": True},
             "serviceAccountImpersonationAnalysis": [{"fullyExplored": True, "analysisResults": None}]},
        ):
            with self.subTest(document=document), self.assertRaises(VERIFY.VerificationError):
                VERIFY.iam_analysis_results(json.dumps(document))
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.iam_analysis_results("invalid JSON")

    def test_direct_and_impersonation_grants_are_preserved_for_rejection(self):
        for key in ("mainAnalysis", "serviceAccountImpersonationAnalysis"):
            document = {"fullyExplored": True, "mainAnalysis": {"fullyExplored": True}}
            grant = {"fullyExplored": True, "analysisResults": [{"identity": "host"}]}
            document[key] = [grant] if key == "serviceAccountImpersonationAnalysis" else grant
            self.assertEqual(VERIFY.iam_analysis_results(json.dumps(document)), [{"identity": "host"}])


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


if __name__ == "__main__":
    unittest.main()
