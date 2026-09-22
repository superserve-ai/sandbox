import importlib.util
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


class EffectiveIamCommandTests(unittest.TestCase):
    def test_effective_iam_uses_supported_project_scope_flag(self):
        command = VERIFY.effective_iam_command(
            "example-project", "reader@example-project.iam.gserviceaccount.com", "cell-backups"
        )
        self.assertIn("--project=example-project", command)
        self.assertNotIn("--scope=projects/example-project", command)


if __name__ == "__main__":
    unittest.main()
