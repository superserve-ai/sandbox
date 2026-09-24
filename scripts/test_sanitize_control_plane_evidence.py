import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sanitize_control_plane_evidence",
    Path(__file__).with_name("sanitize-control-plane-evidence.py"),
)
SANITIZE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SANITIZE)


class SanitizedEvidenceTests(unittest.TestCase):
    def test_summary_drops_production_details_and_command_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            public = root / "public"
            private.mkdir()
            (private / "evidence.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "checks": [
                            {
                                "name": "bucket-iam",
                                "status": "PASS",
                                "argv": ["--project=production-project"],
                                "principal": "runtime@production-project.iam.gserviceaccount.com",
                                "resource": "gs://production-backups/templates/example/manifest.json",
                            }
                        ],
                    }
                )
            )
            (private / "commands").mkdir()
            (private / "commands" / "01-bucket-iam.stdout").write_text("production policy")

            SANITIZE.write_summary(private, public, "production-use4")

            summary = json.loads((public / "summary.json").read_text())
            self.assertEqual(summary["status"], "PASS")
            self.assertEqual(summary["checks"], [{"name": "bucket-iam", "status": "PASS"}])
            self.assertNotIn("production-project", (public / "summary.json").read_text())
            self.assertNotIn("commands", {path.name for path in public.rglob("*")})

            (private / "evidence.json").write_text(
                json.dumps({"status": "PASS", "checks": [{"name": "principal@example.com", "status": "PASS"}]})
            )
            SANITIZE.write_summary(private, public, "production-use4")
            summary = json.loads((public / "summary.json").read_text())
            self.assertEqual(summary["checks"], [{"name": "check-1", "status": "PASS"}])
            self.assertNotIn("principal@example.com", (public / "summary.json").read_text())

    def test_missing_private_evidence_is_safe_incomplete_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public"
            SANITIZE.write_summary(root / "missing", public, "staging")
            summary = json.loads((public / "summary.json").read_text())
            self.assertEqual(summary["status"], "INCOMPLETE")
            self.assertEqual(summary["checks"], [])


if __name__ == "__main__":
    unittest.main()
