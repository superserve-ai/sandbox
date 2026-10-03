import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


PATH = Path(__file__).with_name("wait-for-push-ci.py")
SPEC = importlib.util.spec_from_file_location("push_ci", PATH)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PushCIGateTests(unittest.TestCase):
    def test_real_shallow_checkout_checks_whole_push_and_renamed_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, checkout = root / "source", root / "checkout"
            source.mkdir()

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=source, text=True).strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.test")
            git("commit", "-q", "--allow-empty", "-m", "base")
            before = git("rev-parse", "HEAD")
            history = source / "supabase/shared-auth-history"
            history.mkdir(parents=True)
            (history / "setup.sql").write_text("SELECT 1;\n")
            git("add", ".")
            git("commit", "-qm", "history input")
            (source / "api.txt").write_text("application change\n")
            git("add", ".")
            git("commit", "-qm", "application tip")
            head = git("rev-parse", "HEAD")
            subprocess.run(["git", "clone", "-q", "--depth=1", source.as_uri(), str(checkout)], check=True)

            def run(args, **kwargs):
                return subprocess.run(args, cwd=checkout, **kwargs)

            self.assertTrue(GATE.recovery_hold(before, head, "push", run=run))
            git("mv", "supabase/shared-auth-history/setup.sql", "renamed.sql")
            git("commit", "-qm", "rename control input")
            renamed = git("rev-parse", "HEAD")
            subprocess.run(["git", "fetch", "-q", "origin", "main"], cwd=checkout, check=True)
            self.assertTrue(GATE.recovery_hold(head, renamed, "push", run=run))

    def test_recovery_changes_hold_complete_push_including_mixed_changes(self):
        for path in GATE.RECOVERY_PATHS | {"scripts/recovery_retired_receivers.json",
                                         "supabase/shared-auth-history/setup.sql",
                                         "supabase/shared-auth-migrations/setup.sql"}:
            with self.subTest(path=path):
                run = Mock(side_effect=[SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=0, stdout="internal/api/handler.go\0infra/main.tf\0" + path + "\0")])
                self.assertTrue(GATE.recovery_hold("b" * 40, "a" * 40, "push", run=run))
                self.assertEqual(run.call_args.args[0][-3:], ["b" * 40, "a" * 40, "--"])
                self.assertIn("--no-renames", run.call_args.args[0])

    def test_ordinary_push_and_manual_dispatch_are_not_held(self):
        run = Mock(side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=0,
                   stdout="internal/api/handler.go\0supabase/migrations/new.sql\0")])
        self.assertFalse(GATE.recovery_hold("b" * 40, "a" * 40, "push", run=run))
        run.reset_mock()
        self.assertFalse(GATE.recovery_hold("", "a" * 40, "workflow_dispatch", run=run))
        run.assert_not_called()

    def test_unknown_push_diff_is_held(self):
        for before in ("", "0" * 40, "not-a-sha"):
            self.assertTrue(GATE.recovery_hold(before, "a" * 40, "push"))
        self.assertTrue(GATE.recovery_hold("b" * 40, "a" * 40, "push",
                                          run=Mock(return_value=SimpleNamespace(returncode=1))))
        self.assertTrue(GATE.recovery_hold("b" * 40, "a" * 40, "push", run=Mock(side_effect=[
            SimpleNamespace(returncode=0), SimpleNamespace(returncode=1)])))

    def check(self, runs, expected):
        result = SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": runs}))
        run, sleep = Mock(return_value=result), Mock()
        self.assertEqual(GATE.wait_for_ci("example/repo", "a" * 40, "push",
                                         attempts=2, interval=0, run=run, sleep=sleep), expected)
        for call in run.call_args_list:
            self.assertIn("head_sha=" + "a" * 40 + "&event=push", call.args[0][2])
        self.assertLessEqual(run.call_count, 2)

    def test_exact_push_revision_and_success_required(self):
        good = dict(head_sha="a" * 40, event="push", status="completed", conclusion="success")
        self.check([good], True)
        for conclusion in ("failure", "cancelled", "skipped", "timed_out", "neutral"):
            with self.subTest(conclusion=conclusion):
                self.check([dict(good, conclusion=conclusion)], False)
        self.check([dict(good, head_sha="b" * 40)], False)
        self.check([dict(good, event="pull_request")], False)
        self.check([], False)
        self.check([dict(good, status="in_progress", conclusion=None), good], False)

    def test_pending_then_success_and_manual_semantics(self):
        good = dict(head_sha="a" * 40, event="push", status="completed", conclusion="success")
        run = Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": []})),
            SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": [good]})),
        ])
        self.assertTrue(GATE.wait_for_ci("example/repo", "a" * 40, "push",
                                        attempts=2, interval=0, run=run, sleep=Mock()))
        run.reset_mock()
        self.assertTrue(GATE.wait_for_ci("example/repo", "a" * 40, "workflow_dispatch", run=run))
        run.assert_not_called()

    def test_lookup_failure_fails_closed(self):
        for result in (SimpleNamespace(returncode=1, stdout=""),
                       SimpleNamespace(returncode=0, stdout="not JSON")):
            self.assertFalse(GATE.wait_for_ci("example/repo", "a" * 40, "push",
                                             run=Mock(return_value=result), sleep=Mock()))

    def test_deployment_roots_require_ci_before_migration_gate(self):
        for name in ("deploy-api.yml", "deploy-proxy.yml", "terraform-cd.yml"):
            with self.subTest(workflow=name):
                workflow = PATH.parents[1].joinpath(name).read_text()
                self.assertLess(workflow.index("python3 .github/workflows/scripts/wait-for-push-ci.py"),
                                workflow.index("- name: Wait for same-SHA CD Migrate to succeed"))
                self.assertIn("actions: read", workflow[:workflow.index("wait-for-push-ci.py")])
