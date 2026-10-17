import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


PATH = Path(__file__).with_name("wait-for-push-ci.py")
SPEC = importlib.util.spec_from_file_location("push_ci", PATH)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PushCIGateTests(unittest.TestCase):
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

    def test_transient_lookup_failure_does_not_decide(self):
        good = dict(head_sha="a" * 40, event="push", status="completed", conclusion="success")
        ok = SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": [good]}))
        pending = SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": [
            dict(good, status="in_progress", conclusion=None)]}))
        bad = SimpleNamespace(returncode=1, stdout="")
        run = Mock(side_effect=[bad, pending, bad, bad, ok])
        self.assertTrue(GATE.wait_for_ci("example/repo", "a" * 40, "push",
                                        attempts=6, interval=0, tolerance=3,
                                        run=run, sleep=Mock()))
        self.assertEqual(run.call_count, 5)
        run = Mock(return_value=bad)
        self.assertFalse(GATE.wait_for_ci("example/repo", "a" * 40, "push",
                                         attempts=60, interval=0, tolerance=3,
                                         run=run, sleep=Mock()))
        self.assertEqual(run.call_count, 3)
