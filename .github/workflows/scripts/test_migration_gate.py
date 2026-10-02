import subprocess
import unittest
from unittest.mock import patch

import migration_gate as gate


SHA = "a" * 40
BEFORE = "b" * 40


class MigrationGateTest(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_SHA": SHA, "GITHUB_REPOSITORY": "example/project",
                    "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "APPROVED_REVISION": SHA, "MIGRATION_ACTION": "preflight",
                    "MIGRATION_ENVIRONMENT": "production", "PREFLIGHT_RUN_ID": "123"}
        self.ci = patch.object(gate.push_ci, "wait_for_ci", return_value=True).start()
        self.addCleanup(patch.stopall)
        self.run = {"head_sha": SHA, "head_branch": "main", "event": "workflow_dispatch",
                    "status": "completed", "conclusion": "success", "path": ".github/workflows/cd.yml"}
        self.jobs = {"jobs": [{"name": name, "conclusion": "success"}
                              for name in ("Preflight Staging", "Preflight Production")]}

    def api(self, repository, path):
        if path == "git/ref/heads/main":
            return {"object": {"sha": SHA}}
        return self.jobs if "/jobs?" in path else self.run

    def test_preflight_is_read_only_and_migrate_requires_receipt(self):
        with patch.object(gate, "api", side_effect=self.api):
            self.assertEqual(gate.select_action(self.env), ("preflight", True))
            self.env["MIGRATION_ACTION"] = "migrate"
            self.assertEqual(gate.select_action(self.env), ("push", True))
            self.jobs["jobs"].pop()
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)
            self.env["MIGRATION_ENVIRONMENT"] = "staging"
            self.assertEqual(gate.select_action(self.env), ("push", False))
        self.ci.assert_called_with("example/project", SHA, "push")

    def test_invalid_manual_inputs_fail_closed(self):
        for key, value in (("APPROVED_REVISION", BEFORE), ("MIGRATION_ACTION", ""),
                           ("MIGRATION_ACTION", "push"), ("MIGRATION_ENVIRONMENT", ""),
                           ("GITHUB_REF", "refs/heads/other"), ("GITHUB_SHA", "main")):
            with self.subTest(key=key, value=value), patch.object(gate, "api", side_effect=self.api):
                with self.assertRaises(gate.GateError):
                    gate.select_action({**self.env, key: value})
        with patch.object(gate, "api", return_value={"object": {"sha": BEFORE}}):
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)
        self.ci.return_value = False
        with patch.object(gate, "api", side_effect=self.api), self.assertRaises(gate.GateError):
            gate.select_action(self.env)

    def test_wrong_or_incomplete_preflight_is_rejected(self):
        self.env["MIGRATION_ACTION"] = "migrate"
        for key, value in (("head_sha", BEFORE), ("event", "push"), ("status", "in_progress"),
                           ("conclusion", "failure"), ("path", ".github/workflows/other.yml"),
                           ("head_branch", "other")):
            with self.subTest(key=key), patch.object(gate, "api", side_effect=self.api):
                original = self.run[key]
                self.run[key] = value
                with self.assertRaises(gate.GateError):
                    gate.select_action(self.env)
                self.run[key] = original
        self.jobs["jobs"] = [{"name": "Migrate Production", "conclusion": "success"}]
        with patch.object(gate, "api", side_effect=self.api), self.assertRaises(gate.GateError):
            gate.select_action(self.env)
        for run_id in ("", "0", "../123", "abc"):
            with patch.object(gate, "api", side_effect=self.api), self.assertRaises(gate.GateError):
                gate.select_action({**self.env, "PREFLIGHT_RUN_ID": run_id})

    def test_full_push_range_and_mixed_control_change_hold(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            output = "supabase/migrations/20990101000000_example.sql\0scripts/migrate_database.py\0"
            return subprocess.CompletedProcess(args, 0, stdout=output if args[1] == "diff" else "")

        self.assertTrue(gate.push_ci.recovery_hold(BEFORE, SHA, "push", run=run))
        self.assertEqual(calls[-1][-3:], [BEFORE, SHA, "--"])
        for path in gate.push_ci.RECOVERY_PATHS:
            with self.subTest(path=path):
                result = subprocess.CompletedProcess([], 0, stdout=path + "\0")
                self.assertTrue(gate.push_ci.recovery_hold(BEFORE, SHA, "push", run=lambda *a, **k: result))
        result = subprocess.CompletedProcess([], 0, stdout="supabase/migrations/20990101000000_example.sql\0")
        self.assertFalse(gate.push_ci.recovery_hold(BEFORE, SHA, "push", run=lambda *a, **k: result))
        self.assertTrue(gate.push_ci.recovery_hold("0" * 40, SHA, "push", run=run))
        self.assertTrue(gate.push_ci.recovery_hold(BEFORE, SHA, "push", run=lambda *a, **k: subprocess.CompletedProcess([], 1)))

    def test_push_hold_precedes_ci_and_database_jobs(self):
        env = {**self.env, "GITHUB_EVENT_NAME": "push", "PUSH_BEFORE": BEFORE}
        with patch.object(gate.push_ci, "recovery_hold", return_value=True):
            with self.assertRaises(gate.GateError):
                gate.select_action(env)
            self.ci.assert_not_called()
        with patch.object(gate.push_ci, "recovery_hold", return_value=False), patch.object(gate, "api", side_effect=self.api):
            self.assertEqual(gate.select_action(env), ("push", True))

    def test_main_advance_during_ci_wait_holds(self):
        with patch.object(gate, "api", side_effect=[{"object": {"sha": SHA}}, {"object": {"sha": BEFORE}}]):
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)


if __name__ == "__main__":
    unittest.main()
