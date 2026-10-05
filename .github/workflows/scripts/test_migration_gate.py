import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
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

    def test_recovery_requires_distinct_preflight_and_fresh_evidence(self):
        self.env["MIGRATION_ACTION"] = "recovery-preflight"
        with patch.object(gate, "api", side_effect=self.api):
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)
            self.env["RECOVERY_EVIDENCE_RUN_ID"] = "456"
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)
            self.env["RECOVERY_COORDINATION_ACK"] = "accepted"
            self.assertEqual(gate.select_action(self.env), ("recovery-preflight", True))
            self.env["MIGRATION_ACTION"] = "recover"
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)
            self.jobs["jobs"] = [{"name": name, "conclusion": "success"} for name in
                                 ("Recovery Preflight Staging", "Recovery Preflight Production")]
            self.assertEqual(gate.select_action(self.env), ("recover", True))
            self.env["MIGRATION_ACTION"] = "migrate"
            with self.assertRaises(gate.GateError):
                gate.select_action(self.env)

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

    def test_environment_approval_cannot_release_stale_revision(self):
        with patch.object(gate, "api", side_effect=self.api):
            self.assertEqual(gate.select_action(self.env), ("preflight", True))
            gate.verify_revision(self.env)
        with patch.object(gate, "api", return_value={"object": {"sha": BEFORE}}):
            with self.assertRaises(gate.GateError):
                gate.verify_revision(self.env)
        with patch.object(gate, "api", side_effect=gate.GateError("Unavailable")):
            with self.assertRaises(gate.GateError):
                gate.verify_revision(self.env)
        # Every regional action must recheck after its environment approval,
        # including West after East has finished in the same production job.
        workflow = Path(__file__).parents[1].joinpath("cd.yml").read_text()
        for target in ("staging", "use4", "usw2"):
            self.assertIn("python3 .github/workflows/scripts/migration_gate.py --verify-revision\n"
                          f"          python3 scripts/migrate_database.py {target} ", workflow)

    def test_actual_regional_shell_refuses_database_after_main_advances(self):
        root = Path(__file__).resolve().parents[3]
        workflow = (root / ".github/workflows/cd.yml").read_text()
        blocks = re.findall(r"        run: \|\n((?:          .+\n)+)", workflow)
        self.assertEqual(len(blocks), 3)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            gh = directory / "gh"
            gh.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
                          "if os.environ.get('GH_FAIL'): sys.exit(1)\n"
                          "print(json.dumps({'object': {'sha': os.environ['CURRENT_MAIN']}}))\n")
            gh.chmod(0o755)
            marker = directory / "database-invoked"
            recorder = directory / "record.py"
            recorder.write_text("import os\nfrom pathlib import Path\nPath(os.environ['MARKER']).touch()\n")
            env = {**os.environ, **self.env, "PATH": temp + os.pathsep + os.environ["PATH"],
                   "MARKER": str(marker), "CURRENT_MAIN": SHA}
            for target, block in zip(("staging", "use4", "usw2"), blocks):
                shell = block.replace("python3 scripts/migrate_database.py", "python3 " + shlex.quote(str(recorder)))
                with self.subTest(target=target):
                    result = subprocess.run(["bash", "-e", "-c", shell], cwd=root, env=env, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(marker.exists())
                    marker.unlink()
                    # Main changes after the initial gate, during either
                    # environment wait, or after the preceding region finishes.
                    for changed in ({"CURRENT_MAIN": BEFORE}, {"GH_FAIL": "1"}):
                        result = subprocess.run(["bash", "-e", "-c", shell], cwd=root,
                                                env={**env, **changed}, capture_output=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(marker.exists(), "stale/unverified action reached the database runner")


if __name__ == "__main__":
    unittest.main()
