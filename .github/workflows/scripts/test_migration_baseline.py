import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


SPEC = importlib.util.spec_from_file_location("deployment_gate", Path(__file__).with_name("wait-for-push-ci.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class MigrationBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.checkout = self.root / "source", self.root / "checkout"
        self.source.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.test")
        self.git("commit", "-q", "--allow-empty", "-m", "baseline")
        self.base = self.git("rev-parse", "HEAD")
        migrations = self.source / "supabase/migrations"
        migrations.mkdir(parents=True)
        self.migration = migrations / "20990101000000_example.sql"
        self.migration.write_text("SELECT 1;\n")
        self.commit("migration A")
        self.a = self.git("rev-parse", "HEAD")
        (self.source / "app.txt").write_text("application B\n")
        self.commit("application B")
        self.b = self.git("rev-parse", "HEAD")
        subprocess.run(["git", "clone", "-q", "--depth=1", self.source.as_uri(), str(self.checkout)], check=True)
        self.tip = self.b
        self.runs = [self.record(1, self.base)]
        self.jobs = {}
        self.mutate_inventory = False
        self.inventory_calls = 0

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.source, text=True).strip()

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-qm", message)

    def record(self, number, sha, **overrides):
        return dict(id=number, head_sha=sha, head_branch="main", event="push",
                    path=".github/workflows/cd.yml", status="completed", conclusion="success",
                    run_attempt=1, updated_at=f"2099-01-01T00:{number:02}:00Z", **overrides)

    def command(self, args, **kwargs):
        if args[0] == "git":
            return subprocess.run(args, cwd=self.checkout, **kwargs)
        path = args[2]
        if path.endswith("git/ref/heads/main"):
            response = {"object": {"sha": self.tip}}
        elif "workflows/cd.yml/runs?" in path:
            self.inventory_calls += 1
            if self.mutate_inventory and self.inventory_calls == 2:
                self.runs[0]["run_attempt"] += 1
            page = int(path.rsplit("page=", 1)[1])
            response = {"workflow_runs": self.runs[(page - 1) * 100:page * 100], "total_count": len(self.runs)}
        else:
            run_id = int(path.split("/runs/")[1].split("/")[0])
            names = self.jobs.get(run_id, {"Migrate Staging": "success", "Migrate Production": "success"})
            response = {"jobs": [{"name": name, "conclusion": state} for name, state in names.items()],
                        "total_count": len(names)}
        return SimpleNamespace(returncode=0, stdout=json.dumps(response))

    def check(self, expected, **kwargs):
        self.assertEqual(GATE.wait_for_migration_baseline("example/repo", self.tip, "push",
                         attempts=2, interval=0, run=self.command, sleep=Mock(), **kwargs), expected)

    def test_inherited_migration_cannot_escape_with_app_only_push(self):
        # B's own push has no migration diff, but A was never applied.
        self.check(False)
        self.runs.insert(0, self.record(2, self.a))
        self.runs[0]["conclusion"] = "cancelled"
        self.check(False)
        self.runs[0]["status"] = "in_progress"
        self.check(False)
        self.runs[0].update(status="completed", conclusion="success")
        self.check(True)

    def test_current_tip_manual_migration_establishes_baseline(self):
        self.runs.insert(0, self.record(2, self.b))
        self.runs[0]["event"] = "workflow_dispatch"
        self.check(True)

    def test_preflight_and_partial_region_are_not_migration_success(self):
        self.runs.insert(0, self.record(2, self.b))
        self.jobs[2] = {"Preflight Staging": "success", "Preflight Production": "success"}
        self.check(False)
        self.jobs[2] = {"Migrate Staging": "success", "Migrate Production": "skipped"}
        self.check(False)
        self.jobs[2] = {"Migrate Staging": "success", "Migrate Production": "failure"}
        self.check(False)
        self.runs[1]["head_sha"] = self.a
        self.jobs[2] = {"Preflight Staging": "success", "Preflight Production": "success"}
        self.check(True)

    def test_failed_read_only_preflight_does_not_invalidate_migration_success(self):
        self.runs = [self.record(2, self.b), self.record(1, self.a)]
        self.jobs[2] = {"Verify migration release": "success", "Preflight Staging": "failure",
                        "Preflight Production": "skipped"}
        for conclusion in ("failure", "cancelled", "timed_out"):
            self.runs[0]["conclusion"] = conclusion
            self.check(True)
        self.jobs[2]["Migrate Production"] = "failure"
        self.check(False)

    def test_pending_read_only_preflight_does_not_hold_rollout(self):
        self.runs = [self.record(2, self.b), self.record(1, self.a)]
        self.jobs[2] = {"Verify migration release": "success", "Preflight Staging": None,
                        "Preflight Production": None}
        for status in ("waiting", "queued", "in_progress"):
            self.runs[0].update(status=status, conclusion=None)
            self.check(True)
        self.jobs[2] = {"Verify migration release": None}
        self.check(False)
        self.jobs[2]["Migrate Staging"] = None
        self.check(False)

    def test_newer_failed_or_running_attempt_invalidates_older_success(self):
        self.runs = [self.record(2, self.a), self.record(1, self.a)]
        # Creation order is deliberately different from attempt completion order.
        self.runs[1].update(run_attempt=2, updated_at="2099-01-02T00:00:00Z", conclusion="failure")
        self.check(False)
        self.runs[1].update(status="in_progress", conclusion=None)
        self.check(False)

    def test_revert_does_not_reuse_old_matching_tree(self):
        self.migration.unlink()
        self.commit("revert migration")
        self.tip = self.git("rev-parse", "HEAD")
        self.check(False)

    def test_pending_normal_migration_can_finish(self):
        self.runs = [self.record(2, self.a)]
        self.runs[0].update(status="in_progress", conclusion=None)
        def finish(_):
            self.runs[0].update(status="completed", conclusion="success")
        self.assertTrue(GATE.wait_for_migration_baseline("example/repo", self.tip, "push",
                        attempts=2, interval=0, run=self.command, sleep=finish))

    def test_changed_attempt_or_main_refuses_release(self):
        self.runs = [self.record(2, self.a)]
        self.mutate_inventory = True
        self.check(False)
        self.mutate_inventory = False
        self.assertFalse(GATE.wait_for_migration_baseline("example/repo", self.a, "push", run=self.command))

    def test_paginated_inventory_is_complete(self):
        self.runs = [self.record(number, self.a) for number in range(1, 102)]
        self.check(True)
        self.assertEqual(self.inventory_calls, 4)

    def test_missing_malformed_and_incomplete_evidence_fail_closed(self):
        for payload in ("not json", {}, {"workflow_runs": [], "total_count": 1001},
                        {"workflow_runs": [], "total_count": 1}):
            def broken_inventory(args, **kwargs):
                if args[0] == "gh" and "workflows/cd.yml/runs?" in args[2]:
                    return SimpleNamespace(returncode=0, stdout=json.dumps(payload))
                return self.command(args, **kwargs)
            self.assertFalse(GATE.wait_for_migration_baseline("example/repo", self.tip, "push",
                             run=broken_inventory))
        self.runs = []
        self.check(False)

    def test_wrong_run_identity_and_incomplete_jobs_are_rejected(self):
        for key, value in (("path", ".github/workflows/other.yml"), ("head_branch", "topic"),
                           ("head_sha", "main"), ("event", "pull_request"), ("run_attempt", 0)):
            self.runs = [self.record(2, self.a)]
            self.runs[0][key] = value
            self.check(False)
        self.runs = [self.record(2, self.a)]
        def incomplete_jobs(args, **kwargs):
            result = self.command(args, **kwargs)
            if args[0] == "gh" and "/jobs?" in args[2]:
                payload = json.loads(result.stdout)
                payload["total_count"] += 1
                return SimpleNamespace(returncode=0, stdout=json.dumps(payload))
            return result
        self.assertFalse(GATE.wait_for_migration_baseline("example/repo", self.tip, "push", run=incomplete_jobs))

    def test_main_advancing_only_at_final_proof_check_rejects_release(self):
        self.runs = [self.record(2, self.a)]
        main_reads = 0
        def advancing_main(args, **kwargs):
            nonlocal main_reads
            if args[0] == "gh" and args[2].endswith("git/ref/heads/main"):
                main_reads += 1
                if main_reads == 2:
                    return SimpleNamespace(returncode=0, stdout=json.dumps({"object": {"sha": self.a}}))
            return self.command(args, **kwargs)
        self.assertFalse(GATE.wait_for_migration_baseline("example/repo", self.tip, "push", run=advancing_main))
        self.assertEqual(main_reads, 2)

    def test_pending_preflight_requires_complete_known_job_inventory(self):
        self.runs = [self.record(2, self.b), self.record(1, self.a)]
        self.runs[0].update(status="waiting", conclusion=None)
        self.jobs[2] = {"Preflight Staging": None, "Unknown database action": None}
        self.check(False)
        self.jobs[2] = {"Preflight Staging": None}
        def truncated_jobs(args, **kwargs):
            result = self.command(args, **kwargs)
            if args[0] == "gh" and "/runs/2/attempts/" in args[2]:
                data = json.loads(result.stdout)
                data["total_count"] += 1
                return SimpleNamespace(returncode=0, stdout=json.dumps(data))
            return result
        self.assertFalse(GATE.wait_for_migration_baseline("example/repo", self.tip, "push", run=truncated_jobs))

    def test_non_successful_migration_conclusions_require_later_full_success(self):
        self.runs = [self.record(2, self.a), self.record(1, self.base)]
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral"):
            self.runs[0]["conclusion"] = conclusion
            self.check(False)
        self.runs.insert(0, self.record(3, self.b))
        self.check(True)

    def test_manual_dispatch_and_ci_function_do_not_require_migration_baseline(self):
        run = Mock()
        self.assertTrue(GATE.wait_for_migration_baseline("example/repo", self.tip, "workflow_dispatch", run=run))
        run.assert_not_called()
        run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps({"workflow_runs": [
            dict(head_sha=self.tip, event="push", status="completed", conclusion="success")]}))
        self.assertTrue(GATE.wait_for_ci("example/repo", self.tip, "push", run=run))
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
