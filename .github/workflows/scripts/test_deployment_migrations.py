"""Exercise deployment prerequisites without cloud credentials or migrations."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deployment_migration_gate as gate


SHA, OLD = "a" * 40, "b" * 40
WORKFLOWS = Path(__file__).parents[1]


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(GITHUB_REPOSITORY="example/repo", GITHUB_SHA=SHA,
                        GITHUB_REF="refs/heads/main", GITHUB_EVENT_NAME="push",
                        DEPLOYMENT_REVISION=SHA, DEPLOYMENT_PRODUCTION="true")

    def test_current_revision_ci_and_manual_failure(self):
        for event in ("push", "workflow_dispatch"):
            env = dict(self.env, GITHUB_EVENT_NAME=event)
            with patch.object(gate, "api", return_value={"object": {"sha": SHA}}), \
                    patch.object(gate.push_ci, "wait_for_ci", return_value=True) as ci:
                self.assertEqual(gate.require_ci(env), SHA)
                ci.assert_called_once_with("example/repo", SHA, "push")
                ci.return_value = False
                with self.assertRaises(gate.GateError):
                    gate.require_ci(env)
        with patch.object(gate, "api", return_value={"object": {"sha": OLD}}), \
                self.assertRaises(gate.GateError):
            gate.require_ci(self.env)
        with patch.object(gate, "api", side_effect=[{"object": {"sha": SHA}}, {"object": {"sha": OLD}}]), \
                patch.object(gate.push_ci, "wait_for_ci", return_value=True), self.assertRaises(gate.GateError):
            gate.require_ci(self.env)

    def test_only_authenticated_proxy_resume_can_use_ancestor(self):
        env = dict(self.env, GITHUB_EVENT_NAME="workflow_dispatch", DEPLOYMENT_REVISION=OLD, RESUME_RUN_ID="123")
        run = dict(head_sha=OLD, head_branch="main", path=".github/workflows/deploy-proxy.yml", event="push")
        with patch.object(gate, "api", side_effect=[run, {"status": "ahead"}]):
            self.assertEqual(gate.verify_revision(env), OLD)
        for override in ({"path": ".github/workflows/other.yml"}, {"head_sha": SHA},
                         {"head_branch": "other"}, {"event": "pull_request"}):
            with patch.object(gate, "api", return_value=dict(run, **override)), self.assertRaises(gate.GateError):
                gate.verify_revision(env)
        for state in ("behind", "diverged", None):
            with patch.object(gate, "api", side_effect=[run, {"status": state}]), self.assertRaises(gate.GateError):
                gate.verify_revision(env)
        with self.assertRaises(gate.GateError):
            gate.verify_revision(dict(env, GITHUB_EVENT_NAME="push"))

    def test_branch_staging_uses_main_and_rejects_changed_inherited_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
            git("init", "-q", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.test")
            migrations = root / "supabase/migrations"
            migrations.mkdir(parents=True)
            (migrations / "20990101000000_required.sql").write_text("SELECT 1;\n")
            git("add", ".")
            git("commit", "-qm", "migration")
            main = git("rev-parse", "HEAD")
            git("remote", "add", "origin", str(root))
            git("switch", "-qc", "branch")
            (root / "app.txt").write_text("application only\n")
            git("add", ".")
            git("commit", "-qm", "application")
            branch = git("rev-parse", "HEAD")
            env = dict(self.env, GITHUB_SHA=branch, DEPLOYMENT_REVISION=branch, GITHUB_REF="refs/heads/branch",
                       GITHUB_EVENT_NAME="workflow_dispatch", DEPLOYMENT_PRODUCTION="false", ALLOW_BRANCH_STAGING="true")
            original_run = subprocess.run
            def command(*args, **kwargs):
                return original_run(*args, cwd=root, **kwargs)
            with patch.object(gate, "api", return_value={"object": {"sha": main}}), \
                    patch.object(gate.subprocess, "run", side_effect=command), \
                    patch.object(gate.push_ci, "wait_for_ci", return_value=True) as ci:
                self.assertEqual(gate.require_ci(env), main)
                ci.assert_called_once_with("example/repo", main, "push")
                for override in ({"DEPLOYMENT_PRODUCTION": "true"}, {"ALLOW_BRANCH_STAGING": "false"},
                                 {"GITHUB_EVENT_NAME": "push"}, {"RESUME_RUN_ID": "123"}):
                    with self.assertRaises(gate.GateError):
                        gate.verify_revision(dict(env, **override))
            # An inherited SQL or preparation-helper change cannot use main's
            # migrations as proof, even after an application-only commit.
            for path in (migrations / "20990102000000_branch.sql",
                         root / "scripts/snapshot_reference_index.py"):
                with self.subTest(path=path.relative_to(root)):
                    git("reset", "--hard", branch)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("-- changed migration input\n")
                    git("add", ".")
                    git("commit", "-qm", "branch migration input")
                    (root / "app.txt").write_text("another application edit\n")
                    git("add", ".")
                    git("commit", "-qm", "application after migration input")
                    tip = git("rev-parse", "HEAD")
                    with patch.object(gate, "api", return_value={"object": {"sha": main}}), \
                            patch.object(gate.subprocess, "run", side_effect=command), self.assertRaises(gate.GateError):
                        gate.verify_revision(dict(env, GITHUB_SHA=tip, DEPLOYMENT_REVISION=tip))


def job_blocks(workflow):
    body = workflow.split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", body, re.M))
    return {m[1]: body[m.end():starts[i + 1].start() if i + 1 < len(starts) else len(body)]
            for i, m in enumerate(starts)}


def dependencies(block):
    match = re.search(r"^    needs: \[([^]]*)\]$", block, re.M)
    return [name.strip() for name in match[1].split(",")] if match else []


class DependencyTests(unittest.TestCase):
    def test_failed_cancelled_or_skipped_prerequisite_blocks_every_deployment(self):
        for workflow, prerequisite in (("deploy-api.yml", "wait-for-migrations"),
                                       ("deploy-proxy.yml", "migrations"), ("terraform-cd.yml", "wait-for-migrations")):
            source = (WORKFLOWS / workflow).read_text()
            jobs = job_blocks(source)
            self.assertIn("uses: ./.github/workflows/deployment-migrations.yml", jobs[prerequisite])
            self.assertNotIn("continue-on-error", jobs[prerequisite])
            self.assertNotIn("workflows/cd.yml/runs", source)
            for failed in ("failure", "cancelled", "skipped"):
                states = {prerequisite: failed}
                def state(name):
                    if name not in states:
                        deps = dependencies(jobs[name])
                        states[name] = "success" if all(state(dep) == "success" for dep in deps) else "skipped"
                    return states[name]
                for name, block in jobs.items():
                    if "environment:" in block or "docker build" in block:
                        with self.subTest(workflow=workflow, job=name, prerequisite=failed):
                            self.assertNotIn("always()", block.split("    steps:")[0])
                            self.assertNotIn("!cancelled()", block.split("    steps:")[0])
                            self.assertEqual(state(name), "skipped")

    def test_all_regions_exact_checkout_and_separate_locks(self):
        source = (WORKFLOWS / "deployment-migrations.yml").read_text()
        jobs = job_blocks(source)
        self.assertEqual(dependencies(jobs["staging"]), ["gate"])
        self.assertEqual(dependencies(jobs["production"]), ["gate", "staging"])
        self.assertNotIn("continue-on-error", source)
        self.assertLess(source.index("migrate_database.py use4 push"), source.index("migrate_database.py usw2 push"))
        self.assertEqual(source.count("ref: ${{ needs.gate.outputs.migration_revision }}"), 2)
        self.assertEqual(source.count("deployment_migration_gate.py --verify-revision"), 3)
        self.assertNotIn("recover", source)
        for caller in ("deploy-api.yml", "deploy-proxy.yml", "terraform-cd.yml"):
            self.assertNotIn("group: database-migrations", (WORKFLOWS / caller).read_text())
        self.assertIn("group: database-migrations", source)
        cd = (WORKFLOWS / "cd.yml").read_text()
        self.assertNotRegex(cd, r"(?m)^  push:")
        self.assertIn("recovery-preflight", cd)
        self.assertIn("group: database-migrations", cd)
        api = (WORKFLOWS / "deploy-api.yml").read_text()
        for path in (*gate.MIGRATION_INPUTS, ".github/workflows/deployment-migrations.yml"):
            pattern = path + "/**" if path.startswith("supabase/") else path
            self.assertIn("- '" + pattern + "'", api)


if __name__ == "__main__":
    unittest.main()
