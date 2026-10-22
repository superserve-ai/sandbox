"""Exercise deployment prerequisites without cloud credentials or migrations."""

from pathlib import Path
import json
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
            with patch.object(gate, "api", return_value={"status": "identical"}), \
                    patch.object(gate.push_ci, "wait_for_ci", return_value=True) as ci:
                self.assertEqual(gate.require_ci(env), SHA)
                ci.assert_called_once_with("example/repo", SHA, "push")
                ci.return_value = False
                with self.assertRaises(gate.GateError):
                    gate.require_ci(env)

    def test_main_advancing_does_not_invalidate_pinned_deployment(self):
        for event in ("push", "workflow_dispatch"):
            for advance_before_ci in (False, True):
                with self.subTest(event=event, advance_before_ci=advance_before_ci):
                    env = dict(self.env, GITHUB_EVENT_NAME=event)
                    main = {"status": "ahead" if advance_before_ci else "identical"}
                    def complete_ci(*args):
                        main["status"] = "ahead"
                        return True
                    with patch.object(gate, "api", return_value=main), \
                            patch.object(gate.push_ci, "wait_for_ci", side_effect=complete_ci) as ci:
                        self.assertEqual(gate.require_ci(env), SHA)
                        ci.assert_called_once_with("example/repo", SHA, "push")
                        self.assertEqual(gate.verify_revision(env), SHA)

    def test_non_resume_revision_must_match_workflow_commit(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), self.assertRaises(gate.GateError):
                gate.verify_revision(dict(self.env, GITHUB_EVENT_NAME=event, DEPLOYMENT_REVISION=OLD))

    def test_removed_revision_is_rejected_before_or_after_ci(self):
        for event in ("push", "workflow_dispatch"):
            for state in ("behind", "diverged", None):
                for remove_before_ci in (False, True):
                    with self.subTest(event=event, state=state, remove_before_ci=remove_before_ci):
                        env = dict(self.env, GITHUB_EVENT_NAME=event)
                        responses = [{"status": state}] if remove_before_ci else [
                            {"status": "identical"}, {"status": state}]
                        with patch.object(gate, "api", side_effect=responses) as api, \
                                patch.object(gate.push_ci, "wait_for_ci", return_value=True), \
                                self.assertRaisesRegex(gate.GateError, "not an ancestor"):
                            gate.require_ci(env)
                        api.assert_called_with("example/repo", f"compare/{SHA}...main")

    def test_only_authenticated_proxy_resume_can_override_workflow_revision(self):
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
                         root / "scripts/snapshot_reference_index.py",
                         root / "scripts/migrate_shared_auth.py",
                         root / ".github/workflows/deployment-migrations.yml",
                         root / ".github/workflows/scripts/deployment_migration_gate.py",
                         root / ".github/workflows/deploy-api.yml",
                         root / ".github/workflows/terraform-cd.yml",
                         root / ".github/workflows/scripts/migration_gate.py",
                         root / ".github/workflows/scripts/wait-for-push-ci.py"):
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


class SharedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(GITHUB_SHA=SHA, MIGRATION_REVISION=SHA, GITHUB_RUN_ID="123",
                        GITHUB_RUN_ATTEMPT="1", SHARED_AUTH_REQUIRED="true")
        self.bundle = patch.object(gate, "bundle_identity", return_value="c" * 64)
        self.bundle.start()
        self.addCleanup(self.bundle.stop)

    def test_workflow_cli_modes_emit_executed_step_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            env = dict(self.env, GITHUB_OUTPUT=str(output))
            verification = gate.verification_identity(env, "staging", Path("migration-source"))
            with patch.dict(gate.os.environ, env), patch.object(gate.sys, "argv", [
                    "gate", "--apply-shared", "--target", "staging"]), \
                    patch.object(gate, "apply_shared", return_value=verification) as execute:
                self.assertEqual(gate.main(), 0)
                execute.assert_called_once()
            self.assertEqual(json.loads(output.read_text().strip().split("=", 1)[1]), verification)
            output.write_text("")
            with patch.dict(gate.os.environ, dict(env, SHARED_VERIFICATION=json.dumps(verification))), \
                    patch.object(gate.sys, "argv", ["gate", "--record-receipt", "--target", "staging"]):
                self.assertEqual(gate.main(), 0)
            receipt = json.loads(output.read_text().strip().split("=", 1)[1])
            self.assertEqual(receipt["regional_targets"], ["staging"])
            with patch.dict(gate.os.environ, dict(env, MIGRATION_RECEIPT=json.dumps(receipt))), \
                    patch.object(gate.sys, "argv", ["gate", "--verify-receipt", "--target", "staging"]):
                self.assertEqual(gate.main(), 0)

    def test_only_proxy_can_omit_shared_prerequisite(self):
        for caller in ("deploy-api", "terraform-cd", "new-consumer", "deploy-proxy"):
            env = dict(self.env, GITHUB_REPOSITORY="example/repo", SHARED_AUTH_REQUIRED="false",
                       GITHUB_WORKFLOW_REF=f"example/repo/.github/workflows/{caller}.yml@refs/heads/main")
            if caller == "deploy-proxy":
                gate.check_shared_requirement(env)
            else:
                with self.assertRaises(gate.GateError):
                    gate.check_shared_requirement(env)
            gate.check_shared_requirement(dict(env, SHARED_AUTH_REQUIRED="true"))

    def test_executor_order_and_failure_cannot_emit_success(self):
        for target in ("staging", "use4"):
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                selected = command[command.index("--migration") + 1]
                return subprocess.CompletedProcess(command, 0, json.dumps(dict(
                    target=target, version=gate.SHARED_MIGRATIONS[selected],
                    state="applied", regional_history_unchanged=True)))
            with patch.object(gate, "verify_checkout"), patch.object(gate.subprocess, "run", side_effect=execute):
                result = gate.apply_shared(self.env, target)
            self.assertEqual(result, gate.verification_identity(self.env, target, Path("migration-source")))
            self.assertEqual([c[c.index("--migration") + 1] for c in calls], list(gate.SHARED_MIGRATIONS))
            for command in calls:
                self.assertEqual(command[-1], gate.SHARED_TARGETS[target])
                self.assertEqual(command[command.index("--revision") + 1], SHA)
        for failed_at in range(3):
            outcomes = [subprocess.CompletedProcess([], 0, json.dumps(dict(
                target="staging", version=version, state="applied", regional_history_unchanged=True)))
                for version in list(gate.SHARED_MIGRATIONS.values())[:failed_at]]
            outcomes.append(subprocess.CompletedProcess([], 1, "", "private driver output"))
            with patch.object(gate, "verify_checkout"), patch.object(gate.subprocess, "run", side_effect=outcomes) as run:
                with self.assertRaisesRegex(gate.GateError, "inspect before retrying"):
                    gate.apply_shared(self.env, "staging")
                self.assertEqual(run.call_count, failed_at + 1)
        for bad in (dict(target="staging", version=gate.SHARED_MIGRATIONS["authority"],
                         state="pending", regional_history_unchanged=True), {},
                    dict(target="use4", version=gate.SHARED_MIGRATIONS["authority"],
                         state="applied", regional_history_unchanged=True)):
            with patch.object(gate, "verify_checkout"), patch.object(gate.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, json.dumps(bad))), self.assertRaises(gate.GateError):
                gate.apply_shared(self.env, "staging")

    def receipt(self, target="staging"):
        verification = gate.verification_identity(self.env, target, Path("migration-source"))
        return gate.record_receipt(dict(self.env, SHARED_VERIFICATION=json.dumps(verification)), target)

    def test_partial_rerun_requires_new_actual_shared_execution(self):
        receipt = self.receipt()
        env = dict(self.env, MIGRATION_RECEIPT=json.dumps(receipt))
        gate.verify_receipt(env, "staging")
        rerun = dict(env, GITHUB_RUN_ATTEMPT="2")
        for old_output in (json.dumps(receipt), "null", ""):
            with self.subTest(output=old_output), self.assertRaises((gate.GateError, ValueError)):
                gate.verify_receipt(dict(rerun, MIGRATION_RECEIPT=old_output), "staging")
        old_shared = gate.verification_identity(self.env, "staging", Path("migration-source"))
        with self.assertRaises(gate.GateError):
            gate.record_receipt(dict(rerun, SHARED_VERIFICATION=json.dumps(old_shared)), "staging")
        new_shared = gate.verification_identity(rerun, "staging", Path("migration-source"))
        current = gate.record_receipt(dict(rerun, SHARED_VERIFICATION=json.dumps(new_shared)), "staging")
        gate.verify_receipt(dict(rerun, MIGRATION_RECEIPT=json.dumps(current)), "staging")

    def test_receipt_cannot_cross_sources_runs_targets_or_incomplete_regions(self):
        receipt = self.receipt("use4")
        gate.verify_receipt(dict(self.env, MIGRATION_RECEIPT=json.dumps(receipt)), "use4")
        for change in (dict(run_id="456"), dict(deployment_revision=OLD), dict(migration_revision=OLD),
                       dict(project="other-project"), dict(bundle="d" * 64), dict(shared_versions=[]),
                       dict(regional_targets=["use4"]), dict(target="staging")):
            with self.subTest(change=change), self.assertRaises(gate.GateError):
                gate.verify_receipt(dict(self.env, MIGRATION_RECEIPT=json.dumps(dict(receipt, **change))), "use4")
        with self.assertRaises(gate.GateError):
            gate.verify_receipt(dict(self.env, MIGRATION_RECEIPT=json.dumps(self.receipt())), "use4")
        # Compatible branch deployments deliberately have a different source SHA.
        branch = dict(self.env, MIGRATION_REVISION=OLD)
        verification = gate.verification_identity(branch, "staging", Path("migration-source"))
        receipt = gate.record_receipt(dict(branch, SHARED_VERIFICATION=json.dumps(verification)), "staging")
        gate.verify_receipt(dict(branch, MIGRATION_RECEIPT=json.dumps(receipt)), "staging")


def job_blocks(workflow):
    body = workflow.split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", body, re.M))
    return {m[1]: body[m.end():starts[i + 1].start() if i + 1 < len(starts) else len(body)]
            for i, m in enumerate(starts)}


def dependencies(block):
    match = re.search(r"^    needs: \[([^]]*)\]$", block, re.M)
    return [name.strip() for name in match[1].split(",")] if match else []


class DependencyTests(unittest.TestCase):
    def test_shared_execution_precedes_regions_and_receipt_follows_all_regions(self):
        source = (WORKFLOWS / "deployment-migrations.yml").read_text()
        jobs = job_blocks(source)
        for job, target, final_region in (("staging", "staging", "staging"), ("production", "use4", "usw2")):
            block = jobs[job]
            self.assertLess(block.index("--apply-shared"), block.index("migrate_database.py"))
            self.assertLess(block.index(f"migrate_database.py {final_region} push"), block.index("--record-receipt"))
            self.assertIn("SHARED_VERIFICATION: ${{ steps.shared.outputs.verification }}", block)
            self.assertIn("receipt: ${{ steps.receipt.outputs.receipt }}", block)
            self.assertNotIn("always()", block)
        for workflow in ("deploy-api.yml", "terraform-cd.yml"):
            caller = job_blocks((WORKFLOWS / workflow).read_text())["wait-for-migrations"]
            self.assertIn("shared_auth_required: true", caller)
        self.assertNotIn("shared_auth_required", (WORKFLOWS / "deploy-proxy.yml").read_text())

    def test_partial_rerun_checks_all_consumer_jobs_before_mutation(self):
        consumers = {
            "deploy-api.yml": {"deploy-staging": "Deploy to Cloud Run", "deploy-production": "Deploy use4 cell to Cloud Run"},
            "terraform-cd.yml": {
                "staging-us-central1-infra": "Terraform apply staging/us-central1",
                "staging-us-central1-api": "Deploy to Cloud Run",
                "production-us-west2-infra": "Terraform apply production/us-west2",
                "production-us-west2-api": "Deploy to Cloud Run",
                "production-us-east4-infra": "Terraform apply production/us-east4",
                "production-us-east4-api": "Deploy to Cloud Run",
            },
        }
        for workflow, expected in consumers.items():
            jobs = job_blocks((WORKFLOWS / workflow).read_text())
            actual = {job for job, block in jobs.items() if "--verify-receipt" in block}
            self.assertEqual(actual, set(expected))
            for job, mutation in expected.items():
                block = jobs[job]
                self.assertIn("wait-for-migrations", dependencies(block))
                consumer = ("          terraform apply -input=false -auto-approve tfplan" if job.endswith("-infra")
                            else "- name: " + mutation)
                self.assertLess(block.index("--verify-receipt"), block.index(consumer))
                self.assertIn("MIGRATION_REVISION: ${{ needs.wait-for-migrations.outputs.migration_revision }}", block)
                receipt = "staging_receipt" if "staging" in job else "production_receipt"
                self.assertIn("MIGRATION_RECEIPT: ${{ needs.wait-for-migrations.outputs." + receipt + " }}", block)

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
